package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/fr34aky/fips-exit-gate/backend/store"
)

// JSON wire types (mirror docs/api-agent-backend.md and the agent client).

type authzMemberJSON struct {
	Addr    netip.Addr `json:"addr"`
	Account string     `json:"account"`
}

type handlers struct {
	store          *store.Store
	usageIntervalS int
	graceMinutes   int
}

// --- agent-facing endpoints -------------------------------------------------

func (h *handlers) enroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnrollToken string `json:"enroll_token"`
		NodePubkey  string `json:"node_pubkey"`
		Name        string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	nodeID, token, err := h.store.EnrollNode(r.Context(), req.EnrollToken, req.NodePubkey, req.Name)
	if err == store.ErrInvalidEnrollToken {
		writeErr(w, http.StatusUnauthorized, "invalid_enroll_token", err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"node_id": nodeID, "auth_token": token})
}

func (h *handlers) authz(w http.ResponseWriter, r *http.Request) {
	clientRev, _ := strconv.ParseInt(r.URL.Query().Get("rev"), 10, 64)
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait <= 0 || wait > 55 {
		wait = 25
	}
	ctx := r.Context()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		cur, err := h.store.CurrentRev(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if clientRev != cur {
			h.writeAuthz(w, ctx, clientRev)
			return
		}
		if time.Now().After(deadline) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (h *handlers) writeAuthz(w http.ResponseWriter, ctx context.Context, clientRev int64) {
	if clientRev == 0 {
		members, rev, err := h.store.FullSet(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"rev": rev, "full": true, "addresses": toMembers(members),
		})
		return
	}
	add, del, rev, err := h.store.DeltaSince(ctx, clientRev)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rev": rev, "add": toMembers(add), "del": del,
	})
}

func (h *handlers) usage(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	var req struct {
		ReportID     string `json:"report_id"`
		CounterEpoch string `json:"counter_epoch"`
		WindowEnd    string `json:"window_end"`
		Samples      []struct {
			Service string     `json:"service"`
			Addr    netip.Addr `json:"addr"`
			Bytes   uint64     `json:"bytes"`
		} `json:"samples"`
	}
	if !decode(w, r, &req) {
		return
	}
	windowEnd, _ := time.Parse(time.RFC3339, req.WindowEnd)
	rep := store.ReportInput{
		ReportID:     req.ReportID,
		CounterEpoch: req.CounterEpoch,
		WindowEnd:    windowEnd,
	}
	for _, s := range req.Samples {
		rep.Samples = append(rep.Samples, store.SampleInput{Service: s.Service, Addr: s.Addr, Bytes: s.Bytes})
	}
	revoke, err := h.store.IngestUsage(r.Context(), nodeID, rep)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ack": req.ReportID, "revoke": revoke})
}

func (h *handlers) heartbeat(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	var req struct {
		Version string `json:"version"`
	}
	_ = decodeQuiet(r, &req)
	services, err := h.store.Heartbeat(r.Context(), nodeID, req.Version)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	svc := make([]map[string]any, 0, len(services))
	for _, s := range services {
		svc = append(svc, map[string]any{"key": s.Key, "port": s.Port})
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": map[string]any{
		"usage_interval_s": h.usageIntervalS,
		"grace_minutes":    h.graceMinutes,
		"services":         svc,
	}})
}

func toMembers(ms []store.AuthzMember) []authzMemberJSON {
	out := make([]authzMemberJSON, 0, len(ms))
	for _, m := range ms {
		out = append(out, authzMemberJSON{Addr: m.Addr, Account: m.Account})
	}
	return out
}

// helpers

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func decodeQuiet(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
