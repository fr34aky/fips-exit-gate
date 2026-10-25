package main

import (
	"context"
	"encoding/json"
	"io"
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

	// revs wakes authz long-polls on a revision change (nil = poll only).
	revs *revWaiter
	// fallbackPoll bounds how long a long-poll sleeps between revision checks
	// when no notification arrives (missed NOTIFY, no listener). Zero = 5 s.
	fallbackPoll time.Duration
	// allowMassRevoke marks full-set responses with force=true so agents apply
	// them even when that would remove most of their live set. Off by default:
	// agents refuse such a reconcile as a guard against an empty/truncated
	// set (DB restore, broken recompute) revoking every paying user at once.
	allowMassRevoke bool
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

// authz is the agent long-poll. `rev` is the agent's cursor (0 = give me the
// full set); `full=1` asks for the full set right now even when the backend's
// revision is still 0, so an agent reconciling a fresh backend can still clear
// stale kernel entries (without it, rev 0 == cur 0 would long-poll to a 204 and
// the agent would record the reconcile as done without removing anything).
func (h *handlers) authz(w http.ResponseWriter, r *http.Request) {
	clientRev, _ := strconv.ParseInt(r.URL.Query().Get("rev"), 10, 64)
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if wait <= 0 || wait > 55 {
		wait = 25
	}
	full := r.URL.Query().Get("full") == "1" || r.URL.Query().Get("full") == "true"
	ctx := r.Context()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	poll := h.fallbackPoll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	for {
		// Take the wake-up channel BEFORE reading the revision: a NOTIFY that
		// lands between the read and the select would otherwise close a
		// channel we never obtained, and the poll would sleep a full
		// fallback interval instead of waking at once.
		wake := h.revs.wait()
		cur, err := h.store.CurrentRev(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if full || clientRev != cur {
			h.writeAuthz(w, ctx, clientRev, full)
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if remaining < poll {
			poll = remaining
		}
		// Wake on a NOTIFY from RecomputeAuthz, or re-check after the fallback
		// interval in case one was missed.
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(poll):
		}
	}
}

func (h *handlers) writeAuthz(w http.ResponseWriter, ctx context.Context, clientRev int64, full bool) {
	if full || clientRev == 0 {
		members, rev, err := h.store.FullSet(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"rev": rev, "full": true, "addresses": toMembers(members), "force": h.allowMassRevoke,
		})
		return
	}
	add, del, rev, err := h.store.DeltaSince(ctx, clientRev)
	if err == store.ErrCompacted {
		// The log no longer reaches the agent's cursor: hand it the full set,
		// which it reconciles against its kernel set (the documented fallback).
		h.writeAuthz(w, ctx, 0, true)
		return
	}
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
		Version  string `json:"version"`
		AuthzRev int64  `json:"authz_rev"`
		SetSize  int    `json:"set_size"`
		SetHash  string `json:"set_hash"`
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
	// Drift detection: if the node claims to be caught up (its rev matches ours)
	// yet its live set differs from authz_current, the node's kernel set has
	// drifted out-of-band and its revision cursor can't detect it. Ask it to force
	// a full reconcile. We only flag at an EQUAL revision so a node that is merely
	// behind (and will catch up via the normal delta) isn't needlessly resynced.
	// Agents that report a set_hash are compared member-by-member (same size,
	// different members is drift too); older agents fall back to the size. A
	// negative set_size means the agent could not read its set — not drift.
	resync := false
	if count, hash, rev, err := h.store.AuthzStatus(r.Context()); err == nil && req.AuthzRev == rev {
		switch {
		case req.SetHash != "":
			resync = req.SetHash != hash
		case req.SetSize >= 0:
			resync = req.SetSize != count
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config": map[string]any{
			"usage_interval_s": h.usageIntervalS,
			"grace_minutes":    h.graceMinutes,
			"services":         svc,
		},
		"resync": resync,
	})
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
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
