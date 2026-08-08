package main

import (
	"net/http"

	"github.com/fr34aky/fips-exit-gate/backend/store"
)

// Admin endpoints drive the M3 flow before the portal/payments exist. They are
// protected by a static admin bearer token.

func (h *handlers) adminEnrollToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	_ = decodeQuiet(r, &req)
	token, err := h.store.CreateEnrollToken(r.Context(), req.Note)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"enroll_token": token})
}

func (h *handlers) adminCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Npub string `json:"npub"`
	}
	if !decode(w, r, &req) {
		return
	}
	acct, err := h.store.CreateAccount(r.Context(), req.Npub)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": acct.ID, "npub": acct.Npub, "fips_addr": acct.FipsAddr, "status": acct.Status,
	})
}

func (h *handlers) adminWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OwnerNpub string `json:"owner_npub"`
		GuestNpub string `json:"guest_npub"`
		Label     string `json:"label"`
		Enabled   *bool  `json:"enabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	var err error
	if req.Enabled != nil && !*req.Enabled {
		err = h.store.SetWhitelistEnabled(ctx, req.OwnerNpub, req.GuestNpub, false)
	} else {
		err = h.store.AddWhitelist(ctx, req.OwnerNpub, req.GuestNpub, req.Label)
	}
	switch err {
	case nil:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case store.ErrAccountNotFound:
		writeErr(w, http.StatusNotFound, "account_not_found", err.Error())
	case store.ErrAddressInUse:
		writeErr(w, http.StatusConflict, "address_in_use", err.Error())
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
	}
}

func (h *handlers) adminCredit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Npub string `json:"npub"`
		Kind string `json:"kind"` // volume | time
		GB   int64  `json:"gb"`   // volume kind
		Days int    `json:"days"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Days <= 0 {
		req.Days = 30
	}
	ctx := r.Context()
	var err error
	if req.Kind == "time" {
		err = h.store.CreditTime(ctx, req.Npub, req.Days)
	} else {
		if req.GB <= 0 {
			req.GB = 50
		}
		err = h.store.CreditVolume(ctx, req.Npub, req.GB*1_000_000_000, req.Days)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "credited"})
}

func (h *handlers) adminAuthz(w http.ResponseWriter, r *http.Request) {
	members, rev, err := h.store.FullSet(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rev": rev, "addresses": toMembers(members)})
}
