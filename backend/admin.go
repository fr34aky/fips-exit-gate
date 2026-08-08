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

func (h *handlers) adminListPackages(w http.ResponseWriter, r *http.Request) {
	pkgs, err := h.store.ListPackages(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, map[string]any{
			"id": p.ID, "kind": p.Kind, "name": p.Name,
			"volume_bytes": p.VolumeBytes, "validity_days": p.ValidityDays, "price_msat": p.PriceMsat,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"packages": out})
}

func (h *handlers) adminCreatePackage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		GB        int64  `json:"gb"`
		Days      int    `json:"days"`
		PriceSats int64  `json:"price_sats"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, err := h.store.CreatePackage(r.Context(), req.Kind, req.Name, req.GB*1_000_000_000, req.Days, req.PriceSats*1000)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

// adminSettle marks a purchase paid and grants its entitlement. This is the
// same call the Phase-4 BTCPay webhook will make on invoice settlement.
func (h *handlers) adminSettle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PurchaseID string `json:"purchase_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := h.store.SettlePurchase(r.Context(), req.PurchaseID); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "settled"})
}

func (h *handlers) adminAuthz(w http.ResponseWriter, r *http.Request) {
	members, rev, err := h.store.FullSet(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rev": rev, "addresses": toMembers(members)})
}
