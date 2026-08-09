package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
	"github.com/fr34aky/fips-exit-gate/backend/store"
)

// payHandler receives BTCPay webhooks and drives the purchase lifecycle.
type payHandler struct {
	store  *store.Store
	secret []byte // BTCPay webhook secret (HMAC key)
}

// webhook verifies the BTCPay-Sig HMAC and applies the invoice state change.
// It always acks 2xx once the signature is valid — including for events we
// don't act on and for unknown invoices — so BTCPay stops retrying.
func (ph *payHandler) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "unreadable body")
		return
	}
	if !payments.VerifyWebhook(ph.secret, body, r.Header.Get("BTCPay-Sig")) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "bad webhook signature")
		return
	}
	var ev payments.WebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil || ev.InvoiceID == "" {
		// Signed but unparseable/irrelevant (e.g. a test ping) — ack and move on.
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx := r.Context()
	switch ev.Type {
	case payments.EventInvoiceProcessing:
		err = ph.store.GrantByInvoice(ctx, ev.InvoiceID, false)
	case payments.EventInvoiceSettled:
		err = ph.store.GrantByInvoice(ctx, ev.InvoiceID, true)
	case payments.EventInvoiceInvalid:
		err = ph.store.VoidByInvoice(ctx, ev.InvoiceID, "invalid")
	case payments.EventInvoiceExpired:
		err = ph.store.VoidByInvoice(ctx, ev.InvoiceID, "expired")
	default:
		w.WriteHeader(http.StatusOK) // event we don't act on
		return
	}

	switch err {
	case nil:
		w.WriteHeader(http.StatusOK)
	case store.ErrPurchaseNotFound:
		// Not one of our invoices (or not yet attached). Ack to stop retries.
		log.Printf("payments: webhook %s for unknown invoice %s", ev.Type, ev.InvoiceID)
		w.WriteHeader(http.StatusOK)
	default:
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
	}
}
