package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
	"github.com/fr34aky/fips-exit-gate/backend/store"
	"github.com/fr34aky/fips-exit-gate/pkg/metrics"
)

// payHandler receives BTCPay webhooks and drives the purchase lifecycle.
type payHandler struct {
	store   *store.Store
	secret  []byte              // BTCPay webhook secret (HMAC key)
	metrics *metrics.CounterVec // fipsexit_webhook_events_total{type,result}; may be nil
}

func (ph *payHandler) record(typ, result string) {
	if ph.metrics != nil {
		ph.metrics.With(typ, result).Inc()
	}
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
		ph.record("_", "bad_signature")
		writeErr(w, http.StatusUnauthorized, "unauthorized", "bad webhook signature")
		return
	}
	var ev payments.WebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil || ev.InvoiceID == "" {
		// Signed but unparseable/irrelevant (e.g. a test ping) — ack and move on.
		ph.record("_", "bad_request")
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx := r.Context()
	switch ev.Type {
	case payments.EventInvoiceProcessing:
		// Payment seen but not final (on-chain 0-conf, unconfirmed XMR). Record
		// it for the dashboard but grant NO access until it settles.
		err = ph.store.MarkProcessing(ctx, ev.InvoiceID)
	case payments.EventInvoiceSettled:
		// Payment final per the store's confirmation policy — unlock access.
		err = ph.store.GrantByInvoice(ctx, ev.InvoiceID)
	case payments.EventInvoiceInvalid:
		err = ph.store.VoidByInvoice(ctx, ev.InvoiceID, "invalid")
	case payments.EventInvoiceExpired:
		err = ph.store.VoidByInvoice(ctx, ev.InvoiceID, "expired")
	default:
		ph.record(ev.Type, "ignored") // event we don't act on
		w.WriteHeader(http.StatusOK)
		return
	}

	switch err {
	case nil:
		ph.record(ev.Type, "ok")
		w.WriteHeader(http.StatusOK)
	case store.ErrPurchaseNotFound:
		// Not one of our invoices (or not yet attached). Ack to stop retries.
		ph.record(ev.Type, "unknown_invoice")
		log.Printf("payments: webhook %s for unknown invoice %s", ev.Type, ev.InvoiceID)
		w.WriteHeader(http.StatusOK)
	default:
		ph.record(ev.Type, "error")
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
	}
}
