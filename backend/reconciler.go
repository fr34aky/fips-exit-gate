package main

import (
	"context"
	"log"
	"time"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
	"github.com/fr34aky/fips-exit-gate/backend/store"
	"github.com/fr34aky/fips-exit-gate/pkg/metrics"
)

// reconciler polls open Lightning invoices so payments settle even if a webhook
// is missed or its signature scheme differs by phoenixd version, and so unpaid
// invoices are expired. It complements the webhook, not replaces it.
type reconciler struct {
	store    *store.Store
	ln       *payments.Phoenixd
	interval time.Duration
	ttl      time.Duration // unpaid invoice lifetime before it's voided
	metrics  *metrics.CounterVec
}

func (r *reconciler) record(result string) {
	if r.metrics != nil {
		r.metrics.With("reconcile", result).Inc()
	}
}

func (r *reconciler) run(ctx context.Context) {
	log.Printf("backend: phoenixd reconciler every %s (invoice TTL %s)", r.interval, r.ttl)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.sweep(ctx)
		}
	}
}

func (r *reconciler) sweep(ctx context.Context) {
	open, err := r.store.ListOpenLightning(ctx)
	if err != nil {
		log.Printf("reconciler: list open: %v", err)
		return
	}
	for _, o := range open {
		paid, err := r.ln.LookupIncoming(ctx, o.InvoiceID)
		if err != nil {
			r.record("error")
			continue
		}
		switch {
		case paid:
			if err := r.store.GrantByInvoice(ctx, o.InvoiceID); err != nil {
				r.record("error")
				log.Printf("reconciler: grant %s: %v", o.PurchaseID, err)
			} else {
				r.record("settled")
				log.Printf("reconciler: settled purchase %s", o.PurchaseID)
			}
		case time.Since(o.CreatedAt) > r.ttl:
			if err := r.store.VoidByInvoice(ctx, o.InvoiceID, "expired"); err != nil {
				r.record("error")
			} else {
				r.record("expired")
			}
		}
	}
}
