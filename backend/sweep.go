package main

import (
	"context"
	"log"
	"net/netip"
	"time"
)

// authzRecomputer is the slice of the store the expiry sweep needs.
type authzRecomputer interface {
	RecomputeAuthz(ctx context.Context) ([]netip.Addr, int64, error)
}

// runExpirySweep recomputes the authorized set on a timer. Every other
// recompute is event-driven (a payment, a usage report, an admin call), so a
// time pass that expires while its account is idle would otherwise stay
// authorized until some unrelated event happened to run a recompute. Removals
// reach agents through the normal revision log within one long-poll.
func runExpirySweep(ctx context.Context, st authzRecomputer, every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		removed, rev, err := st.RecomputeAuthz(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("backend: expiry sweep: %v", err)
			}
			continue
		}
		if len(removed) > 0 {
			log.Printf("backend: expiry sweep revoked %d address(es) (rev %d)", len(removed), rev)
		}
	}
}
