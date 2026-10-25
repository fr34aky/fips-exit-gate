package main

import (
	"context"
	"log"
	"time"
)

// retentionStore is the slice of the store the retention job needs.
type retentionStore interface {
	AggregateUsage(ctx context.Context, cutoff time.Time) (samples, reports int64, err error)
	CompactAuthzRevisions(ctx context.Context, cutoff time.Time) (int64, error)
}

// runRetention periodically rolls raw usage samples older than usageKeep into
// daily totals and compacts the authz revision log older than revKeep. The
// threat model promises bounded retention of per-address activity; this is
// what delivers it. Zero durations disable the respective step.
func runRetention(ctx context.Context, st retentionStore, every, usageKeep, revKeep time.Duration) {
	if every <= 0 || (usageKeep <= 0 && revKeep <= 0) {
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
		now := time.Now()
		if usageKeep > 0 {
			if n, reports, err := st.AggregateUsage(ctx, now.Add(-usageKeep)); err != nil {
				if ctx.Err() == nil {
					log.Printf("backend: retention: aggregate usage: %v", err)
				}
			} else if n > 0 || reports > 0 {
				log.Printf("backend: retention: folded %d usage sample(s) into daily totals, dropped %d report(s)", n, reports)
			}
		}
		if revKeep > 0 {
			if n, err := st.CompactAuthzRevisions(ctx, now.Add(-revKeep)); err != nil {
				if ctx.Err() == nil {
					log.Printf("backend: retention: compact authz revisions: %v", err)
				}
			} else if n > 0 {
				log.Printf("backend: retention: compacted %d authz revision(s)", n)
			}
		}
	}
}
