package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AggregateUsage rolls raw usage samples whose report window ended before
// cutoff into usage_daily and deletes them (with their reports). Idempotent
// per row: a sample is either still raw or already in a daily total, never
// both. Returns how many samples were folded and how many reports removed.
func (s *Store) AggregateUsage(ctx context.Context, cutoff time.Time) (samples, reports int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO usage_daily(account_id, service_id, day, bytes)
			 SELECT us.account_id, us.service_id, date_trunc('day', r.window_end)::date, sum(us.bytes)
			 FROM usage_samples us JOIN usage_reports r ON r.id = us.report_id
			 WHERE r.window_end < $1 AND us.account_id IS NOT NULL
			 GROUP BY us.account_id, us.service_id, date_trunc('day', r.window_end)
			 ON CONFLICT (account_id, day, service_id) DO UPDATE SET bytes = usage_daily.bytes + EXCLUDED.bytes`,
			cutoff)
		if err != nil {
			return err
		}
		_ = tag
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM usage_samples us JOIN usage_reports r ON r.id = us.report_id WHERE r.window_end < $1`,
			cutoff).Scan(&samples); err != nil {
			return err
		}
		// Reports cascade to their samples.
		del, err := tx.Exec(ctx, `DELETE FROM usage_reports WHERE window_end < $1`, cutoff)
		if err != nil {
			return err
		}
		reports = del.RowsAffected()
		return nil
	})
	return samples, reports, err
}

// CompactAuthzRevisions deletes revision-log rows older than cutoff, always
// keeping the newest row so max(rev) (the global revision) is stable. An agent
// whose cursor predates the compacted range gets a full set instead of a delta
// (see DeltaSince).
func (s *Store) CompactAuthzRevisions(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM authz_revisions
		 WHERE created_at < $1 AND rev < (SELECT max(rev) FROM authz_revisions)`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
