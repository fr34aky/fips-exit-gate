package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AggregateUsage rolls raw usage samples whose report window ended before
// cutoff into usage_daily and deletes them, then removes the reports that no
// longer have samples. The fold and the delete are ONE statement over one
// snapshot (data-modifying CTEs), so a report committed concurrently can
// never be deleted without having been folded: it simply waits for the next
// sweep. A sample is either still raw or already in a daily total, never
// both. Samples with no account or an unknown service are dropped (unbillable).
// Returns how many samples were removed and how many reports.
func (s *Store) AggregateUsage(ctx context.Context, cutoff time.Time) (samples, reports int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`WITH old AS (
			     SELECT us.id, us.account_id, us.service_id, us.bytes, date_trunc('day', r.window_end)::date AS day
			     FROM usage_samples us JOIN usage_reports r ON r.id = us.report_id
			     WHERE r.window_end < $1),
			 folded AS (
			     INSERT INTO usage_daily(account_id, service_id, day, bytes)
			     SELECT account_id, service_id, day, sum(bytes) FROM old
			     WHERE account_id IS NOT NULL AND service_id IS NOT NULL
			     GROUP BY account_id, service_id, day
			     ON CONFLICT (account_id, day, service_id) DO UPDATE SET bytes = usage_daily.bytes + EXCLUDED.bytes
			     RETURNING 1),
			 removed AS (
			     DELETE FROM usage_samples WHERE id IN (SELECT id FROM old) RETURNING 1)
			 SELECT (SELECT count(*) FROM removed) + 0 * (SELECT count(*) FROM folded)`,
			cutoff).Scan(&samples); err != nil {
			return err
		}
		del, err := tx.Exec(ctx,
			`DELETE FROM usage_reports r WHERE r.window_end < $1
			   AND NOT EXISTS (SELECT 1 FROM usage_samples us WHERE us.report_id = r.id)`, cutoff)
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
