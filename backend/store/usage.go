package store

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5"
)

type svcMeta struct {
	id   string
	rate int64
}

// maxSampleBytes clamps a single usage sample. A 30s window can't plausibly
// carry a terabyte; the clamp also guards the uint64->int64 conversion and the
// weighted-bytes multiplication below against overflow from a buggy or hostile
// node report.
const maxSampleBytes = 1 << 40 // ~1.1 TB

// IngestUsage records a usage report idempotently (keyed on report_id),
// attributing rate-weighted bytes to each account's earliest-expiring volume
// entitlement, then recomputes the authorized set. It returns addresses to
// revoke immediately (accounts whose quota this report exhausted).
func (s *Store) IngestUsage(ctx context.Context, nodeID string, r ReportInput) ([]netip.Addr, error) {
	services, err := s.serviceMetaByKey(ctx)
	if err != nil {
		return nil, err
	}

	var fresh bool
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		// Idempotency: a duplicate report_id is a no-op.
		tag, err := tx.Exec(ctx,
			`INSERT INTO usage_reports(id, node_id, counter_epoch, window_end)
			 VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`,
			r.ReportID, nodeID, r.CounterEpoch, r.WindowEnd)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil // already processed
		}
		fresh = true

		for _, smp := range r.Samples {
			sampleBytes := smp.Bytes
			if sampleBytes > maxSampleBytes {
				sampleBytes = maxSampleBytes
			}
			meta, ok := services[smp.Service]
			var svcID any
			if ok {
				svcID = meta.id
			}
			// Resolve the owning account from the current authorized set.
			var accountID *string
			if err := tx.QueryRow(ctx,
				`SELECT account_id::text FROM authz_current WHERE fips_addr = $1::inet`,
				smp.Addr.String()).Scan(&accountID); err != nil && err != pgx.ErrNoRows {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO usage_samples(report_id, service_id, fips_addr, account_id, bytes)
				 VALUES ($1, $2, $3::inet, $4, $5)`,
				r.ReportID, svcID, smp.Addr.String(), accountID, int64(sampleBytes)); err != nil {
				return err
			}
			if accountID != nil && ok && meta.rate > 0 {
				// bytes * rate / 1e6, computed divide-first so it can't overflow
				// int64 even at the clamp ceiling with a large rate.
				b := int64(sampleBytes)
				weighted := b/1_000_000*meta.rate + b%1_000_000*meta.rate/1_000_000
				if err := consumeVolume(ctx, tx, *accountID, weighted); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil || !fresh {
		return nil, err
	}
	// Exhaustion/expiry may now change the set; recompute and revoke removed.
	removed, _, err := s.RecomputeAuthz(ctx)
	return removed, err
}

// consumeVolume draws weighted bytes from the account's volume entitlements,
// earliest-expiring first. Time entitlements are not consumed. Over-quota
// excess is dropped (the account is revoked on the next recompute).
func consumeVolume(ctx context.Context, tx pgx.Tx, accountID string, weighted int64) error {
	for weighted > 0 {
		var id string
		var total, used int64
		err := tx.QueryRow(ctx,
			`SELECT id::text, volume_bytes, volume_used FROM entitlements
			 WHERE account_id = $1 AND kind = 'volume'
			   AND now() >= starts_at AND now() <= expires_at
			   AND volume_used < volume_bytes
			 ORDER BY expires_at ASC LIMIT 1 FOR UPDATE`, accountID).Scan(&id, &total, &used)
		if err == pgx.ErrNoRows {
			return nil // no volume capacity left (time-based or exhausted)
		}
		if err != nil {
			return err
		}
		remaining := total - used
		consume := weighted
		if remaining < consume {
			consume = remaining
		}
		if _, err := tx.Exec(ctx,
			`UPDATE entitlements SET volume_used = volume_used + $2 WHERE id = $1`, id, consume); err != nil {
			return err
		}
		weighted -= consume
	}
	return nil
}

func (s *Store) serviceMetaByKey(ctx context.Context) (map[string]svcMeta, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, id::text, rate_ppm FROM services WHERE enabled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]svcMeta{}
	for rows.Next() {
		var key string
		var m svcMeta
		if err := rows.Scan(&key, &m.id, &m.rate); err != nil {
			return nil, err
		}
		out[key] = m
	}
	return out, rows.Err()
}
