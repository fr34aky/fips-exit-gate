package store

import "context"

// NodeMetric is one exit node's liveness for metrics.
type NodeMetric struct {
	Name         string
	LastSeenUnix float64 // 0 if never seen
}

// Metrics is a point-in-time snapshot of control-plane state for /metrics.
type Metrics struct {
	AuthorizedAddrs    int
	AuthzRevision      int64
	AccountsByStatus   map[string]int
	EntitlementsActive int
	UsageBytesTotal    int64
	PurchasesByStatus  map[string]int
	Nodes              []NodeMetric
}

// MetricsSnapshot reads the counts exposed at /metrics. It runs a handful of
// cheap aggregates; call it at scrape time.
func (s *Store) MetricsSnapshot(ctx context.Context) (Metrics, error) {
	m := Metrics{AccountsByStatus: map[string]int{}, PurchasesByStatus: map[string]int{}}

	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM authz_current`).Scan(&m.AuthorizedAddrs); err != nil {
		return m, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&m.AuthzRevision); err != nil {
		return m, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM entitlements
		 WHERE now() >= starts_at AND now() <= expires_at
		   AND (kind = 'time' OR volume_used < volume_bytes)`).Scan(&m.EntitlementsActive); err != nil {
		return m, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(sum(bytes), 0) FROM usage_samples`).Scan(&m.UsageBytesTotal); err != nil {
		return m, err
	}
	if err := scanCounts(ctx, s, `SELECT status, count(*) FROM accounts GROUP BY status`, m.AccountsByStatus); err != nil {
		return m, err
	}
	if err := scanCounts(ctx, s, `SELECT status, count(*) FROM purchases GROUP BY status`, m.PurchasesByStatus); err != nil {
		return m, err
	}

	rows, err := s.pool.Query(ctx,
		`SELECT name, COALESCE(EXTRACT(EPOCH FROM last_seen), 0)::float8 FROM exit_nodes`)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var n NodeMetric
		if err := rows.Scan(&n.Name, &n.LastSeenUnix); err != nil {
			return m, err
		}
		m.Nodes = append(m.Nodes, n)
	}
	return m, rows.Err()
}

func scanCounts(ctx context.Context, s *Store, sql string, into map[string]int) error {
	rows, err := s.pool.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v int
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		into[k] = v
	}
	return rows.Err()
}
