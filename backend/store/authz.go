package store

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5"
)

// The authorized set is GLOBAL (any authorized address may use any exit node).
// It is materialized in authz_current and every change is appended to
// authz_revisions, whose max(rev) is the global revision the agents poll.

// desiredSQL selects the addresses that SHOULD be authorized right now: every
// enabled whitelist entry of an active account that has an active entitlement.
const desiredSQL = `
SELECT host(w.fips_addr), w.account_id::text
FROM whitelist_entries w
JOIN accounts a ON a.id = w.account_id
WHERE w.enabled AND a.status = 'active'
  AND EXISTS (
    SELECT 1 FROM entitlements e
    WHERE e.account_id = w.account_id
      AND now() >= e.starts_at AND now() <= e.expires_at
      AND (e.kind = 'time' OR e.volume_used < e.volume_bytes)
  )`

// RecomputeAuthz reconciles authz_current with the desired set, appending
// add/del rows to authz_revisions. It returns the addresses removed in this
// pass (used as inline usage-ack revocations) and the new global revision.
func (s *Store) RecomputeAuthz(ctx context.Context) (removed []netip.Addr, rev int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		desired, err := scanAddrAccount(ctx, tx, desiredSQL)
		if err != nil {
			return err
		}
		current, err := scanAddrAccount(ctx, tx, `SELECT host(fips_addr), account_id::text FROM authz_current`)
		if err != nil {
			return err
		}
		for addr, acct := range desired {
			if _, ok := current[addr]; ok {
				continue
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO authz_current(fips_addr, account_id) VALUES ($1::inet, $2)
				 ON CONFLICT (fips_addr) DO UPDATE SET account_id = EXCLUDED.account_id`, addr, acct); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO authz_revisions(op, fips_addr, account_id) VALUES ('add', $1::inet, $2)`, addr, acct); err != nil {
				return err
			}
		}
		for addr, acct := range current {
			if _, ok := desired[addr]; ok {
				continue
			}
			if _, err := tx.Exec(ctx, `DELETE FROM authz_current WHERE fips_addr = $1::inet`, addr); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO authz_revisions(op, fips_addr, account_id) VALUES ('del', $1::inet, $2)`, addr, acct); err != nil {
				return err
			}
			if a, e := netip.ParseAddr(addr); e == nil {
				removed = append(removed, a)
			}
		}
		return tx.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&rev)
	})
	return removed, rev, err
}

// CurrentRev returns the global authz revision.
func (s *Store) CurrentRev(ctx context.Context) (int64, error) {
	var rev int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&rev)
	return rev, err
}

// FullSet returns the complete current authorized set.
func (s *Store) FullSet(ctx context.Context) ([]AuthzMember, int64, error) {
	rev, err := s.CurrentRev(ctx)
	if err != nil {
		return nil, 0, err
	}
	m, err := scanAddrAccount(ctx, s.pool, `SELECT host(fips_addr), account_id::text FROM authz_current`)
	if err != nil {
		return nil, 0, err
	}
	out := make([]AuthzMember, 0, len(m))
	for addr, acct := range m {
		if a, e := netip.ParseAddr(addr); e == nil {
			out = append(out, AuthzMember{Addr: a, Account: acct})
		}
	}
	return out, rev, nil
}

// DeltaSince returns the net add/del since clientRev by replaying the revision
// log (so an add-then-del of the same address collapses correctly).
func (s *Store) DeltaSince(ctx context.Context, clientRev int64) (add []AuthzMember, del []netip.Addr, rev int64, err error) {
	rows, err := s.pool.Query(ctx,
		`SELECT op, host(fips_addr), account_id::text FROM authz_revisions WHERE rev > $1 ORDER BY rev`, clientRev)
	if err != nil {
		return nil, nil, 0, err
	}
	defer rows.Close()

	type state struct {
		op   string
		acct string
	}
	final := map[string]state{}
	for rows.Next() {
		var op, addr, acct string
		if err := rows.Scan(&op, &addr, &acct); err != nil {
			return nil, nil, 0, err
		}
		final[addr] = state{op: op, acct: acct}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, 0, err
	}
	for addr, st := range final {
		a, e := netip.ParseAddr(addr)
		if e != nil {
			continue
		}
		if st.op == "add" {
			add = append(add, AuthzMember{Addr: a, Account: st.acct})
		} else {
			del = append(del, a)
		}
	}
	if rev, err = s.CurrentRev(ctx); err != nil {
		return nil, nil, 0, err
	}
	return add, del, rev, nil
}

// querier is satisfied by both *pgxpool.Pool and pgx.Tx.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func scanAddrAccount(ctx context.Context, q querier, sql string, args ...any) (map[string]string, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var addr, acct string
		if err := rows.Scan(&addr, &acct); err != nil {
			return nil, err
		}
		out[addr] = acct
	}
	return out, rows.Err()
}
