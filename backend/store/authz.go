package store

import (
	"context"
	"log"
	"net/netip"
	"strconv"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/authzhash"
	"github.com/jackc/pgx/v5"
)

// authzLockKey serializes RecomputeAuthz across backend processes. Without it
// two concurrent recomputes (usage ingest, a webhook, a login) could take
// revision numbers in one order and COMMIT in the other, so an agent that read
// max(rev)=11 before rev 10 became visible would advance its cursor past 10
// and never receive it. Holding a transaction-scoped advisory lock across the
// whole recompute makes revision numbers monotonic in commit order.
const authzLockKey int64 = 0x66697073_61757468 // "fipsauth"

// AuthzChannel is the Postgres NOTIFY channel pinged (with the new revision as
// payload) whenever RecomputeAuthz appends revisions, so API long-polls can
// wake immediately instead of polling max(rev).
const AuthzChannel = "fips_authz"

// The authorized set is GLOBAL (any authorized address may use any exit node).
// It is materialized in authz_current and every change is appended to
// authz_revisions, whose max(rev) is the global revision the agents poll.

// desiredSQL selects the addresses that SHOULD be authorized right now: every
// enabled, accepted (not pending) whitelist entry of an active account that
// has an active entitlement.
const desiredSQL = `
SELECT host(w.fips_addr), w.account_id::text
FROM whitelist_entries w
JOIN accounts a ON a.id = w.account_id
WHERE w.enabled AND NOT w.pending AND a.status = 'active'
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
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, authzLockKey); err != nil {
			return err
		}
		desired, err := scanAddrAccount(ctx, tx, desiredSQL)
		if err != nil {
			return err
		}
		current, err := scanAddrAccount(ctx, tx, `SELECT host(fips_addr), account_id::text FROM authz_current`)
		if err != nil {
			return err
		}
		changed := false
		for addr, acct := range desired {
			if cur, ok := current[addr]; ok && cur == acct {
				continue
			}
			// New member, or a member whose attribution moved to another account
			// (a guest accepted an invitation, or switched back to their own
			// account) while staying authorized. Record the move too: usage is
			// billed to authz_current's account, and the revision log's account
			// is what late-usage attribution falls back to. Agents only see an
			// idempotent re-add.
			if _, err := tx.Exec(ctx,
				`INSERT INTO authz_current(fips_addr, account_id) VALUES ($1::inet, $2)
				 ON CONFLICT (fips_addr) DO UPDATE SET account_id = EXCLUDED.account_id`, addr, acct); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO authz_revisions(op, fips_addr, account_id) VALUES ('add', $1::inet, $2)`, addr, acct); err != nil {
				return err
			}
			changed = true
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
			changed = true
		}
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&rev); err != nil {
			return err
		}
		if changed {
			// Delivered on COMMIT, so listeners never see the revision before
			// the rows that carry it.
			if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, AuthzChannel, strconv.FormatInt(rev, 10)); err != nil {
				return err
			}
		}
		return nil
	})
	return removed, rev, err
}

// ListenAuthz holds a dedicated connection LISTENing on AuthzChannel and calls
// onChange for every notification until ctx ends. It also calls onChange once
// per (re)connect, so a waiter re-checks the revision after any gap in which a
// notification could have been missed. Callers keep a slow poll as a backstop;
// this only makes the common case immediate.
func (s *Store) ListenAuthz(ctx context.Context, onChange func()) {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := s.listenOnce(ctx, onChange)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second // a healthy session resets the ladder
		}
		log.Printf("store: authz listener: %v (reconnecting in %s)", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (s *Store) listenOnce(ctx context.Context, onChange func()) error {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `LISTEN `+AuthzChannel); err != nil {
		return err
	}
	onChange()
	for {
		if _, err := conn.WaitForNotification(ctx); err != nil {
			return err
		}
		onChange()
	}
}

// CurrentRev returns the global authz revision.
func (s *Store) CurrentRev(ctx context.Context) (int64, error) {
	var rev int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&rev)
	return rev, err
}

// FullSet returns the complete current authorized set and the revision it
// reflects, read in one snapshot so the revision matches the set exactly.
func (s *Store) FullSet(ctx context.Context) ([]AuthzMember, int64, error) {
	var rev int64
	var out []AuthzMember
	err := s.readTxRR(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&rev); err != nil {
			return err
		}
		m, err := scanAddrAccount(ctx, tx, `SELECT host(fips_addr), account_id::text FROM authz_current`)
		if err != nil {
			return err
		}
		out = make([]AuthzMember, 0, len(m))
		for addr, acct := range m {
			if a, e := netip.ParseAddr(addr); e == nil {
				out = append(out, AuthzMember{Addr: a, Account: acct})
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return out, rev, nil
}

// AuthzStatus returns the current authorized-set size, its authzhash
// fingerprint and the revision, read in one snapshot so a node heartbeat can
// reliably compare its live kernel set against the backend at a consistent
// point. A fingerprint (or, for older agents, size) mismatch at an equal
// revision means the node's set has drifted out-of-band (e.g. an nftables
// flush) — the caller uses this to ask the node to force a full reconcile.
//
// The fingerprint can only change when the revision changes, so the result is
// memoized per revision: a fleet heartbeating every minute costs one scan per
// revision change, not one per heartbeat.
func (s *Store) AuthzStatus(ctx context.Context) (count int, hash string, rev int64, err error) {
	if rev, err = s.CurrentRev(ctx); err != nil {
		return 0, "", 0, err
	}
	s.statusMu.Lock()
	if s.statusCache.rev == rev && s.statusCache.hash != "" {
		c := s.statusCache
		s.statusMu.Unlock()
		return c.count, c.hash, rev, nil
	}
	s.statusMu.Unlock()
	err = s.readTxRR(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&rev); err != nil {
			return err
		}
		m, err := scanAddrAccount(ctx, tx, `SELECT host(fips_addr), account_id::text FROM authz_current`)
		if err != nil {
			return err
		}
		addrs := make([]netip.Addr, 0, len(m))
		for addr := range m {
			if a, e := netip.ParseAddr(addr); e == nil {
				addrs = append(addrs, a)
			}
		}
		count, hash = len(addrs), authzhash.Of(addrs)
		return nil
	})
	if err == nil {
		s.statusMu.Lock()
		s.statusCache = authzStatus{rev: rev, count: count, hash: hash}
		s.statusMu.Unlock()
	}
	return count, hash, rev, err
}

// authzStatus is the memoized AuthzStatus result for one revision.
type authzStatus struct {
	rev   int64
	count int
	hash  string
}

// DeltaSince returns the net add/del since clientRev by replaying the revision
// log (so an add-then-del of the same address collapses correctly). The rows
// and the returned revision are read in ONE snapshot (readTxRR): the revision
// must reflect exactly the rows replayed, so the agent never advances its
// cursor past a change it wasn't handed and skips it permanently.
func (s *Store) DeltaSince(ctx context.Context, clientRev int64) (add []AuthzMember, del []netip.Addr, rev int64, err error) {
	err = s.readTxRR(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT op, host(fips_addr), account_id::text FROM authz_revisions WHERE rev > $1 ORDER BY rev`, clientRev)
		if err != nil {
			return err
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
				return err
			}
			final[addr] = state{op: op, acct: acct}
		}
		if err := rows.Err(); err != nil {
			return err
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
		return tx.QueryRow(ctx, `SELECT COALESCE(max(rev), 0) FROM authz_revisions`).Scan(&rev)
	})
	if err != nil {
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
