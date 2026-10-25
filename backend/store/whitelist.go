package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
	"github.com/jackc/pgx/v5"
)

// normNpub canonicalizes an npub for storage and comparison: bech32 is
// case-insensitive, so "NPUB1…" and "npub1…" are the same key and must map to
// the same rows (otherwise an uppercase self-invite slips past the identity
// check and a second account appears for the same person).
func normNpub(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Whitelist model
//
// An address is attributed to at most ONE account at a time: the row that is
// `enabled AND NOT pending` (partial unique index whitelist_active_addr).
// Owner rows are created with the account. Guest rows created through the
// portal are INVITATIONS: they start `pending` and do nothing until the invited
// npub accepts them from its own dashboard, so nobody can attach (and thereby
// lock out) an identity that isn't theirs. Accepting moves the address to the
// host account and parks the guest's own owner row; buying a package on one's
// own account (or pressing "use my own account") moves it back.

var (
	// ErrGuestLimit: the account already has MaxGuests guest entries.
	ErrGuestLimit = errors.New("store: guest limit reached for this account")
	// ErrNoActiveEntitlement: only accounts with an active package may invite.
	ErrNoActiveEntitlement = errors.New("store: an active package is required to invite guests")
	// ErrSelfWhitelist: an account cannot invite its own npub.
	ErrSelfWhitelist = errors.New("store: that is this account's own identity")
	// ErrInviteNotFound: no pending invitation matches.
	ErrInviteNotFound = errors.New("store: no such pending invitation")
)

// DefaultMaxGuests bounds guests per account when MaxGuests is unset.
const DefaultMaxGuests = 5

// Invite is a pending guest invitation as seen by the invited npub.
type Invite struct {
	HostNpub  string
	HostAddr  netip.Addr
	Label     string
	AccountID string
}

func (s *Store) maxGuests() int {
	if s.MaxGuests > 0 {
		return s.MaxGuests
	}
	return DefaultMaxGuests
}

// InviteGuest is the portal's "add a device or person": it creates a PENDING
// guest row that the invited npub must accept. Requires an active entitlement
// on the inviting account and respects the per-account guest cap (enabled
// rows). Re-inviting an existing guest leaves an active row alone (label
// refreshed) and puts any other (disabled, moved away) row back to pending:
// attaching an identity always needs that identity's say-so. pending reports
// whether an acceptance is now outstanding (false = the guest is already
// active on this account).
func (s *Store) InviteGuest(ctx context.Context, ownerNpub, guestNpub, label string) (pending bool, err error) {
	guestNpub = normNpub(guestNpub)
	acct, err := s.GetAccountByNpub(ctx, ownerNpub)
	if err != nil {
		return false, err
	}
	addr, err := fipsaddr.FromNpub(guestNpub)
	if err != nil {
		return false, fmt.Errorf("store: derive guest address: %w", err)
	}
	if addr == acct.FipsAddr {
		return false, ErrSelfWhitelist
	}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM entitlements WHERE account_id = $1
			   AND now() >= starts_at AND now() <= expires_at
			   AND (kind = 'time' OR volume_used < volume_bytes))`, acct.ID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return ErrNoActiveEntitlement
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM whitelist_entries WHERE account_id = $1 AND npub = $2)`,
			acct.ID, guestNpub).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			var n int
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM whitelist_entries WHERE account_id = $1 AND role = 'guest' AND enabled`, acct.ID).Scan(&n); err != nil {
				return err
			}
			if n >= s.maxGuests() {
				return ErrGuestLimit
			}
		}
		return tx.QueryRow(ctx,
			`INSERT INTO whitelist_entries(account_id, npub, fips_addr, role, label, enabled, pending)
			 VALUES ($1, $2, $3::inet, 'guest', $4, true, true)
			 ON CONFLICT (account_id, npub) DO UPDATE
			   SET label = EXCLUDED.label, enabled = true,
			       pending = NOT (whitelist_entries.enabled AND NOT whitelist_entries.pending)
			 RETURNING pending`,
			acct.ID, guestNpub, addr.String(), label).Scan(&pending)
	})
	if err != nil {
		return false, err
	}
	// Pending rows never authorize anything, but a re-enable of an accepted
	// guest does; recompute either way (cheap, serialized).
	_, _, err = s.RecomputeAuthz(ctx)
	return pending, err
}

// WithdrawInvite deletes a still-pending invitation from the owner's side, so
// it stops counting and the guest no longer sees it. Returns ErrInviteNotFound
// for accepted (or unknown) rows; those are disabled with SetWhitelistEnabled.
func (s *Store) WithdrawInvite(ctx context.Context, ownerNpub, guestNpub string) error {
	acct, err := s.GetAccountByNpub(ctx, ownerNpub)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM whitelist_entries WHERE account_id = $1 AND npub = $2 AND role = 'guest' AND pending`,
		acct.ID, normNpub(guestNpub))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// PendingInvites lists invitations waiting for guestNpub's decision.
func (s *Store) PendingInvites(ctx context.Context, guestNpub string) ([]Invite, error) {
	guestNpub = normNpub(guestNpub)
	rows, err := s.pool.Query(ctx,
		`SELECT a.npub, host(a.fips_addr), COALESCE(w.label, ''), a.id::text
		 FROM whitelist_entries w JOIN accounts a ON a.id = w.account_id
		 WHERE w.npub = $1 AND w.pending AND w.enabled AND w.role = 'guest'
		 ORDER BY w.created_at`, guestNpub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		var addr string
		if err := rows.Scan(&inv.HostNpub, &addr, &inv.Label, &inv.AccountID); err != nil {
			return nil, err
		}
		inv.HostAddr, _ = netip.ParseAddr(addr)
		out = append(out, inv)
	}
	return out, rows.Err()
}

// AcceptInvite makes guestNpub an active member of hostNpub's account: the
// pending row becomes the address's one active row, and whatever row was
// active for that address before (the guest's own owner row, or an accepted
// invite elsewhere) is parked (disabled, not deleted) so it can be re-activated
// later. The host must still have an active package: accepting a stale
// invitation would otherwise park a paying guest's own row for nothing.
func (s *Store) AcceptInvite(ctx context.Context, guestNpub, hostNpub string) error {
	guestNpub, hostNpub = normNpub(guestNpub), normNpub(hostNpub)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var id, addr, hostID string
		err := tx.QueryRow(ctx,
			`SELECT w.id::text, host(w.fips_addr), a.id::text
			 FROM whitelist_entries w JOIN accounts a ON a.id = w.account_id
			 WHERE w.npub = $1 AND a.npub = $2 AND w.pending AND w.enabled AND w.role = 'guest'
			   AND a.status = 'active'
			 FOR UPDATE OF w`, guestNpub, hostNpub).Scan(&id, &addr, &hostID)
		if err == pgx.ErrNoRows {
			return ErrInviteNotFound
		}
		if err != nil {
			return err
		}
		var active bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM entitlements WHERE account_id = $1
			   AND now() >= starts_at AND now() <= expires_at
			   AND (kind = 'time' OR volume_used < volume_bytes))`, hostID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return ErrNoActiveEntitlement
		}
		return activateRowTx(ctx, tx, id, addr)
	})
	if err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// DeclineInvite removes a pending invitation.
func (s *Store) DeclineInvite(ctx context.Context, guestNpub, hostNpub string) error {
	guestNpub, hostNpub = normNpub(guestNpub), normNpub(hostNpub)
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM whitelist_entries w USING accounts a
		 WHERE a.id = w.account_id AND w.npub = $1 AND a.npub = $2 AND w.pending AND w.role = 'guest'`,
		guestNpub, hostNpub)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteNotFound
	}
	return nil
}

// ActivateOwner makes npub's own account the active one for its address,
// parking any accepted guest row elsewhere. Called when the account gains an
// entitlement (paying for your own package is an unambiguous choice) and from
// the dashboard's "use my own account" action.
func (s *Store) ActivateOwner(ctx context.Context, npub string) error {
	acct, err := s.GetAccountByNpub(ctx, npub)
	if err != nil {
		return err
	}
	if err := s.inTx(ctx, func(tx pgx.Tx) error {
		return activateOwnerTx(ctx, tx, acct.ID)
	}); err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// reactivateOwnerIfOrphanTx: when the row that was active for addr has just
// been parked or removed and nothing else is active for it, the address's
// owner row (if any) becomes active again, so a guest disabled by their host
// (or by support) falls back to their own account instead of to nothing.
func reactivateOwnerIfOrphanTx(ctx context.Context, tx pgx.Tx, addr string) error {
	var active bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM whitelist_entries WHERE fips_addr = $1::inet AND enabled AND NOT pending)`,
		addr).Scan(&active); err != nil {
		return err
	}
	if active {
		return nil
	}
	_, err := tx.Exec(ctx,
		`UPDATE whitelist_entries SET enabled = true, pending = false
		 WHERE fips_addr = $1::inet AND role = 'owner'`, addr)
	return err
}

// activateOwnerTx enables the account's owner row as the active row for its
// address. No-op if the account has no owner row yet.
func activateOwnerTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	var id, addr string
	err := tx.QueryRow(ctx,
		`SELECT id::text, host(fips_addr) FROM whitelist_entries
		 WHERE account_id = $1 AND role = 'owner' FOR UPDATE`, accountID).Scan(&id, &addr)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return activateRowTx(ctx, tx, id, addr)
}

// activateRowTx parks every other active row for addr, then marks row id as
// the active one (enabled, not pending). Ordering matters for the partial
// unique index: park first, then activate.
func activateRowTx(ctx context.Context, tx pgx.Tx, id, addr string) error {
	if _, err := tx.Exec(ctx,
		`UPDATE whitelist_entries SET enabled = false
		 WHERE fips_addr = $1::inet AND enabled AND NOT pending AND id <> $2::uuid`, addr, id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`UPDATE whitelist_entries SET enabled = true, pending = false WHERE id = $1::uuid`, id)
	return err
}

// AttachedTo reports the account (owner npub) an address is currently
// attributed to when that is NOT the given account: the guest-side view of an
// accepted invitation. Empty when the address is active on its own account or
// on none.
func (s *Store) AttachedTo(ctx context.Context, accountID string, addr netip.Addr) (string, error) {
	var host string
	err := s.pool.QueryRow(ctx,
		`SELECT a.npub FROM whitelist_entries w JOIN accounts a ON a.id = w.account_id
		 WHERE w.fips_addr = $1::inet AND w.enabled AND NOT w.pending AND w.account_id <> $2`,
		addr.String(), accountID).Scan(&host)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return host, err
}

// --- admin inspection ---------------------------------------------------------

// InspectedEntry is one whitelist row plus everything that competes with it.
type InspectedEntry struct {
	Npub       string              `json:"npub"`
	Addr       string              `json:"fips_addr"`
	Role       string              `json:"role"`
	Label      string              `json:"label,omitempty"`
	Enabled    bool                `json:"enabled"`
	Pending    bool                `json:"pending"`
	Authorized bool                `json:"authorized"`              // address present in authz_current
	AuthzOwner string              `json:"authz_account,omitempty"` // npub of the account authz_current attributes it to
	Conflicts  []InspectedConflict `json:"conflicts,omitempty"`     // same address on other accounts
}

// InspectedConflict is another account's row for the same address.
type InspectedConflict struct {
	AccountNpub string `json:"account_npub"`
	Role        string `json:"role"`
	Enabled     bool   `json:"enabled"`
	Pending     bool   `json:"pending"`
}

// AccountInspection answers "why can't this user get out?" in one call.
type AccountInspection struct {
	Account      Account           `json:"account"`
	Attached     string            `json:"attached_to,omitempty"` // owner address active on another account
	Whitelist    []InspectedEntry  `json:"whitelist"`
	Entitlements []EntitlementView `json:"entitlements"`
	Invites      []Invite          `json:"pending_invites"` // invitations this npub has not answered
}

// Inspect gathers an account's whitelist rows with conflicts and authz state,
// its entitlements, and invitations addressed to its npub.
func (s *Store) Inspect(ctx context.Context, npub string) (AccountInspection, error) {
	sum, err := s.Summary(ctx, npub)
	if err != nil {
		return AccountInspection{}, err
	}
	out := AccountInspection{Account: sum.Account, Entitlements: sum.Entitlements, Attached: sum.AttachedTo, Invites: sum.Invites}
	for _, w := range sum.Whitelist {
		e := InspectedEntry{Npub: w.Npub, Addr: w.Addr.String(), Role: w.Role, Label: w.Label, Enabled: w.Enabled, Pending: w.Pending}
		var owner *string
		if err := s.pool.QueryRow(ctx,
			`SELECT a.npub FROM authz_current c JOIN accounts a ON a.id = c.account_id WHERE c.fips_addr = $1::inet`,
			e.Addr).Scan(&owner); err != nil && err != pgx.ErrNoRows {
			return out, err
		}
		if owner != nil {
			e.Authorized, e.AuthzOwner = true, *owner
		}
		rows, err := s.pool.Query(ctx,
			`SELECT a.npub, w.role, w.enabled, w.pending
			 FROM whitelist_entries w JOIN accounts a ON a.id = w.account_id
			 WHERE w.fips_addr = $1::inet AND w.account_id <> $2 ORDER BY w.created_at`, e.Addr, sum.Account.ID)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var c InspectedConflict
			if err := rows.Scan(&c.AccountNpub, &c.Role, &c.Enabled, &c.Pending); err != nil {
				rows.Close()
				return out, err
			}
			e.Conflicts = append(e.Conflicts, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
		out.Whitelist = append(out.Whitelist, e)
	}
	return out, nil
}
