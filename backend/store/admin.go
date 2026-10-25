package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrAccountNotFound is returned when an npub has no account.
	ErrAccountNotFound = errors.New("store: account not found")
	// ErrAddressInUse is returned when a whitelisted npub's address is already
	// enabled on another account (the deterministic-attribution constraint).
	ErrAddressInUse = errors.New("store: address already active on another account")
)

// CreateAccount creates (or returns) the account for an npub, plus its owner
// whitelist entry, then recomputes authz.
func (s *Store) CreateAccount(ctx context.Context, npub string) (Account, error) {
	npub = normNpub(npub)
	addr, err := fipsaddr.FromNpub(npub)
	if err != nil {
		return Account{}, fmt.Errorf("store: derive address: %w", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO accounts(npub, fips_addr) VALUES ($1, $2::inet) ON CONFLICT (npub) DO NOTHING`,
		npub, addr.String()); err != nil {
		return Account{}, err
	}
	acct, err := s.GetAccountByNpub(ctx, npub)
	if err != nil {
		return Account{}, err
	}
	// The owner entry is enabled unless this address is ALREADY active elsewhere
	// (the npub ACCEPTED a guest invitation on another account). The partial
	// unique index whitelist_active_addr (fips_addr) WHERE enabled AND NOT
	// pending allows an address to be active on at most one account, so such a
	// guest logging into their own account gets a parked (disabled) owner entry
	// rather than a conflict — they can view their account while their traffic
	// stays attributed to the account they chose; buying a package here (or
	// "use my own account") activates the owner row again. A merely PENDING
	// invitation elsewhere does not count: nobody can park someone else's owner
	// row by inviting them.
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO whitelist_entries(account_id, npub, fips_addr, role, enabled)
		 VALUES ($1, $2, $3::inet, 'owner',
		         NOT EXISTS (SELECT 1 FROM whitelist_entries WHERE fips_addr = $3::inet AND enabled AND NOT pending))
		 ON CONFLICT (account_id, npub) DO NOTHING`,
		acct.ID, npub, addr.String()); err != nil {
		return Account{}, err
	}
	if _, _, err := s.RecomputeAuthz(ctx); err != nil {
		return Account{}, err
	}
	return acct, nil
}

// GetAccountByNpub loads an account.
func (s *Store) GetAccountByNpub(ctx context.Context, npub string) (Account, error) {
	npub = normNpub(npub)
	var a Account
	var addr string
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, npub, host(fips_addr), status FROM accounts WHERE npub = $1`, npub).
		Scan(&a.ID, &a.Npub, &addr, &a.Status)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return Account{}, ErrAccountNotFound
		}
		return Account{}, err
	}
	a.FipsAddr, _ = netip.ParseAddr(addr)
	return a, nil
}

// AddWhitelist adds (or re-enables) a guest npub under an owner's account,
// ACCEPTED immediately. This is the operator path (admin API, support): the
// portal uses InviteGuest, which requires the guest's consent.
func (s *Store) AddWhitelist(ctx context.Context, ownerNpub, guestNpub, label string) error {
	guestNpub = normNpub(guestNpub)
	acct, err := s.GetAccountByNpub(ctx, ownerNpub)
	if err != nil {
		return err
	}
	addr, err := fipsaddr.FromNpub(guestNpub)
	if err != nil {
		return fmt.Errorf("store: derive guest address: %w", err)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO whitelist_entries(account_id, npub, fips_addr, role, label, enabled, pending)
		 VALUES ($1, $2, $3::inet, 'guest', $4, true, false)
		 ON CONFLICT (account_id, npub) DO UPDATE SET enabled = true, pending = false, label = EXCLUDED.label`,
		acct.ID, guestNpub, addr.String(), label)
	if err != nil {
		if strings.Contains(err.Error(), "whitelist_active_addr") {
			return ErrAddressInUse
		}
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// SetWhitelistEnabled toggles a guest entry. Re-enabling a guest whose address
// has meanwhile become active on another account (typically their own) makes
// the row pending again instead of silently pulling the address back: that
// move needs the guest's consent. Disabling a still-pending invitation deletes
// it (nothing to keep), and disabling an accepted guest hands the address back
// to the guest's own account if they have one, so they are never left with no
// active row at all.
func (s *Store) SetWhitelistEnabled(ctx context.Context, ownerNpub, guestNpub string, enabled bool) error {
	guestNpub = normNpub(guestNpub)
	acct, err := s.GetAccountByNpub(ctx, ownerNpub)
	if err != nil {
		return err
	}
	if err := s.inTx(ctx, func(tx pgx.Tx) error {
		if !enabled {
			tag, err := tx.Exec(ctx,
				`DELETE FROM whitelist_entries WHERE account_id = $1 AND npub = $2 AND role = 'guest' AND pending`,
				acct.ID, guestNpub)
			if err != nil {
				return err
			}
			if tag.RowsAffected() > 0 {
				return nil // withdrawn invitation; nothing was active
			}
		}
		var addr string
		err := tx.QueryRow(ctx,
			`UPDATE whitelist_entries w SET enabled = $3,
			   pending = CASE WHEN $3 AND w.role = 'guest' AND NOT w.enabled AND EXISTS (
			                SELECT 1 FROM whitelist_entries o
			                WHERE o.fips_addr = w.fips_addr AND o.id <> w.id AND o.enabled AND NOT o.pending)
			             THEN true ELSE w.pending END
			 WHERE account_id = $1 AND npub = $2
			 RETURNING host(fips_addr)`,
			acct.ID, guestNpub, enabled).Scan(&addr)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if !enabled {
			return reactivateOwnerIfOrphanTx(ctx, tx, addr)
		}
		return nil
	}); err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// CreditVolume grants a volume entitlement (bytes valid for validityDays),
// creating the account if needed. Stand-in for a settled purchase until Phase 4.
func (s *Store) CreditVolume(ctx context.Context, npub string, volumeBytes int64, validityDays int) error {
	acct, err := s.CreateAccount(ctx, npub)
	if err != nil {
		return err
	}
	expires := time.Now().Add(time.Duration(validityDays) * 24 * time.Hour)
	if err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO entitlements(account_id, kind, volume_bytes, expires_at)
			 VALUES ($1, 'volume', $2, $3)`, acct.ID, volumeBytes, expires); err != nil {
			return err
		}
		return activateOwnerTx(ctx, tx, acct.ID)
	}); err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// CreditTime grants a time-pass entitlement valid for validityDays.
func (s *Store) CreditTime(ctx context.Context, npub string, validityDays int) error {
	acct, err := s.CreateAccount(ctx, npub)
	if err != nil {
		return err
	}
	expires := time.Now().Add(time.Duration(validityDays) * 24 * time.Hour)
	if err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO entitlements(account_id, kind, expires_at) VALUES ($1, 'time', $2)`,
			acct.ID, expires); err != nil {
			return err
		}
		return activateOwnerTx(ctx, tx, acct.ID)
	}); err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}
