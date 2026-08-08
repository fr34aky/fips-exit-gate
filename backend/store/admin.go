package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
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
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO whitelist_entries(account_id, npub, fips_addr, role)
		 VALUES ($1, $2, $3::inet, 'owner') ON CONFLICT (account_id, npub) DO NOTHING`,
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

// AddWhitelist adds (or re-enables) a guest npub under an owner's account.
func (s *Store) AddWhitelist(ctx context.Context, ownerNpub, guestNpub, label string) error {
	acct, err := s.GetAccountByNpub(ctx, ownerNpub)
	if err != nil {
		return err
	}
	addr, err := fipsaddr.FromNpub(guestNpub)
	if err != nil {
		return fmt.Errorf("store: derive guest address: %w", err)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO whitelist_entries(account_id, npub, fips_addr, role, label)
		 VALUES ($1, $2, $3::inet, 'guest', $4)
		 ON CONFLICT (account_id, npub) DO UPDATE SET enabled = true, label = EXCLUDED.label`,
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

// SetWhitelistEnabled toggles a guest entry.
func (s *Store) SetWhitelistEnabled(ctx context.Context, ownerNpub, guestNpub string, enabled bool) error {
	acct, err := s.GetAccountByNpub(ctx, ownerNpub)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE whitelist_entries SET enabled = $3 WHERE account_id = $1 AND npub = $2`,
		acct.ID, guestNpub, enabled); err != nil {
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
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO entitlements(account_id, kind, volume_bytes, expires_at)
		 VALUES ($1, 'volume', $2, $3)`, acct.ID, volumeBytes, expires); err != nil {
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
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO entitlements(account_id, kind, expires_at) VALUES ($1, 'time', $2)`,
		acct.ID, expires); err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}
