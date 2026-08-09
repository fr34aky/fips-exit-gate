package store

import (
	"context"
	"net/netip"
	"time"
)

// EntitlementView is one entitlement as shown in the portal.
type EntitlementView struct {
	Kind        string
	VolumeBytes int64
	VolumeUsed  int64
	ExpiresAt   time.Time
	Active      bool
}

// Remaining returns remaining volume bytes (0 for time passes).
func (e EntitlementView) Remaining() int64 {
	if e.Kind != "volume" {
		return 0
	}
	if e.VolumeUsed > e.VolumeBytes {
		return 0
	}
	return e.VolumeBytes - e.VolumeUsed
}

// WhitelistView is one whitelist entry as shown in the portal.
type WhitelistView struct {
	Npub    string
	Label   string
	Role    string
	Enabled bool
	Addr    netip.Addr
}

// AccountSummary is everything the portal dashboard needs for an account.
type AccountSummary struct {
	Account      Account
	Entitlements []EntitlementView
	Whitelist    []WhitelistView
	Open         []PurchaseView // pending/processing purchases awaiting payment
	UsageBytes   int64
}

// NpubByAddr resolves the npub bound to a fips source address, if the address
// is a known (enabled) whitelist entry or account owner. Used by transparent
// fips-source login.
func (s *Store) NpubByAddr(ctx context.Context, addr netip.Addr) (string, error) {
	var npub string
	err := s.pool.QueryRow(ctx,
		`SELECT npub FROM whitelist_entries WHERE fips_addr = $1::inet AND enabled
		 ORDER BY (role = 'owner') DESC LIMIT 1`, addr.String()).Scan(&npub)
	if err != nil {
		return "", ErrAccountNotFound
	}
	return npub, nil
}

// Summary loads an account's dashboard data.
func (s *Store) Summary(ctx context.Context, npub string) (AccountSummary, error) {
	acct, err := s.GetAccountByNpub(ctx, npub)
	if err != nil {
		return AccountSummary{}, err
	}
	out := AccountSummary{Account: acct}

	entRows, err := s.pool.Query(ctx,
		`SELECT kind, COALESCE(volume_bytes, 0), volume_used, expires_at,
		        (now() >= starts_at AND now() <= expires_at
		         AND (kind = 'time' OR volume_used < volume_bytes)) AS active
		 FROM entitlements WHERE account_id = $1 ORDER BY expires_at`, acct.ID)
	if err != nil {
		return out, err
	}
	for entRows.Next() {
		var e EntitlementView
		if err := entRows.Scan(&e.Kind, &e.VolumeBytes, &e.VolumeUsed, &e.ExpiresAt, &e.Active); err != nil {
			entRows.Close()
			return out, err
		}
		out.Entitlements = append(out.Entitlements, e)
	}
	entRows.Close()
	if err := entRows.Err(); err != nil {
		return out, err
	}

	wlRows, err := s.pool.Query(ctx,
		`SELECT npub, COALESCE(label, ''), role, enabled, host(fips_addr)
		 FROM whitelist_entries WHERE account_id = $1 ORDER BY (role = 'owner') DESC, created_at`, acct.ID)
	if err != nil {
		return out, err
	}
	for wlRows.Next() {
		var w WhitelistView
		var addr string
		if err := wlRows.Scan(&w.Npub, &w.Label, &w.Role, &w.Enabled, &addr); err != nil {
			wlRows.Close()
			return out, err
		}
		w.Addr, _ = netip.ParseAddr(addr)
		out.Whitelist = append(out.Whitelist, w)
	}
	wlRows.Close()
	if err := wlRows.Err(); err != nil {
		return out, err
	}

	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(sum(bytes), 0) FROM usage_samples WHERE account_id = $1`, acct.ID).
		Scan(&out.UsageBytes); err != nil {
		return out, err
	}

	open, err := s.OpenPurchases(ctx, npub)
	if err != nil {
		return out, err
	}
	out.Open = open
	return out, nil
}
