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
	Services     []ServiceUsage // per-service consumption (shared balance, per-service rates)
	UsageBytes   int64
}

// ServiceUsage is an account's consumption on one egress service. Metered is the
// raw bytes; Billed is the rate-weighted amount actually drawn from the shared
// balance (bytes * rate_ppm / 1e6) — so a 1.5x service bills 1.5x its bytes.
type ServiceUsage struct {
	Key     string
	Name    string
	RatePPM int64
	Metered int64
	Billed  int64
}

// UsageByService returns per-service consumption for an account across all
// enabled services (0 for services with no usage yet), so the dashboard can
// show one balance draining at each service's rate.
func (s *Store) UsageByService(ctx context.Context, accountID string) ([]ServiceUsage, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT sv.key, sv.name, sv.rate_ppm,
		        COALESCE(sum(us.bytes), 0) AS metered,
		        COALESCE(sum(us.bytes * sv.rate_ppm / 1000000), 0) AS billed
		 FROM services sv
		 LEFT JOIN usage_samples us
		   ON us.service_id = sv.id AND us.account_id = $1
		 WHERE sv.enabled
		 GROUP BY sv.key, sv.name, sv.rate_ppm
		 ORDER BY sv.key`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceUsage
	for rows.Next() {
		var u ServiceUsage
		if err := rows.Scan(&u.Key, &u.Name, &u.RatePPM, &u.Metered, &u.Billed); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
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

	svc, err := s.UsageByService(ctx, acct.ID)
	if err != nil {
		return out, err
	}
	out.Services = svc
	return out, nil
}
