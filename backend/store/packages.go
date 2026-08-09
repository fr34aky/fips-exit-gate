package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPackageNotFound is returned for an unknown or inactive package.
var ErrPackageNotFound = errors.New("store: package not found")

// ErrPurchaseNotFound is returned when no purchase matches (e.g. an unknown
// BTCPay invoice id in a webhook).
var ErrPurchaseNotFound = errors.New("store: purchase not found")

// Package is a catalog entry the portal offers for purchase.
type Package struct {
	ID           string
	Kind         string // volume | time
	Name         string
	VolumeBytes  int64 // 0 for time passes
	ValidityDays int
	PriceMsat    int64
}

// ListPackages returns the active catalog.
func (s *Store) ListPackages(ctx context.Context) ([]Package, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, kind, name, COALESCE(volume_bytes, 0), validity_days, price_msat
		 FROM package_types
		 WHERE active AND (available_until IS NULL OR available_until > now())
		 ORDER BY price_msat`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Package
	for rows.Next() {
		var p Package
		if err := rows.Scan(&p.ID, &p.Kind, &p.Name, &p.VolumeBytes, &p.ValidityDays, &p.PriceMsat); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPackage returns one active catalog entry by id.
func (s *Store) GetPackage(ctx context.Context, id string) (Package, error) {
	var p Package
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, kind, name, COALESCE(volume_bytes, 0), validity_days, price_msat
		 FROM package_types
		 WHERE id = $1 AND active AND (available_until IS NULL OR available_until > now())`, id).
		Scan(&p.ID, &p.Kind, &p.Name, &p.VolumeBytes, &p.ValidityDays, &p.PriceMsat)
	if err == pgx.ErrNoRows {
		return Package{}, ErrPackageNotFound
	}
	return p, err
}

// CreatePackage adds a catalog entry (admin). volumeBytes is ignored for time.
// availableUntil, when non-nil, hides the entry from the catalog after that
// instant (a time-limited promo); nil means always available.
func (s *Store) CreatePackage(ctx context.Context, kind, name string, volumeBytes int64, validityDays int, priceMsat int64, availableUntil *time.Time) (string, error) {
	var vb any
	if kind == "volume" {
		vb = volumeBytes
	}
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO package_types(kind, name, volume_bytes, validity_days, price_msat, available_until)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
		kind, name, vb, validityDays, priceMsat, availableUntil).Scan(&id)
	return id, err
}

// DeactivatePackage soft-deletes a catalog entry (admin): it leaves the catalog
// but existing purchases and entitlements are unaffected.
func (s *Store) DeactivatePackage(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE package_types SET active = false WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrPackageNotFound
	}
	return nil
}

// CreatePurchase records a pending purchase for an npub's account against a
// package, returning the purchase id. Settling it (payment, or admin) grants
// the entitlement.
func (s *Store) CreatePurchase(ctx context.Context, npub, packageID string) (string, error) {
	acct, err := s.GetAccountByNpub(ctx, npub)
	if err != nil {
		return "", err
	}
	var id string
	err = s.pool.QueryRow(ctx,
		`INSERT INTO purchases(account_id, package_type_id) VALUES ($1, $2) RETURNING id::text`,
		acct.ID, packageID).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

// SettlePurchase marks a purchase settled and grants the entitlement from its
// package. Idempotent: a second call (e.g. an admin re-settle) is a no-op
// thanks to the status guard and the unique entitlements.purchase_id. Used by
// the admin/dev path; the BTCPay webhook uses GrantByInvoice/VoidByInvoice.
func (s *Store) SettlePurchase(ctx context.Context, purchaseID string) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx,
			`SELECT status FROM purchases WHERE id = $1 FOR UPDATE`, purchaseID).Scan(&status)
		if err == pgx.ErrNoRows {
			return ErrPackageNotFound
		}
		if err != nil {
			return err
		}
		if status == "settled" {
			return nil // idempotent
		}
		return grantEntitlementTx(ctx, tx, purchaseID, "settled")
	})
	if err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// grantEntitlementTx inserts the purchase's entitlement (idempotent via the
// unique entitlements.purchase_id) and sets the purchase status. settled_at is
// stamped only when moving to 'settled', and never cleared afterwards.
func grantEntitlementTx(ctx context.Context, tx pgx.Tx, purchaseID, status string) error {
	var accountID, kind string
	var volumeBytes *int64
	var validityDays int
	err := tx.QueryRow(ctx,
		`SELECT p.account_id::text, pt.kind, pt.volume_bytes, pt.validity_days
		 FROM purchases p JOIN package_types pt ON pt.id = p.package_type_id
		 WHERE p.id = $1 FOR UPDATE`, purchaseID).Scan(&accountID, &kind, &volumeBytes, &validityDays)
	if err == pgx.ErrNoRows {
		return ErrPurchaseNotFound
	}
	if err != nil {
		return err
	}
	var vb any
	if kind == "volume" && volumeBytes != nil {
		vb = *volumeBytes
	}
	// Expiry counts from first grant (Processing), not from a later Settled, so
	// the buyer isn't shortchanged if confirmation lands days later.
	if _, err := tx.Exec(ctx,
		`INSERT INTO entitlements(account_id, purchase_id, kind, volume_bytes, expires_at)
		 VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))
		 ON CONFLICT (purchase_id) DO NOTHING`,
		accountID, purchaseID, kind, vb, validityDays); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`UPDATE purchases
		 SET status = $2,
		     settled_at = CASE WHEN $2 = 'settled' AND settled_at IS NULL THEN now() ELSE settled_at END
		 WHERE id = $1`, purchaseID, status)
	return err
}

// SeedPackages inserts a small default catalog if the catalog is empty.
func (s *Store) SeedPackages(ctx context.Context) error {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM package_types`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	defaults := []struct {
		kind        string
		name        string
		volumeBytes int64
		days        int
		priceMsat   int64
	}{
		{"time", "Unlimited — 1 day pass", 0, 1, 2_000_000},
		{"volume", "50 GB / 30 days", 50_000_000_000, 30, 5_000_000},
		{"volume", "500 GB / 90 days", 500_000_000_000, 90, 15_000_000},
		{"time", "Unlimited — 30 day pass", 0, 30, 10_000_000},
	}
	for _, d := range defaults {
		if _, err := s.CreatePackage(ctx, d.kind, d.name, d.volumeBytes, d.days, d.priceMsat, nil); err != nil {
			return err
		}
	}
	return nil
}
