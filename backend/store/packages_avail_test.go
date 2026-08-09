package store

import (
	"context"
	"testing"
	"time"
)

// A time-limited promo is hidden from the catalog once available_until passes,
// and can't be purchased then; a permanent entry (nil) and a still-live promo
// stay visible. Deactivation removes an entry regardless.
func TestPackageAvailableUntil(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	perm, err := st.CreatePackage(ctx, "time", "Perm", 0, 1, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	expired, err := st.CreatePackage(ctx, "time", "Expired promo", 0, 1, 21, &past)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	live, err := st.CreatePackage(ctx, "time", "Live promo", 0, 1, 42, &future)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	pkgs, err := st.ListPackages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		seen[p.ID] = true
	}
	if !seen[perm] || !seen[live] {
		t.Error("permanent and live-promo packages must be in the catalog")
	}
	if seen[expired] {
		t.Error("expired promo must be hidden from the catalog")
	}

	// GetPackage (the buy path) refuses an expired promo, allows a live one.
	if _, err := st.GetPackage(ctx, expired); err != ErrPackageNotFound {
		t.Errorf("GetPackage(expired) = %v, want ErrPackageNotFound", err)
	}
	if _, err := st.GetPackage(ctx, live); err != nil {
		t.Errorf("GetPackage(live) = %v, want ok", err)
	}

	// Deactivation removes a permanent entry too.
	if err := st.DeactivatePackage(ctx, perm); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetPackage(ctx, perm); err != ErrPackageNotFound {
		t.Errorf("GetPackage(deactivated) = %v, want ErrPackageNotFound", err)
	}
	if err := st.DeactivatePackage(ctx, "00000000-0000-0000-0000-000000000000"); err != ErrPackageNotFound {
		t.Errorf("DeactivatePackage(missing) = %v, want ErrPackageNotFound", err)
	}
}
