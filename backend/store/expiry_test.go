package store

import (
	"context"
	"testing"
)

// TestEntitlementTimeExpiryDeauthorizes covers quota expiry by TIME (distinct
// from the volume-exhaustion path): an account with a still-unspent volume
// package loses authorization once the entitlement's expiry passes.
func TestEntitlementTimeExpiryDeauthorizes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if err := st.CreditVolume(ctx, npubA, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	if !setContains(mustFullSet(t, st), addrOf(t, npubA)) {
		t.Fatal("not authorized after credit")
	}

	// Force the entitlement to have expired (volume is untouched).
	if _, err := st.pool.Exec(ctx, `UPDATE entitlements SET expires_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	removed, _, err := st.RecomputeAuthz(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if setContains(mustFullSet(t, st), addrOf(t, npubA)) {
		t.Fatal("still authorized after the entitlement expired")
	}
	// The recompute should report the address as removed (drives inline revoke).
	found := false
	for _, a := range removed {
		if a == addrOf(t, npubA) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expiry did not report %s as removed: %v", addrOf(t, npubA), removed)
	}
}

// TestVoidExpiredInvoice covers the InvoiceExpired path (unpaid invoice) — it
// voids a not-yet-granted purchase and grants nothing.
func TestVoidExpiredInvoice(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_exp")
	if err := st.MarkProcessing(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if err := st.VoidByInvoice(ctx, inv, "expired"); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "expired" {
		t.Fatalf("status = %q, want expired", s)
	}
	if setContains(mustFullSet(t, st), addrOf(t, npubA)) {
		t.Fatal("authorized after an expired invoice")
	}
}
