package store

import (
	"context"
	"testing"
)

// TestGuestCanCreateOwnAccount reproduces the hardware M3 bug: a whitelisted
// guest (active on another account) logging into their OWN account must not hit
// the active-address unique index. Their owner entry is created disabled so the
// address stays attributed to the account where it is currently active.
func TestGuestCanCreateOwnAccount(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Owner account A with a credit, and guest B whitelisted+enabled under A.
	if err := st.CreditVolume(ctx, npubA, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	if err := st.AddWhitelist(ctx, npubA, npubB, "guest"); err != nil {
		t.Fatal(err)
	}
	// B's address is now active under A.
	full, _, _ := st.FullSet(ctx)
	if !setContains(full, addrOf(t, npubB)) {
		t.Fatal("guest not authorized under owner")
	}

	// B logs into its OWN account (transparent/NIP-07 both call CreateAccount).
	// This previously 500'd on the whitelist_active_addr unique index.
	if _, err := st.CreateAccount(ctx, npubB); err != nil {
		t.Fatalf("guest creating own account: %v", err)
	}
	// B's account exists and is retrievable.
	if _, err := st.GetAccountByNpub(ctx, npubB); err != nil {
		t.Fatalf("guest own account not found: %v", err)
	}
	// Attribution unchanged: B's address is still active exactly once, under A.
	var n int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM whitelist_entries WHERE fips_addr = $1::inet AND enabled`,
		addrOf(t, npubB).String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("guest address active on %d entries, want exactly 1", n)
	}
}
