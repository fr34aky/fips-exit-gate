package store

import (
	"context"
	"testing"
)

// buyPackage creates an account, a pending purchase for the first package, and
// attaches an invoice id. Returns the purchase id and invoice id.
func buyPackage(t *testing.T, st *Store, npub, invoiceID string) (string, string) {
	t.Helper()
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}
	pkgs, err := st.ListPackages(ctx)
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("packages: %v (n=%d)", err, len(pkgs))
	}
	if _, err := st.CreateAccount(ctx, npub); err != nil {
		t.Fatal(err)
	}
	pid, err := st.CreatePurchase(ctx, npub, pkgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AttachInvoice(ctx, pid, invoiceID, "http://checkout/"+invoiceID); err != nil {
		t.Fatal(err)
	}
	return pid, invoiceID
}

func purchaseStatus(t *testing.T, st *Store, pid string) string {
	t.Helper()
	var s string
	if err := st.pool.QueryRow(context.Background(), `SELECT status FROM purchases WHERE id=$1`, pid).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func entCount(t *testing.T, st *Store, pid string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM entitlements WHERE purchase_id=$1`, pid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Optimistic grant on Processing, then confirm on Settled.
func TestGrantByInvoiceProcessingThenSettled(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_1")
	addrA := addrOf(t, npubA)

	// Not authorized while pending.
	full, _, _ := st.FullSet(ctx)
	if setContains(full, addrA) {
		t.Fatal("authorized before any payment")
	}

	// Processing -> optimistic grant, status 'processing'.
	if err := st.GrantByInvoice(ctx, inv, false); err != nil {
		t.Fatal(err)
	}
	full, _, _ = st.FullSet(ctx)
	if !setContains(full, addrA) {
		t.Fatal("not authorized after Processing (optimistic grant failed)")
	}
	if s := purchaseStatus(t, st, pid); s != "processing" {
		t.Fatalf("status after Processing = %q, want processing", s)
	}

	// A duplicate Processing is a no-op (still one entitlement).
	if err := st.GrantByInvoice(ctx, inv, false); err != nil {
		t.Fatal(err)
	}
	if n := entCount(t, st, pid); n != 1 {
		t.Fatalf("entitlements after duplicate Processing = %d, want 1", n)
	}

	// Settled -> confirm, status 'settled', still one entitlement, still authorized.
	if err := st.GrantByInvoice(ctx, inv, true); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status after Settled = %q, want settled", s)
	}
	if n := entCount(t, st, pid); n != 1 {
		t.Fatalf("entitlements after Settled = %d, want 1", n)
	}
	full, _, _ = st.FullSet(ctx)
	if !setContains(full, addrA) {
		t.Fatal("not authorized after Settled")
	}

	// A late Processing after Settled must NOT downgrade the status.
	if err := st.GrantByInvoice(ctx, inv, false); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status downgraded to %q by late Processing", s)
	}
}

// Straight-to-Settled (e.g. a fast Lightning payment) grants without Processing.
func TestGrantByInvoiceSettledDirect(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_2")
	if err := st.GrantByInvoice(ctx, inv, true); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status = %q, want settled", s)
	}
	full, _, _ := st.FullSet(ctx)
	if !setContains(full, addrOf(t, npubA)) {
		t.Fatal("not authorized after direct Settled")
	}
}

// Invalid/Expired revokes an optimistic (processing) grant.
func TestVoidByInvoiceRevokes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_3")
	addrA := addrOf(t, npubA)

	if err := st.GrantByInvoice(ctx, inv, false); err != nil {
		t.Fatal(err)
	}
	full, _, _ := st.FullSet(ctx)
	if !setContains(full, addrA) {
		t.Fatal("not authorized after Processing")
	}

	// Invalid -> entitlement removed, address revoked, status 'invalid'.
	if err := st.VoidByInvoice(ctx, inv, "invalid"); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "invalid" {
		t.Fatalf("status = %q, want invalid", s)
	}
	if n := entCount(t, st, pid); n != 0 {
		t.Fatalf("entitlements after void = %d, want 0", n)
	}
	full, _, _ = st.FullSet(ctx)
	if setContains(full, addrA) {
		t.Fatal("still authorized after void")
	}
}

// A void must never revoke an already-settled purchase.
func TestVoidByInvoiceIgnoresSettled(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_4")
	if err := st.GrantByInvoice(ctx, inv, true); err != nil {
		t.Fatal(err)
	}
	if err := st.VoidByInvoice(ctx, inv, "invalid"); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("settled purchase voided to %q", s)
	}
	if !setContains(mustFullSet(t, st), addrOf(t, npubA)) {
		t.Fatal("settled purchase lost authorization after a spurious void")
	}
}

// A Settled after an Invalid re-grants (payment ultimately cleared).
func TestGrantByInvoiceSettledAfterInvalid(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_5")
	if err := st.GrantByInvoice(ctx, inv, false); err != nil {
		t.Fatal(err)
	}
	if err := st.VoidByInvoice(ctx, inv, "invalid"); err != nil {
		t.Fatal(err)
	}
	if err := st.GrantByInvoice(ctx, inv, true); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status = %q, want settled", s)
	}
	if !setContains(mustFullSet(t, st), addrOf(t, npubA)) {
		t.Fatal("not re-authorized after Settled following Invalid")
	}
}

// Unknown invoices are reported as not-found (webhook acks them without error).
func TestGrantVoidUnknownInvoice(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.GrantByInvoice(ctx, "nope", true); err != ErrPurchaseNotFound {
		t.Fatalf("grant unknown: want ErrPurchaseNotFound, got %v", err)
	}
	if err := st.VoidByInvoice(ctx, "nope", "invalid"); err != ErrPurchaseNotFound {
		t.Fatalf("void unknown: want ErrPurchaseNotFound, got %v", err)
	}
}

// OpenPurchases surfaces pending/processing purchases and drops settled ones.
func TestOpenPurchases(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	_, inv := buyPackage(t, st, npubA, "inv_6")

	open, err := st.OpenPurchases(ctx, npubA)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Status != "pending" || open[0].CheckoutURL == "" {
		t.Fatalf("open pending = %+v", open)
	}
	if err := st.GrantByInvoice(ctx, inv, true); err != nil {
		t.Fatal(err)
	}
	open, _ = st.OpenPurchases(ctx, npubA)
	if len(open) != 0 {
		t.Fatalf("settled purchase still open: %+v", open)
	}
}

func mustFullSet(t *testing.T, st *Store) []AuthzMember {
	t.Helper()
	full, _, err := st.FullSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return full
}
