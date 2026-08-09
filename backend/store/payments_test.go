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

// Processing (payment SEEN, e.g. 0-conf on-chain) must NOT grant access; only
// Settled (payment final) does. This is the on-chain-finalization guarantee.
func TestProcessingDoesNotGrantSettledDoes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_1")
	addrA := addrOf(t, npubA)

	// Not authorized while pending.
	if full, _, _ := st.FullSet(ctx); setContains(full, addrA) {
		t.Fatal("authorized before any payment")
	}

	// Processing -> status 'processing' but NO grant, NO authorization.
	if err := st.MarkProcessing(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "processing" {
		t.Fatalf("status after Processing = %q, want processing", s)
	}
	if n := entCount(t, st, pid); n != 0 {
		t.Fatalf("entitlements after Processing = %d, want 0 (no grant on 0-conf)", n)
	}
	if full, _, _ := st.FullSet(ctx); setContains(full, addrA) {
		t.Fatal("authorized on unconfirmed payment (Processing must not grant)")
	}

	// A duplicate Processing is a no-op.
	if err := st.MarkProcessing(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "processing" {
		t.Fatalf("status after duplicate Processing = %q", s)
	}

	// Settled -> grant, status 'settled', authorized, exactly one entitlement.
	if err := st.GrantByInvoice(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status after Settled = %q, want settled", s)
	}
	if n := entCount(t, st, pid); n != 1 {
		t.Fatalf("entitlements after Settled = %d, want 1", n)
	}
	if full, _, _ := st.FullSet(ctx); !setContains(full, addrA) {
		t.Fatal("not authorized after Settled")
	}

	// A late Processing after Settled must NOT downgrade or revoke.
	if err := st.MarkProcessing(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status downgraded to %q by late Processing", s)
	}
	if full, _, _ := st.FullSet(ctx); !setContains(full, addrA) {
		t.Fatal("access lost after late Processing")
	}
}

// Settled directly (e.g. a Lightning payment, which is final immediately) grants
// without a prior Processing.
func TestGrantByInvoiceSettledDirect(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_2")
	if err := st.GrantByInvoice(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status = %q, want settled", s)
	}
	if full, _, _ := st.FullSet(ctx); !setContains(full, addrOf(t, npubA)) {
		t.Fatal("not authorized after direct Settled")
	}
}

// Invalid/Expired on an unconfirmed purchase marks it voided and grants nothing
// (there was never a grant to revoke — access is withheld until settlement).
func TestVoidByInvoiceOnProcessing(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_3")
	if err := st.MarkProcessing(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if err := st.VoidByInvoice(ctx, inv, "invalid"); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "invalid" {
		t.Fatalf("status = %q, want invalid", s)
	}
	if n := entCount(t, st, pid); n != 0 {
		t.Fatalf("entitlements = %d, want 0", n)
	}
	if full, _, _ := st.FullSet(ctx); setContains(full, addrOf(t, npubA)) {
		t.Fatal("authorized after void")
	}
}

// A void must never revoke an already-settled (confirmed) purchase.
func TestVoidByInvoiceIgnoresSettled(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_4")
	if err := st.GrantByInvoice(ctx, inv); err != nil {
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

// A Settled after an Invalid re-grants (the payment ultimately confirmed).
func TestGrantByInvoiceSettledAfterInvalid(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pid, inv := buyPackage(t, st, npubA, "inv_5")
	if err := st.MarkProcessing(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if err := st.VoidByInvoice(ctx, inv, "invalid"); err != nil {
		t.Fatal(err)
	}
	if err := st.GrantByInvoice(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if s := purchaseStatus(t, st, pid); s != "settled" {
		t.Fatalf("status = %q, want settled", s)
	}
	if !setContains(mustFullSet(t, st), addrOf(t, npubA)) {
		t.Fatal("not re-authorized after Settled following Invalid")
	}
}

// Unknown invoices are reported as not-found (the webhook acks them anyway).
func TestGrantVoidUnknownInvoice(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.MarkProcessing(ctx, "nope"); err != ErrPurchaseNotFound {
		t.Fatalf("processing unknown: want ErrPurchaseNotFound, got %v", err)
	}
	if err := st.GrantByInvoice(ctx, "nope"); err != ErrPurchaseNotFound {
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
	// A processing (confirming) purchase is still open.
	if err := st.MarkProcessing(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if open, _ = st.OpenPurchases(ctx, npubA); len(open) != 1 || open[0].Status != "processing" {
		t.Fatalf("open processing = %+v", open)
	}
	// Settled drops out of the open list.
	if err := st.GrantByInvoice(ctx, inv); err != nil {
		t.Fatal(err)
	}
	if open, _ = st.OpenPurchases(ctx, npubA); len(open) != 0 {
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
