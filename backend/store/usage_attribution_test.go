package store

import (
	"context"
	"testing"
)

// TestUsageAttributedToLastHolderAfterRevocation: a report that arrives after
// the address left the authorized set (buffered through an outage, or bytes
// that landed right before an inline revoke) is still billed to the account
// that held the address, instead of being recorded with no account.
func TestUsageAttributedToLastHolderAfterRevocation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	if err := st.CreditVolume(ctx, npubA, 100_000, 30); err != nil {
		t.Fatal(err)
	}
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, err := st.EnrollNode(ctx, tok, "pk", "node")
	if err != nil {
		t.Fatal(err)
	}
	addrA := addrOf(t, npubA)
	acct, err := st.GetAccountByNpub(ctx, npubA)
	if err != nil {
		t.Fatal(err)
	}

	// Revoke (disable the owner entry) so the address is gone from authz_current.
	if err := st.SetWhitelistEnabled(ctx, npubA, npubA, false); err != nil {
		t.Fatal(err)
	}
	if setContains(mustFullSet(t, st), addrA) {
		t.Fatal("still authorized after disable")
	}

	// A late report for that address.
	if _, err := st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "late", Samples: []SampleInput{{Service: "clearnet", Addr: addrA, Bytes: 5_000}},
	}); err != nil {
		t.Fatal(err)
	}

	var sampleAcct *string
	if err := st.pool.QueryRow(ctx,
		`SELECT account_id::text FROM usage_samples WHERE report_id = 'late'`).Scan(&sampleAcct); err != nil {
		t.Fatal(err)
	}
	if sampleAcct == nil || *sampleAcct != acct.ID {
		t.Fatalf("late sample attributed to %v, want account %s", sampleAcct, acct.ID)
	}
	var used int64
	if err := st.pool.QueryRow(ctx,
		`SELECT volume_used FROM entitlements WHERE account_id = $1`, acct.ID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 5_000 {
		t.Fatalf("volume_used = %d, want 5000 (late usage must still draw down the package)", used)
	}
}
