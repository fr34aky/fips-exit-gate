package store

import (
	"context"
	"testing"
)

// TestTwoServicesSharedBalance is the Phase 4b modularity proof at the store
// level: a second egress service (tor @ 1.5x) added as a catalog row draws on
// the SAME balance as clearnet (1.0x), each metered at its own rate.
func TestTwoServicesSharedBalance(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Register Tor as a second service at 1.5x. No other code changes.
	if err := st.CreateService(ctx, "tor", "Tor", 1081, 1_500_000, true); err != nil {
		t.Fatal(err)
	}
	svcs, err := st.Services(ctx)
	if err != nil || len(svcs) != 2 {
		t.Fatalf("services = %v (err %v), want clearnet+tor", svcs, err)
	}

	// One volume package (shared across both services).
	if err := st.CreditVolume(ctx, npubA, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	acct, err := st.GetAccountByNpub(ctx, npubA)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, err := st.EnrollNode(ctx, tok, "pk", "node")
	if err != nil {
		t.Fatal(err)
	}
	addrA := addrOf(t, npubA)

	// 1000 bytes on each service in one report.
	if _, err := st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "r1",
		Samples: []SampleInput{
			{Service: "clearnet", Addr: addrA, Bytes: 1000},
			{Service: "tor", Addr: addrA, Bytes: 1000},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// The shared balance was drawn at the per-service rates:
	// clearnet 1000*1.0 + tor 1000*1.5 = 2500 weighted bytes.
	var used int64
	if err := st.pool.QueryRow(ctx,
		`SELECT volume_used FROM entitlements WHERE account_id = $1`, acct.ID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 2500 {
		t.Fatalf("shared balance volume_used = %d, want 2500 (1000*1.0 + 1000*1.5)", used)
	}

	// Per-service view matches: metered raw, billed rate-weighted.
	byKey := map[string]ServiceUsage{}
	su, err := st.UsageByService(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range su {
		byKey[u.Key] = u
	}
	if c := byKey["clearnet"]; c.Metered != 1000 || c.Billed != 1000 {
		t.Fatalf("clearnet usage = %+v, want metered/billed 1000/1000", c)
	}
	if tr := byKey["tor"]; tr.Metered != 1000 || tr.Billed != 1500 {
		t.Fatalf("tor usage = %+v, want metered/billed 1000/1500", tr)
	}
}

// TestCreateServiceUpsert verifies re-registering a key updates it in place.
func TestCreateServiceUpsert(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.CreateService(ctx, "tor", "Tor", 1081, 1_500_000, true); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateService(ctx, "tor", "Tor", 1081, 2_000_000, true); err != nil {
		t.Fatal(err)
	}
	svcs, _ := st.Services(ctx)
	var rate int64 = -1
	for _, s := range svcs {
		if s.Key == "tor" {
			rate = s.Rate
		}
	}
	if rate != 2_000_000 {
		t.Fatalf("tor rate after upsert = %d, want 2000000", rate)
	}
}
