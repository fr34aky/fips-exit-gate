package store

import (
	"context"
	"testing"
)

// TestUsageByteClampNoOverflow: a hostile/buggy node reporting a byte count near
// uint64 max must be clamped, never overflowing the uint64->int64 conversion or
// the weighted-consumption multiplication into a negative value.
func TestUsageByteClampNoOverflow(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	// Big enough that the clamped sample doesn't exhaust it.
	if err := st.CreditVolume(ctx, npubA, 2<<40, 30); err != nil {
		t.Fatal(err)
	}
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, err := st.EnrollNode(ctx, tok, "pk", "node")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "big",
		Samples:  []SampleInput{{Service: "clearnet", Addr: addrOf(t, npubA), Bytes: ^uint64(0)}},
	}); err != nil {
		t.Fatal(err)
	}

	var sampleBytes, used int64
	if err := st.pool.QueryRow(ctx, `SELECT bytes FROM usage_samples LIMIT 1`).Scan(&sampleBytes); err != nil {
		t.Fatal(err)
	}
	if err := st.pool.QueryRow(ctx,
		`SELECT volume_used FROM entitlements WHERE account_id = (SELECT id FROM accounts WHERE npub = $1)`,
		npubA).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if sampleBytes != int64(1<<40) {
		t.Fatalf("sample bytes not clamped: got %d, want %d", sampleBytes, int64(1<<40))
	}
	if used < 0 || sampleBytes < 0 {
		t.Fatalf("overflow to negative: used=%d sample=%d", used, sampleBytes)
	}
	if used != int64(1<<40) { // clearnet rate 1.0x
		t.Fatalf("weighted consumption wrong: got %d, want %d", used, int64(1<<40))
	}
}
