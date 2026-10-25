package store

import (
	"context"
	"testing"
	"time"
)

func TestAggregateUsageRollsUpAndKeepsTotals(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.CreditVolume(ctx, npubA, 10_000_000, 30); err != nil {
		t.Fatal(err)
	}
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, _ := st.EnrollNode(ctx, tok, "pk", "node")
	addrA := addrOf(t, npubA)
	acct, _ := st.GetAccountByNpub(ctx, npubA)

	old := time.Now().Add(-100 * 24 * time.Hour)
	for i, b := range []uint64{1000, 2000} {
		if _, err := st.IngestUsage(ctx, nodeID, ReportInput{
			ReportID: "old" + string(rune('a'+i)), WindowEnd: old.Add(time.Duration(i) * time.Minute),
			Samples: []SampleInput{{Service: "clearnet", Addr: addrA, Bytes: b}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// An old sample for a service key not in the catalog (service_id NULL):
	// unbillable; must be dropped by the roll-up, never wedge it.
	if _, err := st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "oldunknown", WindowEnd: old,
		Samples: []SampleInput{{Service: "unknown:9999", Addr: addrA, Bytes: 77}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "fresh", WindowEnd: time.Now(),
		Samples: []SampleInput{{Service: "clearnet", Addr: addrA, Bytes: 500}},
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := st.Summary(ctx, npubA)
	if before.UsageBytes != 3577 {
		t.Fatalf("usage before = %d, want 3577", before.UsageBytes)
	}

	n, reports, err := st.AggregateUsage(ctx, time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || reports != 3 {
		t.Fatalf("removed %d samples / %d reports, want 3 / 3", n, reports)
	}
	var raw int
	_ = st.pool.QueryRow(ctx, `SELECT count(*) FROM usage_samples`).Scan(&raw)
	if raw != 1 {
		t.Fatalf("raw samples left = %d, want 1 (the fresh one)", raw)
	}
	var daily int64
	_ = st.pool.QueryRow(ctx, `SELECT COALESCE(sum(bytes),0) FROM usage_daily WHERE account_id = $1`, acct.ID).Scan(&daily)
	if daily != 3000 {
		t.Fatalf("daily total = %d, want 3000", daily)
	}
	// Dashboard totals are unchanged by the roll-up, except the unbillable
	// unknown-service bytes, which are dropped.
	after, _ := st.Summary(ctx, npubA)
	if after.UsageBytes != 3500 {
		t.Fatalf("usage after = %d, want 3500", after.UsageBytes)
	}
	svc, _ := st.UsageByService(ctx, acct.ID)
	total := int64(0)
	for _, s := range svc {
		total += s.Metered
	}
	if total != 3500 {
		t.Fatalf("per-service total after roll-up = %d, want 3500", total)
	}
	// Running it again is a no-op.
	if n, _, _ := st.AggregateUsage(ctx, time.Now().Add(-90*24*time.Hour)); n != 0 {
		t.Fatalf("second aggregation folded %d samples", n)
	}
}

func TestCompactAuthzRevisionsFallsBackToFull(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for _, np := range []string{npubA, npubB} {
		if err := st.CreditTime(ctx, np, 1); err != nil {
			t.Fatal(err)
		}
	}
	// Age every revision but keep churning so there is a newest row.
	if _, err := st.pool.Exec(ctx, `UPDATE authz_revisions SET created_at = now() - interval '40 days'`); err != nil {
		t.Fatal(err)
	}
	n, err := st.CompactAuthzRevisions(ctx, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("nothing compacted")
	}
	var minRev, maxRev, count int64
	_ = st.pool.QueryRow(ctx, `SELECT min(rev), max(rev), count(*) FROM authz_revisions`).Scan(&minRev, &maxRev, &count)
	if count != 1 || minRev != maxRev {
		t.Fatalf("compaction must keep exactly the newest row: min=%d max=%d count=%d", minRev, maxRev, count)
	}
	// A cursor from before the compacted range cannot be served a delta.
	if _, _, _, err := st.DeltaSince(ctx, 0); err != ErrCompacted {
		t.Fatalf("DeltaSince(0) after compaction: %v, want ErrCompacted", err)
	}
	// The current cursor still works (no change -> empty delta, same rev).
	add, del, rev, err := st.DeltaSince(ctx, maxRev)
	if err != nil || len(add)+len(del) != 0 || rev != maxRev {
		t.Fatalf("DeltaSince(max): %v %v %d %v", add, del, rev, err)
	}
	if _, _, _, err := st.DeltaSince(ctx, maxRev-1); err != nil {
		t.Fatalf("DeltaSince(max-1) must still be a delta: %v", err)
	}
}
