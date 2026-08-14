package store

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

// TestDeltaSyncConvergesUnderConcurrency guards the agent-sync invariant: an
// agent that only ever applies DeltaSince() results must reconstruct exactly
// the authoritative set, even while revisions are being appended concurrently.
//
// Regression for the TOCTOU where DeltaSince read the changed rows and the
// current revision in two separate snapshots: a revision committing between the
// two reads made the returned rev outrun the returned rows, so the agent
// advanced its cursor past a change it never received and skipped it forever
// (symptom: an address present in authz_current but missing from the exit's nft
// set, so a paid user stays captured). readTxRR now reads both in one snapshot.
func TestDeltaSyncConvergesUnderConcurrency(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Two accounts we toggle in and out of the authorized set to churn revisions.
	for _, np := range []string{npubA, npubB} {
		if _, err := st.CreateAccount(ctx, np); err != nil {
			t.Fatal(err)
		}
		if err := st.CreditVolume(ctx, np, 1_000_000, 30); err != nil {
			t.Fatal(err)
		}
	}

	const rounds = 300
	var churnDone atomic.Bool

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // churn: flip each owner entry enabled/disabled repeatedly.
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			_ = st.SetWhitelistEnabled(ctx, npubA, npubA, i%2 == 0)
			_ = st.SetWhitelistEnabled(ctx, npubB, npubB, i%3 == 0)
		}
		// Settle on a known final state so the agent has a fixed target to hit.
		_ = st.SetWhitelistEnabled(ctx, npubA, npubA, true)
		_ = st.SetWhitelistEnabled(ctx, npubB, npubB, true)
		churnDone.Store(true)
	}()

	// Fake agent: apply deltas from rev 0 forward, never re-reading full state.
	local := map[netip.Addr]struct{}{}
	var cur int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			add, del, rev, err := st.DeltaSince(ctx, cur)
			if err != nil {
				t.Errorf("DeltaSince: %v", err)
				return
			}
			for _, m := range add {
				local[m.Addr] = struct{}{}
			}
			for _, a := range del {
				delete(local, a)
			}
			cur = rev
			if churnDone.Load() {
				final, err := st.CurrentRev(ctx)
				if err != nil {
					t.Errorf("CurrentRev: %v", err)
					return
				}
				if cur == final {
					return // fully drained to the final revision
				}
			}
		}
	}()
	wg.Wait()

	// The delta-only reconstruction must equal the authoritative set exactly.
	full, _, err := st.FullSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[netip.Addr]struct{}{}
	for _, m := range full {
		want[m.Addr] = struct{}{}
	}
	if len(local) != len(want) {
		t.Fatalf("reconstructed set size %d != FullSet size %d (a revision was skipped)", len(local), len(want))
	}
	for a := range want {
		if _, ok := local[a]; !ok {
			t.Fatalf("address %s in FullSet but missing from delta-reconstructed set", a)
		}
	}
}
