package store

import (
	"context"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
	"github.com/jackc/pgx/v5"
)

// Two more valid npubs, derived from fixed private keys so the test is
// deterministic (an npub must be a real secp256k1 x-only public key).
var (
	npubC = npubFromPriv(3)
	npubD = npubFromPriv(4)
)

func npubFromPriv(b byte) string {
	var seed [32]byte
	for i := range seed {
		seed[i] = b
	}
	_, pub := btcec.PrivKeyFromBytes(seed[:])
	var x [32]byte
	copy(x[:], pub.SerializeCompressed()[1:33])
	return fipsaddr.EncodeNpub(x)
}

// TestRevisionsCommitInOrderUnderConcurrentRecomputes guards the second
// delta-sync invariant: revision numbers must become visible in increasing
// order. RecomputeAuthz used to run with no serialization, so two concurrent
// recomputes could take rev 10 and rev 11 and COMMIT in the opposite order; a
// cursor that read max(rev)=11 in between would never see 10. The advisory lock
// in RecomputeAuthz makes commit order match revision order.
//
// The reader below is the strictest possible cursor: it only ever asks for
// rows above the highest revision it has seen (a single-snapshot read each
// time, like DeltaSince) and must still end up having observed every revision.
func TestRevisionsCommitInOrderUnderConcurrentRecomputes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Several accounts, one writer goroutine each, all toggling concurrently so
	// RecomputeAuthz calls genuinely overlap.
	npubs := []string{npubA, npubB, npubC, npubD}
	for _, np := range npubs {
		if _, err := st.CreateAccount(ctx, np); err != nil {
			t.Fatal(err)
		}
		if err := st.CreditVolume(ctx, np, 1_000_000, 30); err != nil {
			t.Fatal(err)
		}
	}

	const rounds = 150
	var writers sync.WaitGroup
	stop := make(chan struct{})
	for i, np := range npubs {
		writers.Add(1)
		go func(i int, np string) {
			defer writers.Done()
			for r := 0; r < rounds; r++ {
				_ = st.SetWhitelistEnabled(ctx, np, np, (r+i)%2 == 0)
			}
		}(i, np)
	}
	go func() { writers.Wait(); close(stop) }()

	seen := map[int64]bool{}
	var cursor int64
	readAbove := func() {
		_ = st.readTxRR(ctx, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT rev FROM authz_revisions WHERE rev > $1 ORDER BY rev`, cursor)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var rev int64
				if err := rows.Scan(&rev); err != nil {
					return err
				}
				seen[rev] = true
				if rev > cursor {
					cursor = rev
				}
			}
			return rows.Err()
		})
	}
	for {
		select {
		case <-stop:
		default:
			readAbove()
			continue
		}
		break
	}
	readAbove() // drain

	// Every revision that exists must have passed under the cursor.
	rows, err := st.pool.Query(ctx, `SELECT rev FROM authz_revisions ORDER BY rev`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var total, missed int
	var firstMissed int64
	for rows.Next() {
		var rev int64
		if err := rows.Scan(&rev); err != nil {
			t.Fatal(err)
		}
		total++
		if !seen[rev] {
			missed++
			if firstMissed == 0 {
				firstMissed = rev
			}
		}
	}
	if total < 100 {
		t.Fatalf("too little churn to be meaningful: %d revisions", total)
	}
	if missed > 0 {
		t.Fatalf("cursor skipped %d of %d revisions (first: %d): revisions became visible out of order", missed, total, firstMissed)
	}
}
