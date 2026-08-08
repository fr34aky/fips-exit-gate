package store

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

// These tests need a Postgres. Set TEST_DATABASE_URL, e.g.:
//   TEST_DATABASE_URL=postgres://fips:pw@localhost:5433/fips_exit go test ./backend/...
// Each test runs on a fresh schema (drop+recreate public) for isolation.

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB integration test")
	}
	ctx := context.Background()
	// Fresh schema per test.
	tmp, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := tmp.pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	tmp.Close()

	st, err := Open(ctx, dsn) // re-open runs migrations on the clean schema
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := st.SeedDefaults(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// A couple of valid npubs (from the fipsaddr vectors) and their addresses.
const (
	npubA = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
	npubB = "npub1l2vyh47mk2p0qlsku7hg0vn29faehy9hy34ygaclpn66ukqp3afqutajft"
)

func addrOf(t *testing.T, npub string) netip.Addr {
	t.Helper()
	a, err := fipsaddr.FromNpub(npub)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func setContains(members []AuthzMember, a netip.Addr) bool {
	for _, m := range members {
		if m.Addr == a {
			return true
		}
	}
	return false
}

func TestEnrollAndAuth(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	tok, err := st.CreateEnrollToken(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	nodeID, authToken, err := st.EnrollNode(ctx, tok, "pubkey-b64", "node-1")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := st.AuthNode(ctx, nodeID, authToken); err != nil {
		t.Errorf("auth good token: %v", err)
	}
	if err := st.AuthNode(ctx, nodeID, "wrong"); err != ErrUnauthorized {
		t.Errorf("auth bad token: want unauthorized, got %v", err)
	}
	// Token is one-time.
	if _, _, err := st.EnrollNode(ctx, tok, "x", "n2"); err != ErrInvalidEnrollToken {
		t.Errorf("reuse enroll token: want invalid, got %v", err)
	}
}

func TestCreditGrantsAuthz(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// No entitlement yet: account exists but is not authorized.
	if _, err := st.CreateAccount(ctx, npubA); err != nil {
		t.Fatal(err)
	}
	full, _, _ := st.FullSet(ctx)
	if setContains(full, addrOf(t, npubA)) {
		t.Fatal("account authorized before any entitlement")
	}

	// Credit a volume package: owner address becomes authorized.
	if err := st.CreditVolume(ctx, npubA, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	full, _, _ = st.FullSet(ctx)
	if !setContains(full, addrOf(t, npubA)) {
		t.Fatal("owner not authorized after credit")
	}

	// Whitelist a guest: it shares the package and becomes authorized too.
	if err := st.AddWhitelist(ctx, npubA, npubB, "friend"); err != nil {
		t.Fatal(err)
	}
	full, _, _ = st.FullSet(ctx)
	if !setContains(full, addrOf(t, npubB)) {
		t.Fatal("whitelisted guest not authorized")
	}
}

func TestUsageConsumptionAndRevoke(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Small volume package (10 KB) so we can exhaust it.
	if err := st.CreditVolume(ctx, npubA, 10_000, 30); err != nil {
		t.Fatal(err)
	}
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, err := st.EnrollNode(ctx, tok, "pk", "node")
	if err != nil {
		t.Fatal(err)
	}
	addrA := addrOf(t, npubA)

	// Under quota: report 4 KB, still authorized.
	revoke, err := st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "r1", Samples: []SampleInput{{Service: "clearnet", Addr: addrA, Bytes: 4_000}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(revoke) != 0 {
		t.Fatalf("unexpected revoke under quota: %v", revoke)
	}
	full, _, _ := st.FullSet(ctx)
	if !setContains(full, addrA) {
		t.Fatal("revoked while under quota")
	}

	// Idempotent replay of r1 must not double-count.
	if _, err := st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "r1", Samples: []SampleInput{{Service: "clearnet", Addr: addrA, Bytes: 4_000}},
	}); err != nil {
		t.Fatal(err)
	}

	// Over quota: report another 8 KB (total 12 KB > 10 KB) -> revoked inline.
	revoke, err = st.IngestUsage(ctx, nodeID, ReportInput{
		ReportID: "r2", Samples: []SampleInput{{Service: "clearnet", Addr: addrA, Bytes: 8_000}},
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range revoke {
		if a == addrA {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected inline revoke of %s, got %v", addrA, revoke)
	}
	full, _, _ = st.FullSet(ctx)
	if setContains(full, addrA) {
		t.Fatal("still authorized after exhausting quota")
	}
}

func TestDeltaSince(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	_, rev0, err := st.RecomputeAuthz(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreditVolume(ctx, npubA, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	add, del, rev1, err := st.DeltaSince(ctx, rev0)
	if err != nil {
		t.Fatal(err)
	}
	if rev1 <= rev0 || len(add) != 1 || len(del) != 0 || add[0].Addr != addrOf(t, npubA) {
		t.Fatalf("delta after credit: add=%v del=%v rev0=%d rev1=%d", add, del, rev0, rev1)
	}
}

func TestAddressInUse(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.CreditVolume(ctx, npubA, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	if err := st.CreditVolume(ctx, npubB, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	// npubB is its own account owner; whitelisting it under A must conflict on
	// the active-address uniqueness constraint.
	if err := st.AddWhitelist(ctx, npubA, npubB, "x"); err != ErrAddressInUse {
		t.Fatalf("want ErrAddressInUse, got %v", err)
	}
}
