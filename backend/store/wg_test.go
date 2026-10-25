package store

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

// A third valid npub (fixed private key) for the stranger case.
var npubWgStranger = func() string {
	var seed [32]byte
	for i := range seed {
		seed[i] = 0x77
	}
	_, pub := btcec.PrivKeyFromBytes(seed[:])
	var x [32]byte
	copy(x[:], pub.SerializeCompressed()[1:33])
	return fipsaddr.EncodeNpub(x)
}()

func testKey(b byte) string {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

func TestWgPeerIssueListDelete(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	owner, guest := npubA, npubB
	if err := st.CreditVolume(ctx, owner, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	if err := st.AddWhitelist(ctx, owner, guest, "phone"); err != nil {
		t.Fatal(err)
	}
	acct, _ := st.GetAccountByNpub(ctx, owner)

	// Owner issues a peer for themselves and one for the guest device.
	p1, err := st.CreateWgPeer(ctx, owner, owner, "laptop", testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := st.CreateWgPeer(ctx, owner, guest, "phone", testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if p1.AccountID != acct.ID || p2.AccountID != acct.ID {
		t.Fatalf("peers not attached to the owner's account: %+v %+v", p1, p2)
	}
	if p1.Idx == p2.Idx || !p1.IP4.IsValid() || !p1.IP6.IsValid() || p1.IP4 == p2.IP4 {
		t.Fatalf("bad allocation: %+v %+v", p1, p2)
	}
	if p1.IP4 == DefaultWgPools.Gateway4() || p2.IP4 == DefaultWgPools.Gateway4() {
		t.Fatal("a peer got the gateway address")
	}
	if !DefaultWgPools.Pool4.Contains(p1.IP4) || !DefaultWgPools.Pool6.Contains(p1.IP6) {
		t.Fatalf("addresses outside the pools: %v %v", p1.IP4, p1.IP6)
	}
	peers, err := st.ListWgPeers(ctx, acct.ID)
	if err != nil || len(peers) != 2 {
		t.Fatalf("list: %v %+v", err, peers)
	}
	// Duplicate key refused; invalid key refused; stranger refused; cap enforced.
	if _, err := st.CreateWgPeer(ctx, owner, owner, "dup", testKey(1)); err != ErrWgBadKey {
		t.Fatalf("duplicate key: %v", err)
	}
	if _, err := st.CreateWgPeer(ctx, owner, owner, "bad", "not-a-key"); err != ErrWgBadKey {
		t.Fatalf("invalid key: %v", err)
	}
	stranger := npubWgStranger
	if _, err := st.CreateAccount(ctx, stranger); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateWgPeer(ctx, stranger, owner, "steal", testKey(3)); err != ErrWgForbidden {
		t.Fatalf("stranger issuing for owner: %v", err)
	}
	st.MaxWgPeersPerAddr = 2
	if _, err := st.CreateWgPeer(ctx, owner, owner, "2nd", testKey(4)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateWgPeer(ctx, owner, owner, "3rd", testKey(5)); err != ErrWgPeerLimit {
		t.Fatalf("cap: %v", err)
	}
	// Agent table + etag changes only on change.
	all, etag1, err := st.WgPeerTable(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("table: %v %d", err, len(all))
	}
	_, etag2, _ := st.WgPeerTable(ctx)
	if etag1 != etag2 {
		t.Fatal("etag changed without a change")
	}
	// The guest may delete their own device; a stranger may not; the owner may.
	if err := st.DeleteWgPeer(ctx, stranger, p2.ID); err != ErrWgPeerNotFound {
		t.Fatalf("stranger delete: %v", err)
	}
	if err := st.DeleteWgPeer(ctx, guest, p2.ID); err != nil {
		t.Fatalf("guest deleting own device: %v", err)
	}
	if err := st.DeleteWgPeer(ctx, owner, p1.ID); err != nil {
		t.Fatal(err)
	}
	_, etag3, _ := st.WgPeerTable(ctx)
	if etag3 == etag1 {
		t.Fatal("etag unchanged after deletes")
	}
}

func TestWgNodesAnnounce(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, err := st.EnrollNode(ctx, tok, "pk", "exit-01")
	if err != nil {
		t.Fatal(err)
	}
	if nodes, _ := st.WgNodes(ctx); len(nodes) != 0 {
		t.Fatal("node without a key listed")
	}
	if err := st.SetNodeWg(ctx, nodeID, "garbage", "x"); err != ErrWgBadKey {
		t.Fatalf("bad node key accepted: %v", err)
	}
	if err := st.SetNodeWg(ctx, nodeID, testKey(9), "npub1exit.fips:51820"); err != nil {
		t.Fatal(err)
	}
	nodes, err := st.WgNodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].Endpoint != "npub1exit.fips:51820" || nodes[0].Name != "exit-01" {
		t.Fatalf("nodes: %v %+v", err, nodes)
	}
}

func TestWgPoolsArithmetic(t *testing.T) {
	p := DefaultWgPools
	if p.Gateway4().String() != "10.64.0.1" || p.Gateway6().String() != "fc10:f1b5:ea17::1" {
		t.Fatalf("gateways: %v %v", p.Gateway4(), p.Gateway6())
	}
	if a := offset4(p.Pool4, 300); a.String() != "10.64.1.44" {
		t.Fatalf("offset4(300) = %v", a)
	}
	if a := offset6(p.Pool6, 300); a.String() != "fc10:f1b5:ea17::12c" {
		t.Fatalf("offset6(300) = %v", a)
	}
	if p.slots() != (1<<16)-3 {
		t.Fatalf("slots = %d", p.slots())
	}
}

func TestValidWgKeyIsStrict(t *testing.T) {
	good := testKey(1)
	if !ValidWgKey(good) {
		t.Fatal("canonical key rejected")
	}
	for _, bad := range []string{
		"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQR=", // non-canonical padding bits: wg rejects it
		good + "\n", " " + good, good[:43], good + "=", "",
	} {
		if ValidWgKey(bad) {
			t.Fatalf("lenient key accepted: %q", bad)
		}
	}
	for _, ok := range []string{"[fd00::1]:51820", "npub1x.fips:51820", "203.0.113.1:1"} {
		if !validWgEndpoint(ok) {
			t.Fatalf("valid endpoint rejected: %q", ok)
		}
	}
	for _, bad := range []string{"", "fd00::1", "x.fips", "x.fips:0", "x.fips:70000", "x.fips:51820\nAllowedIPs = ::/0", "x fips:51820"} {
		if validWgEndpoint(bad) {
			t.Fatalf("bad endpoint accepted: %q", bad)
		}
	}
}

func TestWgNodesAgeOutAndClear(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, _, _ := st.EnrollNode(ctx, tok, "pk", "exit-01")
	if err := st.SetNodeWg(ctx, nodeID, testKey(9), "x.fips:51820\nDNS = 1.2.3.4"); err != ErrWgBadEndpoint {
		t.Fatalf("injected endpoint accepted: %v", err)
	}
	if err := st.SetNodeWg(ctx, nodeID, testKey(9), "[fd00::1]:51820"); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := st.WgNodes(ctx); len(nodes) != 1 {
		t.Fatal("fresh node not listed")
	}
	if _, err := st.pool.Exec(ctx, `UPDATE exit_nodes SET wg_seen_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := st.WgNodes(ctx); len(nodes) != 0 {
		t.Fatal("stale node still listed")
	}
	if err := st.SetNodeWg(ctx, nodeID, testKey(9), "[fd00::1]:51820"); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearNodeWg(ctx, nodeID); err != nil {
		t.Fatal(err)
	}
	if nodes, _ := st.WgNodes(ctx); len(nodes) != 0 {
		t.Fatal("cleared node still listed")
	}
}
