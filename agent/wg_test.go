package main

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const sampleDump = "cHJpdg==\tcHVi\t51820\toff\n" +
	"AAAA\t(none)\t[fd00::5]:40000\t10.64.0.5/32,fc10:f1b5:ea17::5/128\t1700000000\t100\t200\t25\n" +
	"BBBB\t(none)\t(none)\t10.64.0.9/32\t0\t0\t0\toff\n" +
	"CCCC\t(none)\t(none)\t(none)\t0\t0\t0\toff\n"

func TestParseWgDump(t *testing.T) {
	peers := parseWgDump(sampleDump)
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d: %+v", len(peers), peers)
	}
	if got := strings.Join(peers["AAAA"].AllowedIPs, ","); got != "10.64.0.5/32,fc10:f1b5:ea17::5/128" {
		t.Fatalf("AAAA allowed-ips = %q", got)
	}
	if len(peers["CCCC"].AllowedIPs) != 0 {
		t.Fatalf("(none) allowed-ips should parse as empty, got %v", peers["CCCC"].AllowedIPs)
	}
}

func TestDiffPeers(t *testing.T) {
	current := parseWgDump(sampleDump)
	desired := desiredPeers(wgPeersResponse{Peers: []wgPeerInfo{
		{Pubkey: "AAAA", IP4: "10.64.0.5/32", IP6: "fc10:f1b5:ea17::5/128"}, // unchanged
		{Pubkey: "BBBB", IP4: "10.64.0.9/32", IP6: "fc10:f1b5:ea17::9/128"}, // allowed-ips changed
		{Pubkey: "DDDD", IP4: "10.64.0.7/32", IP6: "fc10:f1b5:ea17::7/128"}, // new
	}})
	add, del := diffPeers(current, desired)
	var addKeys []string
	for _, p := range add {
		addKeys = append(addKeys, p.Pubkey)
	}
	sort.Strings(addKeys)
	if strings.Join(addKeys, ",") != "BBBB,DDDD" {
		t.Fatalf("add = %v", addKeys)
	}
	if strings.Join(del, ",") != "CCCC" {
		t.Fatalf("del = %v", del)
	}
}

// fakeWg is an in-memory WireGuard interface.
type fakeWg struct {
	mu    sync.Mutex
	peers map[string]wgPeer
	sets  int
}

func newFakeWg() *fakeWg                     { return &fakeWg{peers: map[string]wgPeer{}} }
func (f *fakeWg) PublicKey() (string, error) { return "NODEPUB=", nil }
func (f *fakeWg) ListPeers() (map[string]wgPeer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]wgPeer, len(f.peers))
	for k, v := range f.peers {
		cp[k] = v
	}
	return cp, nil
}
func (f *fakeWg) SetPeers(add []wgPeer, del []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range del {
		if _, ok := f.peers[k]; !ok {
			return errors.New("wg: peer not found")
		}
		delete(f.peers, k)
	}
	for _, p := range add {
		f.peers[p.Pubkey] = p
	}
	if len(add)+len(del) > 0 {
		f.sets++
	}
	return nil
}
func (f *fakeWg) has(k string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.peers[k]
	return ok
}

// wgBackend serves a programmable peer table with etag semantics.
type wgBackend struct {
	recordingBackend
	table wgPeersResponse
}

func (b *wgBackend) getWgPeers(_ context.Context, etag string) (wgPeersResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if etag != "" && etag == b.table.Etag {
		return wgPeersResponse{}, errUnchanged
	}
	return b.table, nil
}

func TestWgSyncAppliesTableAndRepairsDrift(t *testing.T) {
	be := &wgBackend{table: wgPeersResponse{Etag: "e1", Peers: []wgPeerInfo{
		{Pubkey: "AAAA", IP4: "10.64.0.5/32", IP6: "fc10::5/128"},
	}}}
	fw := newFakeFirewall()
	a := newTestAgent(t, be, fw)
	wgi := newFakeWg()
	_ = wgi.SetPeers([]wgPeer{{Pubkey: "STALE", AllowedIPs: []string{"10.64.0.2/32"}}}, nil)
	a.wg = wgi
	a.wgSyncEvery = 5 * time.Millisecond
	a.fullSyncEvery = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.runWgSync(ctx)
	waitFor(t, time.Second, "peer added and stale removed", func() bool { return wgi.has("AAAA") && !wgi.has("STALE") })

	// Table changes: new etag -> applied.
	be.mu.Lock()
	be.table = wgPeersResponse{Etag: "e2", Peers: []wgPeerInfo{{Pubkey: "BBBB", IP4: "10.64.0.9/32", IP6: "fc10::9/128"}}}
	be.mu.Unlock()
	waitFor(t, time.Second, "table change applied", func() bool { return wgi.has("BBBB") && !wgi.has("AAAA") })

	// Out-of-band drift at an unchanged etag is repaired by the periodic full pass.
	_ = wgi.SetPeers(nil, []string{"BBBB"})
	waitFor(t, time.Second, "drift repaired", func() bool { return wgi.has("BBBB") })
}

func TestHeartbeatAnnouncesWireGuard(t *testing.T) {
	called := make(chan struct{}, 1)
	be := &recordingBackend{hbCalled: called}
	a := newTestAgent(t, be, newFakeFirewall())
	a.wg = newFakeWg()
	a.wgEndpoint = "npub1exit.fips:51820"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.runHeartbeat(ctx)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("heartbeat was not called")
	}
	be.mu.Lock()
	hb := be.lastHB
	be.mu.Unlock()
	if hb.WgPubkey != "NODEPUB=" || hb.WgEndpoint != "npub1exit.fips:51820" {
		t.Fatalf("heartbeat did not announce WireGuard: %+v", hb)
	}
}

// pickyWg rejects one specific key, as `wg` would reject a malformed one, and
// counts PublicKey calls.
type pickyWg struct {
	fakeWg
	reject  string
	pubReqs int
}

func (f *pickyWg) PublicKey() (string, error) {
	f.mu.Lock()
	f.pubReqs++
	f.mu.Unlock()
	return "NODEPUB=", nil
}

func (f *pickyWg) SetPeers(add []wgPeer, del []string) error {
	for _, p := range add {
		if p.Pubkey == f.reject {
			return errors.New("wg: Key is not the correct length or format")
		}
	}
	return f.fakeWg.SetPeers(add, del)
}

// One bad row must not block the other peers: the batch fails, the agent
// falls back to per-peer operations, skips the bad one and advances the etag.
func TestWgSyncSkipsPoisonedPeer(t *testing.T) {
	be := &wgBackend{table: wgPeersResponse{Etag: "e1", Peers: []wgPeerInfo{
		{Pubkey: "GOOD1", IP4: "10.64.0.5/32", IP6: "fc10::5/128"},
		{Pubkey: "BAD!!", IP4: "10.64.0.6/32", IP6: "fc10::6/128"},
		{Pubkey: "GOOD2", IP4: "10.64.0.7/32", IP6: "fc10::7/128"},
	}}}
	a := newTestAgent(t, be, newFakeFirewall())
	wgi := &pickyWg{fakeWg: *newFakeWg(), reject: "BAD!!"}
	a.wg = wgi
	if err := a.applyWgPeers(be.table); err != nil {
		t.Fatalf("apply with one poisoned row must succeed overall: %v", err)
	}
	if !wgi.has("GOOD1") || !wgi.has("GOOD2") || wgi.has("BAD!!") {
		t.Fatalf("good peers not applied / bad one applied: %+v", wgi.peers)
	}
	if a.wgEtag != "e1" {
		t.Fatal("etag not advanced after a partial apply")
	}
}

// The interface key is read once and cached across heartbeats.
func TestWgPublicKeyCached(t *testing.T) {
	a := newTestAgent(t, &recordingBackend{}, newFakeFirewall())
	wgi := &pickyWg{fakeWg: *newFakeWg()}
	a.wg = wgi
	for i := 0; i < 3; i++ {
		if pub, err := a.wgPublicKey(); err != nil || pub != "NODEPUB=" {
			t.Fatalf("pubkey: %q %v", pub, err)
		}
	}
	if wgi.pubReqs != 1 {
		t.Fatalf("PublicKey called %d times, want 1", wgi.pubReqs)
	}
}
