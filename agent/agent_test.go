package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/authzhash"
)

// fakeFirewall is an in-memory Firewall for tests. Like real nft it rejects a
// whole batch that deletes a member which isn't there, so the agent's
// "filter deletes against the live set" logic is exercised, not bypassed.
type fakeFirewall struct {
	mu         sync.Mutex
	authorized map[netip.Addr]struct{}
	acct       map[acctKey]uint64
	applies    int // ApplyAuthorized calls that changed something
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{authorized: map[netip.Addr]struct{}{}, acct: map[acctKey]uint64{}}
}

func (f *fakeFirewall) ListAuthorized() (map[netip.Addr]struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[netip.Addr]struct{}, len(f.authorized))
	for a := range f.authorized {
		cp[a] = struct{}{}
	}
	return cp, nil
}

func (f *fakeFirewall) ApplyAuthorized(add, del []netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range del {
		if _, ok := f.authorized[a]; !ok {
			return fmt.Errorf("nft: delete element authorized { %s }: No such file or directory", a)
		}
	}
	for _, a := range add {
		f.authorized[a] = struct{}{}
	}
	for _, a := range del {
		delete(f.authorized, a)
	}
	if len(add)+len(del) > 0 {
		f.applies++
	}
	return nil
}

func (f *fakeFirewall) ReadAcct() (map[acctKey]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[acctKey]uint64, len(f.acct))
	for k, v := range f.acct {
		cp[k] = v
	}
	return cp, nil
}

func (f *fakeFirewall) DeleteAcct(keys []acctKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range keys {
		if _, ok := f.acct[k]; !ok {
			return fmt.Errorf("nft: delete element acct { %s . %d }: No such file or directory", k.Addr, k.Port)
		}
	}
	for _, k := range keys {
		delete(f.acct, k)
	}
	return nil
}

func (f *fakeFirewall) has(a netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.authorized[a]
	return ok
}

// fakeBackend records usage and returns programmable authz/acks.
type fakeBackend struct {
	mu         sync.Mutex
	authz      authzResponse
	ack        usageAck
	gotReports []usageReport
}

func (b *fakeBackend) setAuth(string, string) {}
func (b *fakeBackend) enroll(context.Context, enrollRequest) (enrollResponse, error) {
	return enrollResponse{NodeID: "node-test", AuthToken: "tok"}, nil
}
func (b *fakeBackend) getAuthz(context.Context, int64, int, bool) (authzResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.authz, nil
}
func (b *fakeBackend) postUsage(_ context.Context, r usageReport) (usageAck, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gotReports = append(b.gotReports, r)
	return b.ack, nil
}
func (b *fakeBackend) heartbeat(context.Context, heartbeatRequest) (heartbeatResponse, error) {
	return heartbeatResponse{}, nil
}

func mkAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func newTestAgent(t *testing.T, be backend, fw Firewall) *Agent {
	t.Helper()
	st, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent(st, be, fw, "test", "enroll", false, 100)
	a.services = map[uint16]string{1080: "clearnet", 1081: "tor"}
	return a
}

func TestComputeDelta(t *testing.T) {
	services := map[uint16]string{1080: "clearnet"}
	prev := map[string]uint64{"fd00::1|1080": 1000}
	cur := map[acctKey]uint64{
		{Addr: mkAddr("fd00::1"), Port: 1080}: 1500, // +500
		{Addr: mkAddr("fd00::2"), Port: 1080}: 200,  // new element, +200
		{Addr: mkAddr("fd00::3"), Port: 9999}: 50,   // unknown port
	}
	samples, next := computeDelta(prev, cur, services)

	got := map[string]uint64{}
	for _, s := range samples {
		got[s.Service+"/"+s.Addr.String()] = s.Bytes
	}
	if got["clearnet/fd00::1"] != 500 || got["clearnet/fd00::2"] != 200 {
		t.Fatalf("unexpected samples: %+v", got)
	}
	if got["unknown:9999/fd00::3"] != 50 {
		t.Fatalf("unknown-port sample missing: %+v", got)
	}
	if next["fd00::1|1080"] != 1500 {
		t.Fatalf("baseline not advanced: %+v", next)
	}
}

func TestComputeDeltaCounterReset(t *testing.T) {
	services := map[uint16]string{1080: "clearnet"}
	prev := map[string]uint64{"fd00::1|1080": 5000}
	// Current below baseline => kernel counter was reset; whole value is the delta.
	cur := map[acctKey]uint64{{Addr: mkAddr("fd00::1"), Port: 1080}: 300}
	samples, next := computeDelta(prev, cur, services)
	if len(samples) != 1 || samples[0].Bytes != 300 {
		t.Fatalf("reset not handled: %+v", samples)
	}
	if next["fd00::1|1080"] != 300 {
		t.Fatalf("baseline should track current after reset: %+v", next)
	}
}

func TestApplyAuthzFullAndDelta(t *testing.T) {
	fw := newFakeFirewall()
	be := &fakeBackend{}
	a := newTestAgent(t, be, fw)

	// Full set: grants two addresses.
	err := a.applyAuthz(authzResponse{
		Rev:  10,
		Full: true,
		Addresses: []authzMember{
			{Addr: mkAddr("fd00::1"), Account: "a1"},
			{Addr: mkAddr("fd00::2"), Account: "a2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.has(mkAddr("fd00::1")) || !fw.has(mkAddr("fd00::2")) {
		t.Fatal("full apply did not grant both")
	}
	if a.store.snapshotRuntime().AuthzRev != 10 {
		t.Fatal("rev not persisted")
	}

	// Delta: add ::3, remove ::1.
	err = a.applyAuthz(authzResponse{
		Rev: 11,
		Add: []authzMember{{Addr: mkAddr("fd00::3"), Account: "a3"}},
		Del: []netip.Addr{mkAddr("fd00::1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.has(mkAddr("fd00::1")) {
		t.Fatal("delta did not revoke ::1")
	}
	if !fw.has(mkAddr("fd00::3")) {
		t.Fatal("delta did not grant ::3")
	}
}

func TestUsageFlowWithInlineRevocation(t *testing.T) {
	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1"), mkAddr("fd00::2")}, nil)
	fw.acct[acctKey{Addr: mkAddr("fd00::1"), Port: 1080}] = 10_000
	fw.acct[acctKey{Addr: mkAddr("fd00::2"), Port: 1081}] = 2_000

	be := &fakeBackend{ack: usageAck{Ack: "x", Revoke: []netip.Addr{mkAddr("fd00::1")}}}
	a := newTestAgent(t, be, fw)

	if err := a.collectAndBuffer(); err != nil {
		t.Fatal(err)
	}
	a.flushBuffer(context.Background())

	be.mu.Lock()
	defer be.mu.Unlock()
	if len(be.gotReports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(be.gotReports))
	}
	// Two samples with correct service labels.
	svc := map[string]uint64{}
	for _, s := range be.gotReports[0].Samples {
		svc[s.Service] = s.Bytes
	}
	if svc["clearnet"] != 10_000 || svc["tor"] != 2_000 {
		t.Fatalf("bad samples: %+v", svc)
	}
	// Inline revocation applied immediately.
	if fw.has(mkAddr("fd00::1")) {
		t.Fatal("inline revoke not applied to firewall")
	}
	if !fw.has(mkAddr("fd00::2")) {
		t.Fatal("non-revoked address wrongly removed")
	}
	// Its acct element GC'd.
	if _, ok := fw.acct[acctKey{Addr: mkAddr("fd00::1"), Port: 1080}]; ok {
		t.Fatal("revoked acct element not GC'd")
	}
	// Buffer drained after ack.
	if len(a.store.snapshotRuntime().BufferedUsage) != 0 {
		t.Fatal("buffer not drained after ack")
	}
}

func TestGraceFailClosed(t *testing.T) {
	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1")}, nil)
	be := &fakeBackend{}
	a := newTestAgent(t, be, fw)
	a.failClosedAfterGrace = true
	a.cfg.GraceMinutes = 60

	// Freeze a clock we control.
	base := time.Unix(1_700_000_000, 0)
	a.nowFn = func() time.Time { return base }
	a.lastAuthzOK = base

	// Within grace: set retained.
	a.nowFn = func() time.Time { return base.Add(30 * time.Minute) }
	a.graceCheck()
	if !fw.has(mkAddr("fd00::1")) {
		t.Fatal("flushed within grace window")
	}

	// Past grace: fail closed.
	a.nowFn = func() time.Time { return base.Add(2 * time.Hour) }
	a.graceCheck()
	if fw.has(mkAddr("fd00::1")) {
		t.Fatal("did not fail closed past grace")
	}
}

func TestBufferPersistsAcrossDeliveryFailure(t *testing.T) {
	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1")}, nil)
	fw.acct[acctKey{Addr: mkAddr("fd00::1"), Port: 1080}] = 500

	// Backend that errors on delivery.
	be := &erroringBackend{}
	a := newTestAgent(t, be, fw)

	if err := a.collectAndBuffer(); err != nil {
		t.Fatal(err)
	}
	a.flushBuffer(context.Background()) // delivery fails; report stays buffered
	if n := len(a.store.snapshotRuntime().BufferedUsage); n != 1 {
		t.Fatalf("expected report buffered after failure, got %d", n)
	}
	// Baseline still advanced (no double count on retry).
	if a.store.snapshotRuntime().Baselines["fd00::1|1080"] != 500 {
		t.Fatal("baseline should advance even when delivery fails")
	}
}

type erroringBackend struct{ fakeBackend }

func (b *erroringBackend) postUsage(context.Context, usageReport) (usageAck, error) {
	return usageAck{}, context.DeadlineExceeded
}

// recordingBackend simulates a backend fixed at one revision with a known full
// set: a rev=0 (full) request returns the set immediately, any other rev holds
// briefly then reports "unchanged" — emulating the long-poll so the sync loop
// paces itself instead of hot-spinning.
type recordingBackend struct {
	mu       sync.Mutex
	full     authzResponse
	hbResync bool
	hbCalled chan struct{}
	lastHB   heartbeatRequest
}

func (b *recordingBackend) setAuth(string, string) {}
func (b *recordingBackend) enroll(context.Context, enrollRequest) (enrollResponse, error) {
	return enrollResponse{NodeID: "node-test", AuthToken: "tok"}, nil
}
func (b *recordingBackend) getAuthz(ctx context.Context, rev int64, _ int, full bool) (authzResponse, error) {
	if rev == 0 || full {
		b.mu.Lock()
		full := b.full
		b.mu.Unlock()
		return full, nil
	}
	select {
	case <-ctx.Done():
		return authzResponse{}, ctx.Err()
	case <-time.After(2 * time.Millisecond):
	}
	return authzResponse{}, errUnchanged
}
func (b *recordingBackend) postUsage(context.Context, usageReport) (usageAck, error) {
	return usageAck{}, nil
}
func (b *recordingBackend) heartbeat(_ context.Context, req heartbeatRequest) (heartbeatResponse, error) {
	b.mu.Lock()
	b.lastHB = req
	resync, ch := b.hbResync, b.hbCalled
	b.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return heartbeatResponse{Resync: resync}, nil
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", d, what)
}

// A kernel flush that leaves the backend revision unchanged (an `up.sh reload`,
// a manual `nft flush`) must self-heal: the revision cursor can't see it, so the
// agent's periodic full reconcile has to notice and repair the drift.
func TestPeriodicFullReconcileRepairsDrift(t *testing.T) {
	fw := newFakeFirewall()
	be := &recordingBackend{full: authzResponse{Rev: 5, Full: true,
		Addresses: []authzMember{{Addr: mkAddr("fd00::1"), Account: "a1"}}}}
	a := newTestAgent(t, be, fw)
	a.fullSyncEvery = 10 * time.Minute

	var clk sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	a.nowFn = func() time.Time { clk.Lock(); defer clk.Unlock(); return now }
	advance := func(d time.Duration) { clk.Lock(); now = now.Add(d); clk.Unlock() }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.ensureEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	go a.runSync(ctx)

	// Startup reconcile grants the address.
	waitFor(t, time.Second, "startup grant", func() bool { return fw.has(mkAddr("fd00::1")) })

	// Out-of-band flush; backend rev stays 5, so the delta poll returns nothing.
	_ = fw.ApplyAuthorized(nil, []netip.Addr{mkAddr("fd00::1")})
	if fw.has(mkAddr("fd00::1")) {
		t.Fatal("flush did not clear the set")
	}

	// Past fullSyncEvery the agent must force a full pull and repair the drift.
	advance(11 * time.Minute)
	waitFor(t, time.Second, "periodic repair", func() bool { return fw.has(mkAddr("fd00::1")) })
}

// A backend-signalled resync (heartbeat spotted a size mismatch) forces a full
// reconcile even before the periodic timer would fire.
func TestResyncRequestForcesFullReconcile(t *testing.T) {
	fw := newFakeFirewall()
	be := &recordingBackend{full: authzResponse{Rev: 7, Full: true,
		Addresses: []authzMember{{Addr: mkAddr("fd00::9"), Account: "a9"}}}}
	a := newTestAgent(t, be, fw)
	a.fullSyncEvery = time.Hour // ensure only the resync path can repair during the test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.ensureEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	go a.runSync(ctx)

	waitFor(t, time.Second, "startup grant", func() bool { return fw.has(mkAddr("fd00::9")) })
	_ = fw.ApplyAuthorized(nil, []netip.Addr{mkAddr("fd00::9")})

	a.requestResync()
	waitFor(t, time.Second, "resync repair", func() bool { return fw.has(mkAddr("fd00::9")) })
}

// The heartbeat loop must turn a backend Resync response into a pending resync
// request that runSync will pick up.
func TestHeartbeatResyncSetsFlag(t *testing.T) {
	fw := newFakeFirewall()
	called := make(chan struct{}, 1)
	be := &recordingBackend{hbResync: true, hbCalled: called}
	a := newTestAgent(t, be, fw)

	ctx, cancel := context.WithCancel(context.Background())
	go a.runHeartbeat(ctx)
	select {
	case <-called:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("heartbeat was not called")
	}
	cancel()
	waitFor(t, time.Second, "resync flag set", func() bool { return a.takeResync() })
}

// --- control-plane consistency (PR: fix/control-plane-consistency) ----------

// An inline revoke (usage ack) removes an address, then the same address
// arrives as a `del` in the next authz delta. nft fails the whole batch on a
// missing member, so without filtering the adds in that delta would be blocked
// and the cursor stuck until the next full reconcile.
func TestDeltaDeleteOfAlreadyRevokedAddressStillAppliesAdds(t *testing.T) {
	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1"), mkAddr("fd00::2")}, nil)
	fw.acct[acctKey{Addr: mkAddr("fd00::1"), Port: 1080}] = 10 // only on one of two services
	a := newTestAgent(t, &fakeBackend{}, fw)

	a.applyRevocations([]netip.Addr{mkAddr("fd00::1")})
	if fw.has(mkAddr("fd00::1")) {
		t.Fatal("inline revoke not applied")
	}
	if _, ok := fw.acct[acctKey{Addr: mkAddr("fd00::1"), Port: 1080}]; ok {
		t.Fatal("acct element not GC'd although the other service's element was absent")
	}

	err := a.applyAuthz(authzResponse{
		Rev: 12,
		Add: []authzMember{{Addr: mkAddr("fd00::3"), Account: "a3"}},
		Del: []netip.Addr{mkAddr("fd00::1")}, // already gone
	})
	if err != nil {
		t.Fatalf("delta with an already-absent del must not fail: %v", err)
	}
	if !fw.has(mkAddr("fd00::3")) {
		t.Fatal("add in the same delta was not applied")
	}
	if a.store.snapshotRuntime().AuthzRev != 12 {
		t.Fatal("cursor did not advance")
	}
	// Revoking something already absent is a no-op, not an error.
	a.applyRevocations([]netip.Addr{mkAddr("fd00::1")})
	if !fw.has(mkAddr("fd00::2")) || !fw.has(mkAddr("fd00::3")) {
		t.Fatal("unrelated members disturbed")
	}
}

func manyAddrs(n int) []authzMember {
	out := make([]authzMember, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, authzMember{Addr: mkAddr(fmt.Sprintf("fd00::%x", i)), Account: "acct"})
	}
	return out
}

// A full set that would wipe most of a large live set is refused unless the
// backend forces it or the operator opted in; nothing is applied and the
// cursor stays put. Small sets and ordinary churn are never guarded.
func TestMassRevokeGuard(t *testing.T) {
	seed := func(n int) (*fakeFirewall, *Agent) {
		fw := newFakeFirewall()
		for _, m := range manyAddrs(n) {
			_ = fw.ApplyAuthorized([]netip.Addr{m.Addr}, nil)
		}
		a := newTestAgent(t, &fakeBackend{}, fw)
		_ = a.store.withRuntime(func(rt *runtime) { rt.AuthzRev = 40 })
		return fw, a
	}

	// 200 live, full set of 10 -> 190 deletions: refused.
	fw, a := seed(200)
	err := a.applyAuthz(authzResponse{Rev: 41, Full: true, Addresses: manyAddrs(10)})
	var mass *massRevokeError
	if !errors.As(err, &mass) {
		t.Fatalf("expected massRevokeError, got %v", err)
	}
	if n, _ := fw.ListAuthorized(); len(n) != 200 {
		t.Fatalf("guard applied something: %d live", len(n))
	}
	if a.store.snapshotRuntime().AuthzRev != 40 {
		t.Fatal("cursor moved despite refusal")
	}

	// Same response with force=true: applied.
	if err := a.applyAuthz(authzResponse{Rev: 41, Full: true, Force: true, Addresses: manyAddrs(10)}); err != nil {
		t.Fatalf("forced full set refused: %v", err)
	}
	if n, _ := fw.ListAuthorized(); len(n) != 10 {
		t.Fatalf("forced full set not applied: %d live", len(n))
	}

	// Operator override.
	fw, a = seed(200)
	a.allowMassRevoke = true
	if err := a.applyAuthz(authzResponse{Rev: 41, Full: true, Addresses: manyAddrs(10)}); err != nil {
		t.Fatalf("override not honoured: %v", err)
	}

	// Below the absolute floor (massRevokeMin=50): 40 live -> 0 is allowed.
	fw, a = seed(40)
	if err := a.applyAuthz(authzResponse{Rev: 41, Full: true}); err != nil {
		t.Fatalf("small set wrongly guarded: %v", err)
	}
	if n, _ := fw.ListAuthorized(); len(n) != 0 {
		t.Fatal("small full set not applied")
	}

	// Large set, but less than half removed: allowed.
	fw, a = seed(200)
	if err := a.applyAuthz(authzResponse{Rev: 41, Full: true, Addresses: manyAddrs(120)}); err != nil {
		t.Fatalf("40%% churn wrongly guarded: %v", err)
	}
	if n, _ := fw.ListAuthorized(); len(n) != 120 {
		t.Fatalf("expected 120 live, got %d", len(n))
	}
}

// deltaBackend answers rev=0/full with a configurable full set and any other
// cursor with one delta, so runSync's fallback from a refused full reconcile
// to the delta log can be observed.
type deltaBackend struct {
	recordingBackend
	delta     authzResponse
	fullCalls chan int64
}

func (b *deltaBackend) getAuthz(ctx context.Context, rev int64, _ int, full bool) (authzResponse, error) {
	if rev == 0 || full {
		select {
		case b.fullCalls <- rev:
		default:
		}
		return b.full, nil
	}
	b.mu.Lock()
	d := b.delta
	b.delta = authzResponse{}
	b.mu.Unlock()
	if d.Rev != 0 {
		return d, nil
	}
	select {
	case <-ctx.Done():
		return authzResponse{}, ctx.Err()
	case <-time.After(2 * time.Millisecond):
	}
	return authzResponse{}, errUnchanged
}

// When the startup full reconcile is refused by the guard, an agent that has a
// cursor must fall through to delta syncing (which carries genuine revocations)
// instead of looping on the refused full set and never applying anything.
func TestRefusedFullReconcileFallsBackToDeltas(t *testing.T) {
	fw := newFakeFirewall()
	for _, m := range manyAddrs(200) {
		_ = fw.ApplyAuthorized([]netip.Addr{m.Addr}, nil)
	}
	be := &deltaBackend{
		fullCalls: make(chan int64, 8),
		delta: authzResponse{Rev: 51,
			Add: []authzMember{{Addr: mkAddr("fd00::ffff"), Account: "new"}},
			Del: []netip.Addr{mkAddr("fd00::1")}},
	}
	be.full = authzResponse{Rev: 51, Full: true} // empty: would revoke all 200
	a := newTestAgent(t, be, fw)
	a.fullSyncEvery = time.Hour
	_ = a.store.withRuntime(func(rt *runtime) { rt.AuthzRev = 50 })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.ensureEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	go a.runSync(ctx)

	select {
	case <-be.fullCalls:
	case <-time.After(time.Second):
		t.Fatal("startup full reconcile never requested")
	}
	waitFor(t, time.Second, "delta applied after refused full", func() bool {
		return fw.has(mkAddr("fd00::ffff")) && !fw.has(mkAddr("fd00::1"))
	})
	if n, _ := fw.ListAuthorized(); len(n) != 200 { // -1 +1
		t.Fatalf("expected 200 live after delta, got %d (full set must not have been applied)", len(n))
	}
	if a.store.snapshotRuntime().AuthzRev != 51 {
		t.Fatalf("cursor = %d, want 51", a.store.snapshotRuntime().AuthzRev)
	}
}

// A corrupt runtime.json must not keep the agent down: it is moved aside, the
// agent starts from a clean cursor, and the first collection primes baselines
// instead of re-billing counters that were already reported.
func TestCorruptRuntimeStateRecovers(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), []byte("{\"authz_rev\": 9, \"basel"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := openStore(dir)
	if err != nil {
		t.Fatalf("openStore should recover from a corrupt runtime file: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	backedUp := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "runtime.json.corrupt-") {
			backedUp = true
		}
	}
	if !backedUp {
		t.Fatal("corrupt file was not kept for forensics")
	}
	rt := st.snapshotRuntime()
	if rt.AuthzRev != 0 || !rt.PrimeBaselines {
		t.Fatalf("expected clean state with PrimeBaselines, got %+v", rt)
	}

	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1")}, nil)
	fw.acct[acctKey{Addr: mkAddr("fd00::1"), Port: 1080}] = 123_456 // already billed before the crash
	be := &fakeBackend{}
	a := newAgent(st, be, fw, "test", "enroll", false, 100)
	a.services = map[uint16]string{1080: "clearnet"}

	if err := a.collectAndBuffer(); err != nil {
		t.Fatal(err)
	}
	if n := len(a.store.snapshotRuntime().BufferedUsage); n != 0 {
		t.Fatalf("priming window must not produce a report, got %d", n)
	}
	if a.store.snapshotRuntime().Baselines["fd00::1|1080"] != 123_456 {
		t.Fatal("baseline not primed from the live counter")
	}
	fw.acct[acctKey{Addr: mkAddr("fd00::1"), Port: 1080}] = 123_556
	if err := a.collectAndBuffer(); err != nil {
		t.Fatal(err)
	}
	rep := a.store.snapshotRuntime().BufferedUsage
	if len(rep) != 1 || len(rep[0].Samples) != 1 || rep[0].Samples[0].Bytes != 100 {
		t.Fatalf("expected one 100-byte sample after priming, got %+v", rep)
	}
}

// The grace clock survives a restart: lastAuthzOK is persisted on every
// successful sync and used to seed the next process, so an agent that keeps
// restarting during an outage still fails closed when the window has passed.
func TestLastAuthzOKPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	a := newAgent(st, &fakeBackend{}, newFakeFirewall(), "test", "enroll", true, 100)
	a.nowFn = func() time.Time { return base }
	a.markAuthzOK()

	// "Restart": new store + agent over the same directory, clock 5 h later.
	st2, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1")}, nil)
	b := newAgent(st2, &fakeBackend{}, fw, "test", "enroll", true, 100)
	b.cfg.GraceMinutes = 240
	restart := base.Add(5 * time.Hour)
	b.nowFn = func() time.Time { return restart }
	b.initLastAuthzOK()
	if got := b.lastAuthzOK; !got.Equal(base) {
		t.Fatalf("lastAuthzOK after restart = %v, want persisted %v", got, base)
	}
	// Right after start a stale persisted clock alone must NOT flush: the agent
	// (or the whole host) may simply have been down for maintenance.
	b.graceCheck()
	if !fw.has(mkAddr("fd00::1")) {
		t.Fatal("flushed on the first failure after a restart (planned downtime treated as outage)")
	}
	// Once this process has itself seen the backend fail for the startup
	// grace, the persisted clock counts and it fails closed.
	b.nowFn = func() time.Time { return restart.Add(b.startupGrace() + time.Second) }
	b.graceCheck()
	if fw.has(mkAddr("fd00::1")) {
		t.Fatal("did not fail closed although the persisted grace window had passed and the startup grace elapsed")
	}
}

// A delta whose revision is below the persisted cursor means the backend's
// timeline was reset; it must not be applied or move the cursor.
func TestDeltaBelowCursorIsRejected(t *testing.T) {
	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1")}, nil)
	a := newTestAgent(t, &fakeBackend{}, fw)
	_ = a.store.withRuntime(func(rt *runtime) { rt.AuthzRev = 500 })
	err := a.applyAuthz(authzResponse{Rev: 3, Add: []authzMember{{Addr: mkAddr("fd00::2"), Account: "x"}}, Del: []netip.Addr{mkAddr("fd00::1")}})
	var regress *revRegressionError
	if !errors.As(err, &regress) {
		t.Fatalf("expected revRegressionError, got %v", err)
	}
	if !fw.has(mkAddr("fd00::1")) || fw.has(mkAddr("fd00::2")) {
		t.Fatal("regressed delta was applied")
	}
	if a.store.authzRev() != 500 {
		t.Fatal("cursor moved backwards")
	}
}

// countingBackend answers every authz request with the same full set and
// counts how many times it was asked, to prove a disabled periodic full sync
// does not turn the loop into a firehose.
type countingBackend struct {
	recordingBackend
	calls atomic.Int32
}

func (b *countingBackend) getAuthz(ctx context.Context, rev int64, w int, full bool) (authzResponse, error) {
	b.calls.Add(1)
	return b.recordingBackend.getAuthz(ctx, rev, w, full)
}

func TestFullSyncIntervalZeroDisablesPeriodicFullPulls(t *testing.T) {
	fw := newFakeFirewall()
	be := &countingBackend{recordingBackend: recordingBackend{full: authzResponse{Rev: 5, Full: true,
		Addresses: []authzMember{{Addr: mkAddr("fd00::1"), Account: "a1"}}}}}
	a := newTestAgent(t, be, fw)
	a.fullSyncEvery = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.ensureEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	go a.runSync(ctx)
	waitFor(t, time.Second, "startup grant", func() bool { return fw.has(mkAddr("fd00::1")) })
	time.Sleep(300 * time.Millisecond)
	// One startup full pull, then paced delta long-polls (2 ms each in the
	// fake) — never a burst of immediate full pulls.
	if n := be.calls.Load(); n > 200 {
		t.Fatalf("sync loop made %d requests in 300 ms with fullSyncEvery=0 (firehose)", n)
	}
}

// The clean state substituted for a corrupt runtime.json is persisted at once,
// so a crash before the first collection can't lose the prime flag.
func TestRecoveredRuntimeStateIsPersisted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(dir); err != nil {
		t.Fatal(err)
	}
	st2, err := openStore(dir) // "crash" and restart without any collection in between
	if err != nil {
		t.Fatal(err)
	}
	if !st2.snapshotRuntime().PrimeBaselines {
		t.Fatal("PrimeBaselines lost across a restart right after recovery")
	}
}

// The heartbeat carries a member-by-member fingerprint of the kernel set, and
// reports "unknown" (-1, no hash) rather than an empty set when it can't read.
func TestHeartbeatReportsSetHash(t *testing.T) {
	fw := newFakeFirewall()
	_ = fw.ApplyAuthorized([]netip.Addr{mkAddr("fd00::1"), mkAddr("fd00::2")}, nil)
	called := make(chan struct{}, 1)
	be := &recordingBackend{hbCalled: called}
	a := newTestAgent(t, be, fw)
	a.heartbeatEvery = time.Hour

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
	if hb.SetSize != 2 {
		t.Fatalf("set_size = %d, want 2", hb.SetSize)
	}
	if want := authzhash.Of([]netip.Addr{mkAddr("fd00::2"), mkAddr("fd00::1")}); hb.SetHash != want {
		t.Fatalf("set_hash = %q, want %q", hb.SetHash, want)
	}
}

type brokenListFirewall struct{ fakeFirewall }

func (f *brokenListFirewall) ListAuthorized() (map[netip.Addr]struct{}, error) {
	return nil, errors.New("nft: table missing")
}

func TestHeartbeatReportsUnknownWhenSetUnreadable(t *testing.T) {
	called := make(chan struct{}, 1)
	be := &recordingBackend{hbCalled: called}
	fw := &brokenListFirewall{*newFakeFirewall()}
	a := newTestAgent(t, be, fw)
	a.heartbeatEvery = time.Hour
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
	if hb.SetSize != -1 || hb.SetHash != "" {
		t.Fatalf("unreadable set must report size -1 and no hash, got %+v", hb)
	}
}

func TestBackoffDoublesWithJitterAndCaps(t *testing.T) {
	b := newBackoff()
	want := time.Second
	for i := 0; i < 10; i++ {
		got := b.next()
		lo, hi := time.Duration(float64(want)*0.8), time.Duration(float64(want)*1.2)
		if got < lo || got > hi {
			t.Fatalf("step %d: %v outside [%v, %v]", i, got, lo, hi)
		}
		if want < backoffMax {
			want *= 2
		}
		if want > backoffMax {
			want = backoffMax
		}
	}
	b.reset()
	if got := b.next(); got > 1200*time.Millisecond {
		t.Fatalf("reset did not restart from 1s: %v", got)
	}
}
