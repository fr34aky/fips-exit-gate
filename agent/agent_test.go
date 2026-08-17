package main

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeFirewall is an in-memory Firewall for tests.
type fakeFirewall struct {
	mu         sync.Mutex
	authorized map[netip.Addr]struct{}
	acct       map[acctKey]uint64
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
	for _, a := range add {
		f.authorized[a] = struct{}{}
	}
	for _, a := range del {
		delete(f.authorized, a)
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
func (b *fakeBackend) getAuthz(context.Context, int64, int) (authzResponse, error) {
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
}

func (b *recordingBackend) setAuth(string, string) {}
func (b *recordingBackend) enroll(context.Context, enrollRequest) (enrollResponse, error) {
	return enrollResponse{NodeID: "node-test", AuthToken: "tok"}, nil
}
func (b *recordingBackend) getAuthz(ctx context.Context, rev int64, _ int) (authzResponse, error) {
	if rev == 0 {
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
func (b *recordingBackend) heartbeat(context.Context, heartbeatRequest) (heartbeatResponse, error) {
	b.mu.Lock()
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
