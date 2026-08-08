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
