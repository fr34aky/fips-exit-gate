package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const agentVersion = "0.2.0-phase2"

// backend is the subset of the backend API the agent uses; *backendClient
// implements it, and tests substitute a fake.
type backend interface {
	setAuth(nodeID, token string)
	enroll(ctx context.Context, req enrollRequest) (enrollResponse, error)
	getAuthz(ctx context.Context, rev int64, wait int) (authzResponse, error)
	postUsage(ctx context.Context, report usageReport) (usageAck, error)
	heartbeat(ctx context.Context, req heartbeatRequest) (heartbeatResponse, error)
}

// Agent wires the store, backend client, and firewall together and runs the
// sync, usage, and heartbeat loops.
type Agent struct {
	store  *store
	client backend
	fw     Firewall

	nodeName    string
	enrollToken string

	mu                   sync.Mutex
	cfg                  agentConfig
	services             map[uint16]string // port -> service key
	failClosedAfterGrace bool
	bufferCap            int
	lastAuthzOK          time.Time
	nowFn                func() time.Time // injectable for tests
	metrics              *agentMetrics    // nil when metrics are disabled
}

func newAgent(st *store, cl backend, fw Firewall, name, enrollToken string, failClosed bool, bufferCap int) *Agent {
	return &Agent{
		store:                st,
		client:               cl,
		fw:                   fw,
		nodeName:             name,
		enrollToken:          enrollToken,
		cfg:                  agentConfig{UsageIntervalS: 30, GraceMinutes: 240},
		services:             map[uint16]string{},
		failClosedAfterGrace: failClosed,
		bufferCap:            bufferCap,
		nowFn:                time.Now,
	}
}

func (a *Agent) now() time.Time { return a.nowFn() }

// counterEpoch identifies a kernel-counter lifetime; it changes on reboot so
// the backend can tell resets apart. Per-element handling in computeDelta keeps
// deltas correct regardless.
func counterEpoch() string {
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		return "boot-" + strings.TrimSpace(string(b))
	}
	return "boot-unknown"
}

// ensureEnrolled enrolls the node on first run, persisting its identity.
func (a *Agent) ensureEnrolled(ctx context.Context) error {
	if a.store.enrolled() {
		id := a.store.identity()
		a.client.setAuth(id.NodeID, id.AuthToken)
		return nil
	}
	if a.enrollToken == "" {
		return errNoEnrollToken
	}
	pub, seed := a.store.newIdentity()
	resp, err := a.client.enroll(ctx, enrollRequest{
		EnrollToken: a.enrollToken,
		NodePubkey:  pub,
		Name:        a.nodeName,
	})
	if err != nil {
		return err
	}
	if err := a.store.saveIdentity(identity{
		NodeID: resp.NodeID, AuthToken: resp.AuthToken, PrivSeedB64: seed,
	}); err != nil {
		return err
	}
	a.client.setAuth(resp.NodeID, resp.AuthToken)
	log.Printf("agent: enrolled as node %s", resp.NodeID)
	return nil
}

var errNoEnrollToken = &agentError{"not enrolled and FIPS_AGENT_ENROLL_TOKEN is empty"}

type agentError struct{ msg string }

func (e *agentError) Error() string { return e.msg }

// Run starts all loops and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	a.lastAuthzOK = a.now()
	a.mu.Unlock()

	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){a.runSync, a.runUsage, a.runHeartbeat} {
		wg.Add(1)
		go func(f func(context.Context)) { defer wg.Done(); f(ctx) }(loop)
	}
	wg.Wait()
	return ctx.Err()
}

// --- authz sync -------------------------------------------------------------

func (a *Agent) runSync(ctx context.Context) {
	backoff := newBackoff()
	// Force a full reconcile on startup: the kernel set may have changed while we
	// were down — e.g. `up.sh reload` recreates the nftables table with an empty
	// authorized set. Our persisted revision would otherwise make the backend
	// answer "unchanged" and we'd never refill it. rev=0 pulls the full set, which
	// applyAuthz diffs against the live kernel set and repairs.
	forceFull := true
	for ctx.Err() == nil {
		rev := a.store.snapshotRuntime().AuthzRev
		if forceFull {
			rev = 0
		}
		resp, err := a.client.getAuthz(ctx, rev, 50)
		switch {
		case err == errUnchanged:
			a.markAuthzOK()
			backoff.reset()
		case err != nil:
			a.metrics.syncErr()
			a.graceCheck()
			sleep(ctx, backoff.next())
			continue
		default:
			if err := a.applyAuthz(resp); err != nil {
				a.metrics.nftErr()
				log.Printf("agent: apply authz: %v", err)
				sleep(ctx, backoff.next())
				continue
			}
			forceFull = false
			a.markAuthzOK()
			backoff.reset()
		}
	}
}

func (a *Agent) applyAuthz(resp authzResponse) error {
	var add, del []netip.Addr
	if resp.Full {
		current, err := a.fw.ListAuthorized()
		if err != nil {
			return err
		}
		desired := make(map[netip.Addr]struct{}, len(resp.Addresses))
		for _, m := range resp.Addresses {
			desired[m.Addr] = struct{}{}
		}
		add, del = diffAuthorized(current, desired)
	} else {
		for _, m := range resp.Add {
			add = append(add, m.Addr)
		}
		del = resp.Del
	}
	if err := a.fw.ApplyAuthorized(add, del); err != nil {
		return err
	}
	return a.store.withRuntime(func(rt *runtime) { rt.AuthzRev = resp.Rev })
}

func (a *Agent) markAuthzOK() {
	a.mu.Lock()
	a.lastAuthzOK = a.now()
	a.mu.Unlock()
	a.metrics.syncOK(a.store.snapshotRuntime().AuthzRev, a.now())
}

// graceCheck optionally fails closed (flushes the authorized set) once the
// backend has been unreachable longer than the grace window.
func (a *Agent) graceCheck() {
	a.metrics.outage()
	a.mu.Lock()
	grace := time.Duration(a.cfg.GraceMinutes) * time.Minute
	over := a.now().Sub(a.lastAuthzOK) > grace
	failClosed := a.failClosedAfterGrace
	a.mu.Unlock()
	if !over || !failClosed {
		return // fail-open: keep last-known set so paying users are unaffected
	}
	current, err := a.fw.ListAuthorized()
	if err != nil || len(current) == 0 {
		return
	}
	del := make([]netip.Addr, 0, len(current))
	for addr := range current {
		del = append(del, addr)
	}
	if err := a.fw.ApplyAuthorized(nil, del); err != nil {
		log.Printf("agent: grace fail-closed flush: %v", err)
		return
	}
	log.Printf("agent: backend unreachable > %s, failed closed (flushed %d addrs)", grace, len(del))
}

// --- usage ------------------------------------------------------------------

func (a *Agent) runUsage(ctx context.Context) {
	// Brief prime so the first heartbeat can populate the service map and
	// interval before the first collection; then collect-then-sleep so usage
	// is reported promptly on startup rather than after a full interval.
	if !sleep(ctx, 2*time.Second) {
		return
	}
	for ctx.Err() == nil {
		if err := a.collectAndBuffer(); err != nil {
			log.Printf("agent: collect usage: %v", err)
		}
		a.flushBuffer(ctx)
		a.metrics.setBuffered(len(a.store.snapshotRuntime().BufferedUsage))
		a.mu.Lock()
		interval := time.Duration(a.cfg.UsageIntervalS) * time.Second
		a.mu.Unlock()
		if !sleep(ctx, interval) {
			return
		}
	}
}

// collectAndBuffer reads counters, computes the delta since the last baseline,
// advances the baseline, and enqueues a report — all persisted atomically so a
// crash never double-counts or loses the delta.
func (a *Agent) collectAndBuffer() error {
	cur, err := a.fw.ReadAcct()
	if err != nil {
		return err
	}
	a.mu.Lock()
	services := a.services
	a.mu.Unlock()

	epoch := counterEpoch()
	return a.store.withRuntime(func(rt *runtime) {
		samples, next := computeDelta(rt.Baselines, cur, services)
		rt.Baselines = next
		rt.CounterEpoch = epoch
		if len(samples) == 0 {
			return
		}
		rt.BufferedUsage = append(rt.BufferedUsage, usageReport{
			ReportID:     randID(),
			CounterEpoch: epoch,
			WindowEnd:    a.now().UTC().Format(time.RFC3339),
			Samples:      samples,
		})
		if len(rt.BufferedUsage) > a.bufferCap {
			drop := len(rt.BufferedUsage) - a.bufferCap
			log.Printf("agent: usage buffer full, dropping %d oldest report(s)", drop)
			rt.BufferedUsage = rt.BufferedUsage[drop:]
			a.metrics.usageDrop(drop)
		}
	})
}

// flushBuffer delivers queued reports oldest-first, dropping each on ack and
// applying any inline revocations immediately (sub-interval cutoff).
func (a *Agent) flushBuffer(ctx context.Context) {
	for {
		snap := a.store.snapshotRuntime()
		if len(snap.BufferedUsage) == 0 {
			return
		}
		report := snap.BufferedUsage[0]
		ack, err := a.client.postUsage(ctx, report)
		if err != nil {
			return // keep buffered; retry next tick
		}
		a.metrics.usageSentInc()
		a.applyRevocations(ack.Revoke)
		if err := a.store.withRuntime(func(rt *runtime) {
			if len(rt.BufferedUsage) > 0 && rt.BufferedUsage[0].ReportID == report.ReportID {
				rt.BufferedUsage = rt.BufferedUsage[1:]
			}
		}); err != nil {
			log.Printf("agent: persist after ack: %v", err)
			return
		}
	}
}

func (a *Agent) applyRevocations(revoke []netip.Addr) {
	if len(revoke) == 0 {
		return
	}
	if err := a.fw.ApplyAuthorized(nil, revoke); err != nil {
		log.Printf("agent: revoke: %v", err)
		return
	}
	a.gcAcct(revoke)
	log.Printf("agent: revoked %d addr(s) on backend request", len(revoke))
}

// gcAcct removes accounting elements for revoked addresses across all services.
func (a *Agent) gcAcct(addrs []netip.Addr) {
	a.mu.Lock()
	services := a.services
	a.mu.Unlock()
	var keys []acctKey
	for _, addr := range addrs {
		for port := range services {
			keys = append(keys, acctKey{Addr: addr, Port: port})
		}
	}
	if err := a.fw.DeleteAcct(keys); err != nil {
		// Non-fatal: stale acct elements don't authorize anything.
		log.Printf("agent: gc acct (ignored): %v", err)
	}
}

// --- heartbeat --------------------------------------------------------------

func (a *Agent) runHeartbeat(ctx context.Context) {
	for ctx.Err() == nil {
		set, _ := a.fw.ListAuthorized()
		a.metrics.setAuthorized(len(set))
		snap := a.store.snapshotRuntime()
		resp, err := a.client.heartbeat(ctx, heartbeatRequest{
			Version:  agentVersion,
			AuthzRev: snap.AuthzRev,
			SetSize:  len(set),
		})
		if err == nil {
			a.applyConfig(resp.Config)
		}
		if !sleep(ctx, 60*time.Second) {
			return
		}
	}
}

func (a *Agent) applyConfig(cfg agentConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cfg.UsageIntervalS > 0 {
		a.cfg.UsageIntervalS = cfg.UsageIntervalS
	}
	if cfg.GraceMinutes > 0 {
		a.cfg.GraceMinutes = cfg.GraceMinutes
	}
	if len(cfg.Services) > 0 {
		m := make(map[uint16]string, len(cfg.Services))
		for _, s := range cfg.Services {
			m[s.Port] = s.Key
		}
		a.services = m
	}
}

// --- helpers ----------------------------------------------------------------

func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sleep waits d or until ctx is done; returns false if ctx was cancelled.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		d = time.Second
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

type backoff struct{ cur time.Duration }

func newBackoff() *backoff { return &backoff{} }

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = time.Second
	} else if b.cur < 60*time.Second {
		b.cur *= 2
	}
	if b.cur > 60*time.Second {
		b.cur = 60 * time.Second
	}
	return b.cur
}

func (b *backoff) reset() { b.cur = 0 }
