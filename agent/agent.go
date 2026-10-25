package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/authzhash"
)

const agentVersion = "0.3.0"

// backend is the subset of the backend API the agent uses; *backendClient
// implements it, and tests substitute a fake.
type backend interface {
	setAuth(nodeID, token string)
	enroll(ctx context.Context, req enrollRequest) (enrollResponse, error)
	getAuthz(ctx context.Context, rev int64, wait int, full bool) (authzResponse, error)
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

	// fullSyncEvery bounds how long the kernel set may silently drift from the
	// backend before runSync forces a full reconcile even at an unchanged
	// revision (0 = never; the startup and heartbeat-triggered reconciles still
	// happen). heartbeatEvery and longPollWait pace the other two loops. All
	// are set before Run and read-only afterwards.
	fullSyncEvery  time.Duration
	heartbeatEvery time.Duration
	longPollWait   time.Duration

	// Mass-revoke guard: a full reconcile that would delete more than
	// massRevokeMin addresses AND more than half of the live set is refused
	// unless the backend marks the response force=true or the operator sets
	// allowMassRevoke. It protects every paying user on the node from an
	// empty/truncated backend set (DB restore, misconfigured backend URL
	// pointing at a fresh instance, a recompute bug).
	massRevokeMin   int
	allowMassRevoke bool

	mu                   sync.Mutex
	startedAt            time.Time // when Run began (fail-closed startup grace)
	cfg                  agentConfig
	services             map[uint16]string // port -> service key
	failClosedAfterGrace bool
	bufferCap            int
	lastAuthzOK          time.Time
	forceResync          bool             // set by heartbeat when the backend reports drift
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
		fullSyncEvery:        5 * time.Minute,
		heartbeatEvery:       60 * time.Second,
		longPollWait:         50 * time.Second,
		massRevokeMin:        50,
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
	a.initLastAuthzOK()

	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){a.runSync, a.runUsage, a.runHeartbeat} {
		wg.Add(1)
		go func(f func(context.Context)) { defer wg.Done(); f(ctx) }(loop)
	}
	wg.Wait()
	return ctx.Err()
}

// initLastAuthzOK seeds the grace clock from persisted state, so an outage
// that spans restarts still fails closed on time; a first run starts it now.
// graceCheck additionally requires startupGrace of THIS process's uptime
// before acting on a stale persisted clock, so planned downtime of the agent
// or host (which says nothing about the backend) followed by one transient
// startup failure does not flush every paying user.
func (a *Agent) initLastAuthzOK() {
	last := a.store.snapshotRuntime().LastAuthzOK
	now := a.now()
	if last.IsZero() {
		last = now
	}
	a.mu.Lock()
	a.lastAuthzOK = last
	a.startedAt = now
	a.mu.Unlock()
}

// startupGrace is how long after start the backend must have been failing
// before a stale persisted clock may trigger fail-closed: 10 minutes, or half
// the grace window if that is shorter.
func (a *Agent) startupGrace() time.Duration {
	g := 10 * time.Minute
	if half := time.Duration(a.cfg.GraceMinutes) * time.Minute / 2; half > 0 && half < g {
		g = half
	}
	return g
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
	var lastFull time.Time
	for ctx.Err() == nil {
		// A revision counter only detects changes on the BACKEND side; it can't
		// see the kernel set being flushed out-of-band (an `up.sh reload`, a
		// manual `nft flush`, a table reload), which leaves rev unchanged while
		// the set is wrong. So also force a full pull (a) periodically, so any
		// such drift self-heals within fullSyncEvery, and (b) on demand when the
		// backend's heartbeat spots a size mismatch. applyAuthz then diffs the
		// full desired set against the live kernel set and repairs the difference.
		if a.takeResync() {
			forceFull = true
		}
		if !forceFull && a.fullSyncEvery > 0 && a.now().Sub(lastFull) >= a.fullSyncEvery {
			forceFull = true
		}
		persisted := a.store.authzRev()
		rev := persisted
		if forceFull {
			rev = 0
		}
		resp, err := a.client.getAuthz(ctx, rev, int(a.longPollWait/time.Second), forceFull)
		switch {
		case err == errUnchanged:
			// Backend has nothing past rev. If we were attempting a periodic full
			// reconcile, the pull with rev=0 already proved the kernel set is in
			// sync (a change would have returned the full body), so record it.
			if forceFull {
				forceFull = false
				lastFull = a.now()
			}
			a.markAuthzOK()
			backoff.reset()
		case err != nil:
			a.metrics.syncErr()
			a.graceCheck()
			sleep(ctx, backoff.next())
			continue
		default:
			if err := a.applyAuthz(resp); err != nil {
				var mass *massRevokeError
				var regress *revRegressionError
				switch {
				case errors.As(err, &mass):
					// The backend answered, so this is a deliberate hold, not an
					// outage: keep the grace clock and metrics truthful.
					a.metrics.massRevokeRefused()
					a.markAuthzOK()
					log.Printf("agent: REFUSING full reconcile: %v (backend force=false, FIPS_AGENT_ALLOW_MASS_REVOKE unset)", err)
					if forceFull && persisted > 0 {
						// We have a cursor: let the authoritative delta log, which
						// carries any genuine revocations, drive the set instead of
						// this suspicious full set. The periodic full reconcile
						// retries later and passes once delta and full agree.
						forceFull = false
						lastFull = a.now()
						backoff.reset()
						continue
					}
					// Unforced full (compaction, or a backend with no delta log) or
					// no cursor: nothing safer to fall back to; hold and retry.
					sleep(ctx, backoff.next())
					continue
				case errors.As(err, &regress):
					// The backend's revision went backwards (restored/fresh
					// database): our cursor is meaningless there. Don't move it
					// onto the new timeline silently; ask for a full set, which the
					// mass-revoke guard then judges.
					a.markAuthzOK()
					log.Printf("agent: %v; forcing a full reconcile", err)
					forceFull = true
					sleep(ctx, backoff.next())
					continue
				}
				a.metrics.nftErr()
				log.Printf("agent: apply authz: %v", err)
				sleep(ctx, backoff.next())
				continue
			}
			if resp.Full {
				a.metrics.fullSync()
			}
			if forceFull {
				forceFull = false
				lastFull = a.now()
			}
			a.markAuthzOK()
			backoff.reset()
		}
	}
}

// massRevokeError is returned by applyAuthz when the mass-revoke guard trips;
// nothing has been applied and the cursor has not moved.
type massRevokeError struct {
	del, current int
}

func (e *massRevokeError) Error() string {
	return fmt.Sprintf("full set would revoke %d of %d live addresses", e.del, e.current)
}

// revRegressionError is returned by applyAuthz for a delta whose revision is
// below the persisted cursor: the backend's revision timeline was reset
// (database restore, pointed at a fresh backend). Nothing has been applied.
type revRegressionError struct {
	got, cursor int64
}

func (e *revRegressionError) Error() string {
	return fmt.Sprintf("backend revision %d is below our cursor %d (backend reset?)", e.got, e.cursor)
}

// presentOnly filters del down to addresses actually in the live set. nft
// fails a whole batch if any `delete element` names a missing member, and a
// member can legitimately be gone already: an inline revoke from a usage ack
// removes it first and the same del then arrives in the next authz delta.
// Without this the delta batch failed repeatedly, the cursor never advanced,
// and the adds in that delta (new paying users) stayed blocked until the next
// periodic full reconcile.
func (a *Agent) presentOnly(del []netip.Addr) ([]netip.Addr, error) {
	if len(del) == 0 {
		return nil, nil
	}
	current, err := a.fw.ListAuthorized()
	if err != nil {
		return nil, err
	}
	out := del[:0:0]
	for _, d := range del {
		if _, ok := current[d]; ok {
			out = append(out, d)
		}
	}
	return out, nil
}

// requestResync asks runSync to force a full reconcile on its next iteration.
// Called from the heartbeat loop when the backend reports the exit's set size
// disagrees with authz_current (kernel-side drift the revision can't detect).
func (a *Agent) requestResync() {
	a.mu.Lock()
	a.forceResync = true
	a.mu.Unlock()
}

// takeResync reports and clears a pending resync request.
func (a *Agent) takeResync() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.forceResync {
		a.forceResync = false
		return true
	}
	return false
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
		if !resp.Force && !a.allowMassRevoke && a.isMassRevoke(len(del), len(current)) {
			return &massRevokeError{del: len(del), current: len(current)}
		}
	} else {
		if cursor := a.store.authzRev(); resp.Rev < cursor {
			return &revRegressionError{got: resp.Rev, cursor: cursor}
		}
		for _, m := range resp.Add {
			add = append(add, m.Addr)
		}
		var err error
		if del, err = a.presentOnly(resp.Del); err != nil {
			return err
		}
	}
	if err := a.fw.ApplyAuthorized(add, del); err != nil {
		return err
	}
	return a.store.withRuntime(func(rt *runtime) { rt.AuthzRev = resp.Rev })
}

// isMassRevoke is the guard threshold: more than massRevokeMin deletions AND
// more than half of the live set. Small sets are never guarded (the blast
// radius is small and a legitimate churn of a few users is common).
func (a *Agent) isMassRevoke(del, current int) bool {
	return del > a.massRevokeMin && del*2 > current
}

// persistAuthzOKEvery throttles how often the grace clock is written to disk:
// it only needs minute resolution, and every idle 204 long-poll would otherwise
// re-serialize and fsync the whole runtime file (buffered usage included).
const persistAuthzOKEvery = time.Minute

func (a *Agent) markAuthzOK() {
	now := a.now()
	a.mu.Lock()
	a.lastAuthzOK = now
	a.mu.Unlock()
	a.store.mu.Lock()
	stale := now.Sub(a.store.rt.LastAuthzOK) >= persistAuthzOKEvery
	a.store.mu.Unlock()
	if stale {
		if err := a.store.withRuntime(func(rt *runtime) { rt.LastAuthzOK = now }); err != nil {
			log.Printf("agent: persist last_authz_ok: %v", err)
		}
	}
	a.metrics.syncOK(a.store.authzRev(), now)
}

// graceCheck optionally fails closed (flushes the authorized set) once the
// backend has been unreachable longer than the grace window.
func (a *Agent) graceCheck() {
	a.metrics.outage()
	a.mu.Lock()
	grace := time.Duration(a.cfg.GraceMinutes) * time.Minute
	now := a.now()
	over := now.Sub(a.lastAuthzOK) > grace
	// A persisted clock older than grace may just mean WE were down (planned
	// maintenance); only act on it once this process has itself seen the
	// backend fail for startupGrace.
	settled := a.startedAt.IsZero() || now.Sub(a.startedAt) >= a.startupGrace()
	failClosed := a.failClosedAfterGrace
	a.mu.Unlock()
	if !over || !failClosed || !settled {
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
			a.metrics.collectErr()
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
	var total uint64
	err = a.store.withRuntime(func(rt *runtime) {
		samples, next := computeDelta(rt.Baselines, cur, services)
		rt.Baselines = next
		rt.CounterEpoch = epoch
		if rt.PrimeBaselines {
			// State was lost (corrupt runtime file): the kernel counters still
			// hold bytes that were already reported. Record them as the baseline
			// and skip this window rather than bill them a second time.
			rt.PrimeBaselines = false
			log.Printf("agent: primed usage baselines from %d counter(s) after state recovery; skipping this window", len(cur))
			return
		}
		total = 0
		for _, s := range samples {
			total += s.Bytes
		}
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
	if err != nil {
		return err
	}
	// Only a persisted collection counts as a success.
	a.metrics.collected(total, a.now())
	return nil
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
	del, err := a.presentOnly(revoke)
	if err != nil {
		log.Printf("agent: revoke: %v", err)
		return
	}
	if err := a.fw.ApplyAuthorized(nil, del); err != nil {
		log.Printf("agent: revoke: %v", err)
		return
	}
	a.gcAcct(revoke)
	log.Printf("agent: revoked %d addr(s) on backend request (%d already absent)", len(del), len(revoke)-len(del))
}

// gcAcct removes accounting elements for revoked addresses across all services.
// Only elements that exist are named: nft rejects the whole batch otherwise,
// and an address rarely has traffic on every service.
func (a *Agent) gcAcct(addrs []netip.Addr) {
	existing, err := a.fw.ReadAcct()
	if err != nil {
		log.Printf("agent: gc acct (ignored): %v", err)
		return
	}
	want := make(map[netip.Addr]struct{}, len(addrs))
	for _, addr := range addrs {
		want[addr] = struct{}{}
	}
	var keys []acctKey
	for k := range existing {
		if _, ok := want[k.Addr]; ok {
			keys = append(keys, k)
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
		req := heartbeatRequest{Version: agentVersion, AuthzRev: a.store.snapshotRuntime().AuthzRev, SetSize: -1}
		set, err := a.fw.ListAuthorized()
		if err != nil {
			// Report "unknown" rather than an empty set, which the backend would
			// read as drift and answer with a pointless resync.
			log.Printf("agent: heartbeat: list authorized: %v", err)
		} else {
			a.metrics.setAuthorized(len(set))
			req.SetSize = len(set)
			req.SetHash = authzhash.OfSet(set)
		}
		resp, err := a.client.heartbeat(ctx, req)
		if err == nil {
			a.applyConfig(resp.Config)
			if resp.Resync {
				log.Printf("agent: backend reported set drift (local=%d), forcing full reconcile", req.SetSize)
				a.requestResync()
			}
		}
		if !sleep(ctx, a.heartbeatEvery) {
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

const backoffMax = 60 * time.Second

// next doubles from 1 s up to backoffMax and returns that with ±20 % jitter,
// so a fleet of agents that lost the backend together doesn't retry in
// lockstep when it comes back.
func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = time.Second
	} else if b.cur < backoffMax {
		b.cur *= 2
	}
	if b.cur > backoffMax {
		b.cur = backoffMax
	}
	return jitter(b.cur, 0.2)
}

// jitter returns d scaled by a random factor in [1-frac, 1+frac].
func jitter(d time.Duration, frac float64) time.Duration {
	f := 1 + frac*(2*mrand.Float64()-1)
	return time.Duration(float64(d) * f)
}

func (b *backoff) reset() { b.cur = 0 }
