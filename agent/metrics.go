package main

import (
	"context"
	"log"
	"net/http"
	goruntime "runtime"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/metrics"
)

// agentMetrics is the agent's Prometheus registry and handles. All update
// methods are nil-safe, so the agent runs unchanged when metrics are disabled
// (no FIPS_AGENT_METRICS_ADDR) or in tests.
type agentMetrics struct {
	reg             *metrics.Registry
	authorizedAddrs *metrics.Gauge
	authzRev        *metrics.Gauge
	lastSync        *metrics.Gauge
	backendUp       *metrics.Gauge
	failOpen        *metrics.Gauge
	syncErrors      *metrics.Counter
	nftErrors       *metrics.Counter
	usageSent       *metrics.Counter
	usageDropped    *metrics.Counter
	usageBuffered   *metrics.Gauge
}

func newAgentMetrics() *agentMetrics {
	r := metrics.New()
	m := &agentMetrics{
		reg:             r,
		authorizedAddrs: r.Gauge("fipsexit_agent_authorized_addresses", "Addresses in the kernel authorized set"),
		authzRev:        r.Gauge("fipsexit_agent_authz_revision", "Last applied authz revision"),
		lastSync:        r.Gauge("fipsexit_agent_last_sync_seconds", "Unix time of the last successful authz sync"),
		backendUp:       r.Gauge("fipsexit_agent_backend_up", "1 if the backend was reachable on the last sync attempt"),
		failOpen:        r.Gauge("fipsexit_agent_fail_open_active", "1 while the backend is unreachable and the last-known set is retained"),
		syncErrors:      r.Counter("fipsexit_agent_sync_errors_total", "Authz sync errors"),
		nftErrors:       r.Counter("fipsexit_agent_nft_errors_total", "nftables operation errors"),
		usageSent:       r.Counter("fipsexit_agent_usage_reports_sent_total", "Usage reports delivered to the backend"),
		usageDropped:    r.Counter("fipsexit_agent_usage_reports_dropped_total", "Usage reports dropped (buffer full)"),
		usageBuffered:   r.Gauge("fipsexit_agent_usage_reports_buffered", "Usage reports currently buffered on disk"),
	}
	r.Collect(func() []metrics.Sample {
		return []metrics.Sample{{Name: "fipsexit_agent_goroutines", Help: "Number of goroutines", Value: float64(goruntime.NumGoroutine())}}
	})
	return m
}

func (m *agentMetrics) syncOK(rev int64, now time.Time) {
	if m == nil {
		return
	}
	m.backendUp.Set(1)
	m.failOpen.Set(0)
	m.lastSync.Set(float64(now.Unix()))
	m.authzRev.Set(float64(rev))
}
func (m *agentMetrics) syncErr() {
	if m == nil {
		return
	}
	m.syncErrors.Inc()
}
func (m *agentMetrics) outage() {
	if m == nil {
		return
	}
	m.backendUp.Set(0)
	m.failOpen.Set(1)
}
func (m *agentMetrics) nftErr() {
	if m == nil {
		return
	}
	m.nftErrors.Inc()
}
func (m *agentMetrics) usageSentInc() {
	if m == nil {
		return
	}
	m.usageSent.Inc()
}
func (m *agentMetrics) usageDrop(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.usageDropped.Add(float64(n))
}
func (m *agentMetrics) setBuffered(n int) {
	if m == nil {
		return
	}
	m.usageBuffered.Set(float64(n))
}
func (m *agentMetrics) setAuthorized(n int) {
	if m == nil {
		return
	}
	m.authorizedAddrs.Set(float64(n))
}

// serveMetrics starts an HTTP /metrics listener on addr (no-op if addr empty).
func (m *agentMetrics) serve(ctx context.Context, addr string) {
	if m == nil || addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.reg)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go func() {
		log.Printf("agent: metrics on %s/metrics", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("agent: metrics server: %v", err)
		}
	}()
}
