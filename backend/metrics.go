package main

import (
	"context"
	"crypto/subtle"
	"net/http"
	"runtime"
	"time"

	"github.com/fr34aky/fips-exit-gate/backend/store"
	"github.com/fr34aky/fips-exit-gate/pkg/metrics"
)

// appMetrics holds the backend's Prometheus registry and the counters updated
// from request handlers. Scrape-time gauges are collected from the store.
type appMetrics struct {
	reg     *metrics.Registry
	webhook *metrics.CounterVec // labels: type, result
}

func newAppMetrics(st *store.Store) *appMetrics {
	reg := metrics.New()
	m := &appMetrics{
		reg: reg,
		webhook: reg.CounterVec("fipsexit_webhook_events_total",
			"BTCPay webhook deliveries processed, by event type and result", "type", "result"),
	}
	reg.Collect(runtimeSamples)
	reg.Collect(func() []metrics.Sample { return storeSamples(st) })
	return m
}

// serveMetrics renders /metrics, optionally gated by a bearer token.
func serveMetrics(m *appMetrics, token string) http.HandlerFunc {
	want := []byte(token)
	return func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			t, ok := bearer(r)
			if !ok || subtle.ConstantTimeCompare([]byte(t), want) != 1 {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "bad metrics token")
				return
			}
		}
		m.reg.ServeHTTP(w, r)
	}
}

func runtimeSamples() []metrics.Sample {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return []metrics.Sample{
		{Name: "fipsexit_goroutines", Help: "Number of goroutines", Value: float64(runtime.NumGoroutine())},
		{Name: "fipsexit_memory_alloc_bytes", Help: "Heap bytes allocated and in use", Value: float64(ms.Alloc)},
		{Name: "fipsexit_gc_total", Help: "Completed GC cycles", Type: "counter", Value: float64(ms.NumGC)},
	}
}

// storeSamples reads control-plane counts at scrape time. On a store error it
// reports fipsexit_store_up 0 rather than failing the whole scrape.
func storeSamples(st *store.Store) []metrics.Sample {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	snap, err := st.MetricsSnapshot(ctx)
	if err != nil {
		return []metrics.Sample{{Name: "fipsexit_store_up", Help: "1 if the store was reachable at scrape time", Value: 0}}
	}
	out := []metrics.Sample{
		{Name: "fipsexit_store_up", Help: "1 if the store was reachable at scrape time", Value: 1},
		{Name: "fipsexit_authorized_addresses", Help: "Addresses in the authorized set", Value: float64(snap.AuthorizedAddrs)},
		{Name: "fipsexit_authz_revision", Help: "Current global authz revision", Type: "counter", Value: float64(snap.AuthzRevision)},
		{Name: "fipsexit_entitlements_active", Help: "Active (unexpired, unexhausted) entitlements", Value: float64(snap.EntitlementsActive)},
		{Name: "fipsexit_usage_bytes_total", Help: "Total metered bytes ingested", Type: "counter", Value: float64(snap.UsageBytesTotal)},
	}
	for status, n := range snap.AccountsByStatus {
		out = append(out, metrics.Sample{Name: "fipsexit_accounts", Help: "Accounts by status", Labels: []string{"status", status}, Value: float64(n)})
	}
	for status, n := range snap.PurchasesByStatus {
		out = append(out, metrics.Sample{Name: "fipsexit_purchases", Help: "Purchases by status", Labels: []string{"status", status}, Value: float64(n)})
	}
	for _, node := range snap.Nodes {
		out = append(out, metrics.Sample{
			Name: "fipsexit_exit_node_last_seen_seconds", Help: "Unix time of a node's last heartbeat (0 = never)",
			Labels: []string{"node", node.Name}, Value: node.LastSeenUnix,
		})
	}
	return out
}
