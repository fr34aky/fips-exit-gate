package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/metrics"
)

// captiveMetrics is the captive daemon's Prometheus registry. Update methods are
// nil-safe so the daemon runs unchanged when metrics are disabled.
type captiveMetrics struct {
	reg         *metrics.Registry
	connections *metrics.Counter
	redirects   *metrics.Counter
	refused     *metrics.Counter
	shed        *metrics.Counter
}

func newCaptiveMetrics() *captiveMetrics {
	r := metrics.New()
	return &captiveMetrics{
		reg:         r,
		connections: r.Counter("fipsexit_captive_connections_total", "Connections accepted and handled"),
		redirects:   r.Counter("fipsexit_captive_redirects_total", "HTTP 302 redirects issued to the portal"),
		refused:     r.Counter("fipsexit_captive_refused_total", "Connections refused (non-HTTP / non-CONNECT / error)"),
		shed:        r.Counter("fipsexit_captive_shed_total", "Connections dropped at max capacity"),
	}
}

func (m *captiveMetrics) conn() {
	if m != nil {
		m.connections.Inc()
	}
}
func (m *captiveMetrics) redirect() {
	if m != nil {
		m.redirects.Inc()
	}
}
func (m *captiveMetrics) refuse() {
	if m != nil {
		m.refused.Inc()
	}
}
func (m *captiveMetrics) shedConn() {
	if m != nil {
		m.shed.Inc()
	}
}

func (m *captiveMetrics) serve(ctx context.Context, addr string) {
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
		log.Printf("captive: metrics on %s/metrics", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("captive: metrics server: %v", err)
		}
	}()
}
