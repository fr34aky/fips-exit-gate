// Command httpproxy is a fips-exit egress service: an HTTP forward proxy on the
// connectivity-style model. It listens on a service port (fips address :8080)
// and speaks the HTTP proxy protocol to the client — plaintext requests
// (absolute-form GET/POST/...) and CONNECT tunnels (HTTPS) — forwarding every
// request to an upstream SOCKS proxy (Dante over loopback) rather than
// egressing itself.
//
// Forwarding through Dante means this proxy carries NO egress policy of its own:
// it inherits Dante's (fd00::/8, RFC1918, metadata, SMTP, bind all blocked, DNS
// resolved server-side). The port is a normal gated, metered service from the
// client's view, so the nftables gate, accounting, exit-agent, and billing are
// untouched — HTTP is just another port at its own rate. It exists purely for
// client compatibility: many apps and OSes take an HTTP proxy but not SOCKS.
//
// Privacy: like Dante and the dispatcher, it never logs destinations — only
// failure categories and lifecycle.
package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
	socks "golang.org/x/net/proxy"
)

type config struct {
	listen            string
	upstream          string
	dialTimeout       time.Duration
	readHeaderTimeout time.Duration
	maxConns          int
}

func loadConfig() config {
	return config{
		listen:            getenv("HTTPPROXY_LISTEN", "[::1]:8080"),
		upstream:          getenv("HTTPPROXY_UPSTREAM", "127.0.0.1:1090"),
		dialTimeout:       time.Duration(getenvInt("HTTPPROXY_DIAL_TIMEOUT_S", 15)) * time.Second,
		readHeaderTimeout: time.Duration(getenvInt("HTTPPROXY_READ_HEADER_TIMEOUT_S", 15)) * time.Second,
		maxConns:          getenvInt("HTTPPROXY_MAX_CONNS", 4096),
	}
}

func main() {
	cfg := loadConfig()

	// SOCKS5 dialer to the upstream (Dante). proxy.Direct is the fallback dialer
	// it uses to reach the upstream itself; from there Dante does the real egress.
	dialer, err := socks.SOCKS5("tcp", cfg.upstream, nil, socks.Direct)
	if err != nil {
		log.Fatalf("httpproxy: build socks dialer to %s: %v", cfg.upstream, err)
	}
	p := newProxy(dialer, cfg.dialTimeout)

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("httpproxy: listen %s: %v", cfg.listen, err)
	}
	if cfg.maxConns > 0 {
		ln = netutil.LimitListener(ln, cfg.maxConns) // shed load rather than exhaust fds
	}
	log.Printf("httpproxy: listening on %s, upstream(socks)=%s", cfg.listen, cfg.upstream)

	srv := &http.Server{
		Handler: p,
		// Bound only the header read; body/tunnel copies must not be write-capped
		// (they are long-lived), and CONNECT hijacks the conn out from under the
		// server entirely.
		ReadHeaderTimeout: cfg.readHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("httpproxy: serve: %v", err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
