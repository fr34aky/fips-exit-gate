// Command captive is the fips-exit captive daemon. Unauthorized clients hit
// the service ports and are redirected here by nftables; captive speaks just
// enough SOCKS5 to read their first request and answer plain HTTP with a 302
// to the user portal (refusing everything else). It never proxies traffic and
// needs no backend, so it keeps working during backend outages.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type config struct {
	listen    string
	portalURL string
	secret    []byte
	maxConns  int
	ioTimeout time.Duration
}

func loadConfig() (config, error) {
	c := config{
		listen:    getenv("CAPTIVE_LISTEN", "[::1]:1080"),
		portalURL: os.Getenv("CAPTIVE_PORTAL_URL"),
		maxConns:  getenvInt("CAPTIVE_MAX_CONNS", 1024),
		ioTimeout: time.Duration(getenvInt("CAPTIVE_IO_TIMEOUT_S", 10)) * time.Second,
	}
	if c.portalURL == "" {
		return c, errors.New("CAPTIVE_PORTAL_URL is required")
	}
	secret := os.Getenv("CAPTIVE_TOKEN_SECRET")
	if secret == "" {
		return c, errors.New("CAPTIVE_TOKEN_SECRET is required")
	}
	c.secret = []byte(secret)
	return c, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("captive: config: %v", err)
	}
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("captive: listen %s: %v", cfg.listen, err)
	}
	log.Printf("captive: listening on %s, portal=%s", cfg.listen, cfg.portalURL)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()

	// Metrics (Prometheus text format) if an address is configured.
	var m *captiveMetrics
	if addr := os.Getenv("CAPTIVE_METRICS_ADDR"); addr != "" {
		m = newCaptiveMetrics()
		m.serve(ctx, addr)
	}

	sem := make(chan struct{}, cfg.maxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("captive: accept: %v", err)
			continue
		}
		select {
		case sem <- struct{}{}:
			m.conn()
			go func() {
				defer func() { <-sem }()
				handle(conn, cfg, m)
			}()
		default:
			m.shedConn()
			conn.Close() // at capacity: shed load rather than queue
		}
	}
}

func handle(conn net.Conn, cfg config, m *captiveMetrics) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.ioTimeout))

	src := sourceAddr(conn)
	if err := socksAccept(conn); err != nil {
		m.refuse() // malformed or non-CONNECT; SOCKS error already sent where relevant
		return
	}
	exp := time.Now().Add(tokenTTLSeconds * time.Second).Unix()
	redirected, _ := serveRedirect(conn, src, cfg.portalURL, cfg.secret, exp)
	if redirected {
		m.redirect()
	} else {
		m.refuse()
	}
	// Whether or not we redirected, we are done: close the connection.
}

// sourceAddr returns the client's real source address. nftables `redirect`
// only rewrites the destination, so RemoteAddr still carries the fips source.
func sourceAddr(conn net.Conn) netip.Addr {
	if ap, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ap.IP); ok {
			return a.Unmap()
		}
	}
	return netip.Addr{}
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
