// Command dispatch is the fips-exit connectivity front-end. It listens on the
// connectivity service port (fips address :1080) and speaks SOCKS5 to the
// client, then forwards each CONNECT to one of two upstream SOCKS proxies based
// on the destination name:
//
//	*.onion  -> Tor   (loopback SocksPort)  — .onion reachability
//	else     -> Dante (loopback)            — clearnet egress + policy + DNS
//
// It carries no egress policy of its own: the clearnet path inherits Dante's
// (fd00::/8, RFC1918, metadata, SMTP, bind all blocked, DNS resolved server
// side), and the onion path inherits Tor's (internal addresses rejected). The
// port is unchanged from the client's view, so the nftables gate, accounting,
// exit-agent, and billing are untouched — the connectivity service is still one
// gated, metered port at one rate.
//
// Privacy: like Dante, it never logs destinations — only failure categories.
package main

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/fr34aky/fips-exit-gate/pkg/logging"
)

type config struct {
	listen           string
	clearnetUpstream string
	torUpstream      string
	onionSuffix      string
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	idleTimeout      time.Duration // relay: close after this long with no bytes either way (0 = never)
	maxLifetime      time.Duration // relay: close after this long regardless of activity (0 = never)
	maxConns         int
}

func loadConfig() config {
	return config{
		listen:           getenv("DISPATCH_LISTEN", "[::1]:1080"),
		clearnetUpstream: getenv("DISPATCH_CLEARNET_UPSTREAM", "127.0.0.1:1090"),
		torUpstream:      getenv("DISPATCH_TOR_UPSTREAM", "127.0.0.1:9052"),
		onionSuffix:      getenv("DISPATCH_ONION_SUFFIX", ".onion"),
		dialTimeout:      time.Duration(getenvInt("DISPATCH_DIAL_TIMEOUT_S", 15)) * time.Second,
		handshakeTimeout: time.Duration(getenvInt("DISPATCH_HANDSHAKE_TIMEOUT_S", 15)) * time.Second,
		idleTimeout:      time.Duration(getenvInt("DISPATCH_IDLE_TIMEOUT_S", 7200)) * time.Second,
		maxLifetime:      time.Duration(getenvInt("DISPATCH_MAX_LIFETIME_S", 0)) * time.Second,
		maxConns:         getenvInt("DISPATCH_MAX_CONNS", 4096),
	}
}

func main() {
	logging.Setup("dispatch")
	cfg := loadConfig()
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("dispatch: listen %s: %v", cfg.listen, err)
	}
	onion := "disabled"
	if cfg.torUpstream != "" {
		onion = cfg.torUpstream
	}
	log.Printf("dispatch: listening on %s, clearnet=%s onion(%s)=%s",
		cfg.listen, cfg.clearnetUpstream, cfg.onionSuffix, onion)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()

	sem := make(chan struct{}, cfg.maxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("dispatch: accept: %v", err)
			continue
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				handle(conn, cfg)
			}()
		default:
			conn.Close() // at capacity: shed load rather than queue
		}
	}
}

func handle(client net.Conn, cfg config) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(cfg.handshakeTimeout))

	if err := negotiate(client); err != nil {
		return
	}
	atyp, host, port, err := readConnect(client)
	if err != nil {
		return // error reply already sent where relevant
	}

	upstream, rep := pickUpstream(host, atyp == atypDomain, cfg)
	if rep != repSucceeded {
		_ = writeReply(client, rep)
		return
	}

	up, reply, err := dialThrough(upstream, atyp, host, port, cfg.dialTimeout)
	if err != nil {
		// Never log the destination (privacy); the upstream identity is enough.
		log.Printf("dispatch: upstream %s unreachable", upstream)
		_ = writeReply(client, repHostUnreachable)
		return
	}
	defer up.Close()

	// Relay the upstream's reply verbatim (carries the real REP + BND fields).
	if _, err := client.Write(reply); err != nil {
		return
	}
	if reply[1] != repSucceeded {
		return // upstream refused; the client already has the reason.
	}

	// Long-lived tunnel: drop the handshake deadlines and splice both ways.
	_ = client.SetDeadline(time.Time{})
	relay(client, up, cfg.idleTimeout, cfg.maxLifetime)
}

// relay copies bytes in both directions until either side closes, using TCP
// half-close so an EOF one way still lets the other drain. Plain io.Copy on
// the raw conns keeps Go's splice(2) zero-copy path for TCP<->TCP.
//
// Bounds (0 disables either): `maxLife` closes the tunnel after that long
// regardless of activity (opt-in); `idle` closes it when NEITHER side has
// received data for that long. Idleness is read from the kernel (TCP_INFO
// tcpi_last_data_recv, see relay_linux.go) by a watchdog that wakes every
// idle/4, so no byte is copied through userspace just to be counted and a slow
// trickle is still seen as activity. On platforms or conn types without that
// signal the idle bound is not enforced. Revoked clients don't rely on it: the
// nftables gate resets their flows on the next packet, and the listener's TCP
// keepalive provokes that even on a silent tunnel.
func relay(a, b net.Conn, idle, maxLife time.Duration) {
	closeBoth := func() { a.Close(); b.Close() }
	if maxLife > 0 {
		t := time.AfterFunc(maxLife, closeBoth)
		defer t.Stop()
	}
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)

	if idle > 0 {
		stop := make(chan struct{})
		defer close(stop)
		go idleWatchdog(a, b, idle, stop, closeBoth)
	}
	<-done
	<-done
}

// idleWatchdog closes the tunnel once both conns report no received data for
// `idle`. It wakes every idle/4 (at least every second), so the effective
// bound lies in [idle, 1.25*idle].
func idleWatchdog(a, b net.Conn, idle time.Duration, stop <-chan struct{}, closeBoth func()) {
	iv := idle / 4
	if iv < time.Second {
		iv = time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ia, okA := sinceLastRecv(a)
			ib, okB := sinceLastRecv(b)
			if !okA || !okB {
				return // no kernel signal for this conn type: don't guess
			}
			if ia >= idle && ib >= idle {
				closeBoth()
				return
			}
		}
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
