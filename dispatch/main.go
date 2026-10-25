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
	"sync/atomic"
	"syscall"
	"time"
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
		idleTimeout:      time.Duration(getenvInt("DISPATCH_IDLE_TIMEOUT_S", 600)) * time.Second,
		maxLifetime:      time.Duration(getenvInt("DISPATCH_MAX_LIFETIME_S", 86400)) * time.Second,
		maxConns:         getenvInt("DISPATCH_MAX_CONNS", 4096),
	}
}

func main() {
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
// half-close so an EOF one way still lets the other drain. The tunnel is also
// torn down after `idle` without traffic in either direction, or after
// `maxLife` in total (0 disables either): defence in depth so a tunnel can't
// outlive its owner's authorization indefinitely. The nftables gate resets a
// revoked client's flow on its next packet; these bounds cover the silent ones.
func relay(a, b net.Conn, idle, maxLife time.Duration) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	touch := func() { last.Store(time.Now().UnixNano()) }

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, activityReader{r: src, touch: touch})
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)

	if idle > 0 || maxLife > 0 {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			start := time.Now()
			t := time.NewTicker(watchdogInterval(idle, maxLife))
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case now := <-t.C:
					idleFor := now.Sub(time.Unix(0, last.Load()))
					if (idle > 0 && idleFor >= idle) || (maxLife > 0 && now.Sub(start) >= maxLife) {
						a.Close()
						b.Close()
						return
					}
				}
			}
		}()
	}
	<-done
	<-done
}

// watchdogInterval picks how often the relay re-checks its bounds: fine enough
// to enforce short limits promptly, coarse enough to cost nothing at scale.
func watchdogInterval(idle, maxLife time.Duration) time.Duration {
	iv := 5 * time.Second
	for _, d := range []time.Duration{idle, maxLife} {
		if d > 0 && d/4 < iv {
			iv = d / 4
		}
	}
	if iv < 10*time.Millisecond {
		iv = 10 * time.Millisecond
	}
	return iv
}

// activityReader stamps the relay's last-activity clock on every read.
type activityReader struct {
	r     io.Reader
	touch func()
}

func (ar activityReader) Read(p []byte) (int, error) {
	n, err := ar.r.Read(p)
	if n > 0 {
		ar.touch()
	}
	return n, err
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
