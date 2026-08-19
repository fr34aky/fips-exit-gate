package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	socks "golang.org/x/net/proxy"
)

// proxy is the HTTP forward proxy. Plaintext requests go through rt (an
// http.Transport whose dials are tunneled over the upstream SOCKS proxy);
// CONNECT tunnels use dial directly. Splitting the two makes both injectable in
// tests without a live SOCKS upstream.
type proxy struct {
	rt   http.RoundTripper
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// newProxy wires an http.Transport and a CONNECT dialer onto the SOCKS dialer.
// x/net's SOCKS5 dialer implements ContextDialer; fall back to the context-less
// Dial if a future version ever doesn't, so we never panic on the assertion.
func newProxy(d socks.Dialer, dialTimeout time.Duration) *proxy {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if cd, ok := d.(socks.ContextDialer); ok {
			return cd.DialContext(ctx, network, addr)
		}
		return d.Dial(network, addr)
	}
	return &proxy{
		rt: &http.Transport{
			DialContext:           dial,
			ForceAttemptHTTP2:     false, // plain HTTP/1.1 to origins; keeps forwarding simple
			MaxIdleConns:          256,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: dialTimeout,
		},
		dial: dial,
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// A forward proxy only accepts absolute-form request targets
	// (GET http://host/path). Origin-form (GET /path) means someone pointed a
	// non-proxy client at us; there is nothing to forward.
	if !r.URL.IsAbs() || r.URL.Host == "" {
		http.Error(w, "fips-exit http proxy: absolute-form request required", http.StatusBadRequest)
		return
	}

	// Hand the request to the transport untouched except for proxy-layer hop
	// headers. RequestURI must be cleared for an outbound client request.
	r.RequestURI = ""
	delHopHeaders(r.Header)

	resp, err := p.rt.RoundTrip(r)
	if err != nil {
		// Never log the destination (privacy); the category is enough.
		log.Printf("httpproxy: upstream roundtrip failed")
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	delHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleConnect opens a tunnel to r.Host through the SOCKS upstream, hijacks the
// client connection, acknowledges with 200, and splices the two. The upstream
// (Dante) resolves the host and enforces egress policy, so no destination is
// resolved or vetted here.
func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	up, err := p.dial(r.Context(), "tcp", r.Host)
	if err != nil {
		log.Printf("httpproxy: connect upstream unreachable")
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer up.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connect unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	relay(client, up)
}

// relay copies bytes in both directions until either side closes, using TCP
// half-close so an EOF one way still lets the other drain. Same shape as the
// dispatcher's relay.
func relay(a, b net.Conn) {
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
	<-done
	<-done
}

// hopHeaders are the HTTP/1.1 hop-by-hop headers, stripped in both directions so
// they are not forwarded end-to-end (RFC 7230 §6.1).
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func delHopHeaders(h http.Header) {
	// Honor the Connection header's own list of headers to drop, then the
	// standard hop-by-hop set.
	for _, f := range h.Values("Connection") {
		for _, tok := range strings.Split(f, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				h.Del(tok)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
