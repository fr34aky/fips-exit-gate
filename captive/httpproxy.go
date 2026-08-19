package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
)

// The captive daemon is one listener behind the nftables gate, which redirects
// every unauthorized service port to it. SOCKS service ports (e.g. :1080) arrive
// speaking SOCKS5; an HTTP-proxy service port (e.g. :8080) arrives speaking the
// HTTP proxy protocol directly — no SOCKS handshake. handle() peeks the first
// byte to tell them apart (0x05 => SOCKS) and routes non-SOCKS clients here.
//
// An HTTP-proxy client's first line is either a plain request in absolute form
// (GET http://host/path HTTP/1.1) — which we answer with a 302 to the portal —
// or a CONNECT (HTTPS tunnel), which we cannot meaningfully redirect (the client
// awaits a 200 before any HTTP it would follow), so we refuse it. Same captive
// limitation as TLS-over-SOCKS.

// serveProxyRedirect reads the first proxy request line and, for a plain
// (non-CONNECT) HTTP request, writes a 302 to the portal carrying a signed
// context token for src. Returns true if a redirect was written; false (no
// bytes) for CONNECT or anything not recognizably HTTP, so the caller closes.
func serveProxyRedirect(rw io.ReadWriter, src netip.Addr, portalBase string, secret []byte, expUnix int64) (bool, error) {
	br := bufio.NewReaderSize(io.LimitReader(rw, maxRequestLine), maxRequestLine)
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("captive: read proxy request line: %w", err)
	}
	method, target := parseRequestLine(line)
	if method == "" || !looksLikeHTTP(method+" ") {
		return false, nil // not HTTP — caller closes
	}
	if method == "CONNECT" {
		return false, nil // HTTPS tunnel — can't 302 it, refuse like TLS-over-SOCKS
	}

	// Prefer the host in the absolute-form target; fall back to the Host header.
	host := hostFromTarget(target)
	if host == "" {
		host = hostFromHeaders(br)
	}
	location := buildPortalURL(portalBase, src, host, secret, expUnix)
	return writeRedirect(rw, location)
}

// parseRequestLine splits an HTTP request line into method and request-target,
// returning empty strings if it is not a well-formed "METHOD TARGET VERSION".
func parseRequestLine(line string) (method, target string) {
	fields := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "HTTP/") {
		return "", ""
	}
	return fields[0], fields[1]
}

// hostFromTarget returns the host[:port] of an absolute-form request target
// (http://host/path). Origin-form targets ("/path") have no host and yield "".
func hostFromTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Host
}
