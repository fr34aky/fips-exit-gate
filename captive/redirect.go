package main

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
)

// After the SOCKS handshake we read the first request line. If it is plain
// HTTP we answer 302 to the portal; anything else (TLS ClientHello, etc.) we
// simply close — the classic captive-portal limitation, accepted by design.

const maxRequestLine = 8 << 10 // 8 KiB is plenty for a request line + headers we ignore

// knownHTTPMethods gates the sniff so we only treat genuine HTTP as HTTP.
var knownHTTPMethods = []string{
	"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
}

// serveRedirect reads the first line, and if it is an HTTP request, writes a
// 302 to the portal carrying a signed context token for src. Returns true if a
// redirect was written.
func serveRedirect(rw io.ReadWriter, src netip.Addr, portalBase string, secret []byte, expUnix int64) (bool, error) {
	br := bufio.NewReaderSize(io.LimitReader(rw, maxRequestLine), maxRequestLine)
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("captive: read request line: %w", err)
	}
	if !looksLikeHTTP(line) {
		return false, nil // not HTTP — caller closes the connection
	}
	host := hostFromHeaders(br)
	location := buildPortalURL(portalBase, src, host, secret, expUnix)
	body := "Redirecting to the fips-exit portal.\n"
	resp := "HTTP/1.1 302 Found\r\n" +
		"Location: " + location + "\r\n" +
		"Cache-Control: no-store\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n" + body
	if _, err := io.WriteString(rw, resp); err != nil {
		return false, fmt.Errorf("captive: write 302: %w", err)
	}
	return true, nil
}

func looksLikeHTTP(line string) bool {
	for _, m := range knownHTTPMethods {
		if strings.HasPrefix(line, m) {
			return true
		}
	}
	return false
}

// hostFromHeaders scans the (already length-limited) header block for Host,
// used only to make the portal landing more informative. Best-effort.
func hostFromHeaders(br *bufio.Reader) string {
	for {
		line, err := br.ReadString('\n')
		if line == "" || err != nil {
			return ""
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return ""
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			return strings.TrimSpace(v)
		}
	}
}

func buildPortalURL(portalBase string, src netip.Addr, origHost string, secret []byte, expUnix int64) string {
	q := url.Values{}
	q.Set("t", signToken(secret, src, expUnix))
	if origHost != "" {
		q.Set("dest", origHost)
	}
	sep := "?"
	if strings.Contains(portalBase, "?") {
		sep = "&"
	}
	return portalBase + sep + q.Encode()
}
