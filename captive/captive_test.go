package main

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// rw pairs a reader (client->server bytes) with a captured writer (server
// output), implementing io.ReadWriter without ambiguous embedded methods.
type rw struct {
	in  io.Reader
	out bytes.Buffer
}

func (x *rw) Read(p []byte) (int, error)  { return x.in.Read(p) }
func (x *rw) Write(p []byte) (int, error) { return x.out.Write(p) }

func socksGreetConnect(target string) []byte {
	// Greeting: VER, NMETHODS=1, no-auth. Request: CONNECT to <target>:80 as domain.
	b := []byte{socksVersion, 1, methodNoAuth, socksVersion, cmdConnect, 0x00, atypDomain, byte(len(target))}
	b = append(b, []byte(target)...)
	b = append(b, 0x00, 0x50) // port 80
	return b
}

func TestSocksAcceptConnect(t *testing.T) {
	x := &rw{in: bytes.NewReader(socksGreetConnect("example.com"))}
	if err := socksAccept(x); err != nil {
		t.Fatalf("socksAccept: %v", err)
	}
	out := x.out.Bytes()
	// method reply + success reply
	if len(out) < 2 || out[0] != socksVersion || out[1] != methodNoAuth {
		t.Fatalf("bad method reply: %x", out[:2])
	}
	if out[2] != socksVersion || out[3] != repSucceeded {
		t.Fatalf("bad connect reply: %x", out[2:])
	}
}

func TestSocksAcceptRejectsNonConnect(t *testing.T) {
	req := []byte{socksVersion, 1, methodNoAuth, socksVersion, 0x02 /*BIND*/, 0x00, atypIPv4, 1, 2, 3, 4, 0, 80}
	x := &rw{in: bytes.NewReader(req)}
	if err := socksAccept(x); err != errNotConnect {
		t.Fatalf("expected errNotConnect, got %v", err)
	}
	out := x.out.Bytes()
	if !bytes.Contains(out, []byte{socksVersion, repCommandNotSupported}) {
		t.Fatalf("expected command-not-supported reply, got %x", out)
	}
}

func TestServeRedirectHTTP(t *testing.T) {
	src := netip.MustParseAddr("fd10:93b2:8586:6046:e42d:c089:3228:ccff")
	secret := []byte("test-secret")
	exp := time.Now().Add(time.Minute).Unix()
	req := "GET /path HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"
	x := &rw{in: strings.NewReader(req)}

	ok, err := serveRedirect(x, src, "https://portal.example/captive", secret, exp)
	if err != nil || !ok {
		t.Fatalf("serveRedirect: ok=%v err=%v", ok, err)
	}
	resp := x.out.String()
	if !strings.HasPrefix(resp, "HTTP/1.1 302") {
		t.Fatalf("expected 302, got: %q", resp)
	}
	loc := locationHeader(t, resp)
	if !strings.HasPrefix(loc, "https://portal.example/captive?") {
		t.Fatalf("bad location: %s", loc)
	}
	if !strings.Contains(loc, "dest=neverssl.com") {
		t.Fatalf("expected dest in location: %s", loc)
	}
	// The token must verify and carry the source address.
	tok := extractQuery(loc, "t")
	gotAddr, err := verifyToken(secret, tok, time.Now().Unix())
	if err != nil {
		t.Fatalf("verifyToken: %v", err)
	}
	if gotAddr != src {
		t.Fatalf("token addr = %s, want %s", gotAddr, src)
	}
}

func TestServeRedirectNonHTTP(t *testing.T) {
	// TLS ClientHello prefix: 0x16 0x03 ... — must not be treated as HTTP.
	x := &rw{in: bytes.NewReader([]byte{0x16, 0x03, 0x01, 0x00, 0x2a})}
	ok, err := serveRedirect(x, netip.MustParseAddr("fd00::1"), "https://p/", []byte("s"), time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ok {
		t.Fatalf("TLS should not be redirected")
	}
	if x.out.Len() != 0 {
		t.Fatalf("expected no response for non-HTTP, got %q", x.out.String())
	}
}

func TestServeProxyRedirectPlainHTTP(t *testing.T) {
	src := netip.MustParseAddr("fd10:93b2:8586:6046:e42d:c089:3228:ccff")
	secret := []byte("test-secret")
	exp := time.Now().Add(time.Minute).Unix()
	// Absolute-form proxy request (what an HTTP-proxy client sends).
	req := "GET http://neverssl.com/path HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"
	x := &rw{in: strings.NewReader(req)}

	ok, err := serveProxyRedirect(x, src, "https://portal.example/captive", secret, exp)
	if err != nil || !ok {
		t.Fatalf("serveProxyRedirect: ok=%v err=%v", ok, err)
	}
	resp := x.out.String()
	if !strings.HasPrefix(resp, "HTTP/1.1 302") {
		t.Fatalf("expected 302, got: %q", resp)
	}
	loc := locationHeader(t, resp)
	if !strings.Contains(loc, "dest=neverssl.com") {
		t.Fatalf("expected dest from absolute-form target: %s", loc)
	}
	gotAddr, err := verifyToken(secret, extractQuery(loc, "t"), time.Now().Unix())
	if err != nil || gotAddr != src {
		t.Fatalf("token addr = %s (err %v), want %s", gotAddr, err, src)
	}
}

func TestServeProxyRedirectRefusesConnect(t *testing.T) {
	// CONNECT (HTTPS tunnel) cannot be redirected: no bytes, no error.
	x := &rw{in: strings.NewReader("CONNECT neverssl.com:443 HTTP/1.1\r\nHost: neverssl.com:443\r\n\r\n")}
	ok, err := serveProxyRedirect(x, netip.MustParseAddr("fd00::1"), "https://p/", []byte("s"), time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ok {
		t.Fatalf("CONNECT should not be redirected")
	}
	if x.out.Len() != 0 {
		t.Fatalf("expected no response for CONNECT, got %q", x.out.String())
	}
}

func TestServeProxyRedirectNonHTTP(t *testing.T) {
	// A stray TLS ClientHello on the HTTP-proxy port: not a proxy request line.
	x := &rw{in: bytes.NewReader([]byte{0x16, 0x03, 0x01, 0x00, 0x2a})}
	ok, err := serveProxyRedirect(x, netip.MustParseAddr("fd00::1"), "https://p/", []byte("s"), time.Now().Add(time.Minute).Unix())
	if err != nil || ok {
		t.Fatalf("non-HTTP should not redirect: ok=%v err=%v", ok, err)
	}
	if x.out.Len() != 0 {
		t.Fatalf("expected no response for non-HTTP, got %q", x.out.String())
	}
}

func TestTokenTamperAndExpiry(t *testing.T) {
	secret := []byte("s3cr3t")
	src := netip.MustParseAddr("fd00::abcd")
	now := time.Now().Unix()
	tok := signToken(secret, src, now+60)

	if _, err := verifyToken([]byte("wrong"), tok, now); err == nil {
		t.Error("wrong secret verified")
	}
	if _, err := verifyToken(secret, tok, now+120); err == nil {
		t.Error("expired token verified")
	}
	if _, err := verifyToken(secret, tok+"x", now); err == nil {
		t.Error("tampered token verified")
	}
	if got, err := verifyToken(secret, tok, now); err != nil || got != src {
		t.Errorf("valid token failed: got=%s err=%v", got, err)
	}
}

func locationHeader(t *testing.T, resp string) string {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(resp))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.EqualFold(strings.TrimSpace(k), "location") {
			return strings.TrimSpace(v)
		}
	}
	t.Fatal("no Location header")
	return ""
}

func extractQuery(u, key string) string {
	_, q, _ := strings.Cut(u, "?")
	for _, kv := range strings.Split(q, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}
