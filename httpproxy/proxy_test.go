package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// roundTripFunc lets a test stand in for the SOCKS-backed transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPlaintextForwarded(t *testing.T) {
	var got *http.Request
	p := &proxy{
		rt: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			got = r
			return &http.Response{
				StatusCode: http.StatusTeapot,
				Header:     http.Header{"X-From-Origin": {"yes"}, "Connection": {"close"}},
				Body:       io.NopCloser(strings.NewReader("hello")),
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header.Set("Proxy-Connection", "keep-alive") // hop header, must be stripped
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if got == nil {
		t.Fatal("transport was not called")
	}
	if got.URL.Host != "example.com" {
		t.Fatalf("forwarded host = %q, want example.com", got.URL.Host)
	}
	if got.Header.Get("Proxy-Connection") != "" {
		t.Fatalf("Proxy-Connection should have been stripped, got %q", got.Header.Get("Proxy-Connection"))
	}
	res := rec.Result()
	if res.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", res.StatusCode)
	}
	if res.Header.Get("X-From-Origin") != "yes" {
		t.Fatalf("origin header not copied")
	}
	if res.Header.Get("Connection") != "" {
		t.Fatalf("Connection hop header should have been stripped from the response")
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
}

func TestOriginFormRejected(t *testing.T) {
	p := &proxy{rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport must not be called for origin-form requests")
		return nil, nil
	})}
	// httptest.NewRequest with a path-only target yields a non-absolute URL.
	req := httptest.NewRequest(http.MethodGet, "/just/a/path", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Result().StatusCode)
	}
}

func TestConnectTunnel(t *testing.T) {
	// A fake upstream: whatever the client writes after the tunnel is up, the
	// upstream echoes back uppercased — proving bytes flow both ways.
	p := &proxy{dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		if addr != "example.com:443" {
			t.Errorf("dialed %q, want example.com:443", addr)
		}
		c1, c2 := net.Pipe()
		go func() {
			buf := make([]byte, 64)
			n, _ := c2.Read(buf)
			_, _ = c2.Write([]byte(strings.ToUpper(string(buf[:n]))))
			c2.Close()
		}()
		return c1, nil
	}}

	srv := httptest.NewServer(p)
	defer srv.Close()

	// Raw client: send a CONNECT, expect 200, then use the tunnel.
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status = %q, want 200", status)
	}
	// Consume the rest of the response header block.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	// Now the tunnel is raw: write and read the echo.
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("write over tunnel: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "PING" {
		t.Fatalf("tunnel echo = %q, want PING", got)
	}
}

func TestDelHopHeaders(t *testing.T) {
	h := http.Header{
		"Connection":       {"X-Custom-Hop, Keep-Alive"},
		"X-Custom-Hop":     {"drop-me"},
		"Proxy-Connection": {"keep-alive"},
		"X-Keep":           {"survive"},
	}
	delHopHeaders(h)
	if h.Get("X-Custom-Hop") != "" {
		t.Errorf("Connection-listed header not dropped")
	}
	if h.Get("Proxy-Connection") != "" {
		t.Errorf("Proxy-Connection not dropped")
	}
	if h.Get("X-Keep") != "survive" {
		t.Errorf("end-to-end header wrongly dropped")
	}
}
