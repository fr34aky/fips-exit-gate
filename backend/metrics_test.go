package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsEndpoint(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	_, npub, _ := newTestKey(t)
	if err := st.CreditVolume(ctx, npub, 1_000_000, 30); err != nil { // creates account + entitlement + authz
		t.Fatal(err)
	}

	m := newAppMetrics(st)
	m.webhook.With("InvoiceSettled", "ok").Inc()
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	p := testPortal(t, st, false)

	// Open (no token) — content check.
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, m, ""))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("metrics status = %d", resp.StatusCode)
	}
	for _, want := range []string{
		"fipsexit_store_up 1",
		"fipsexit_authorized_addresses 1",
		`fipsexit_webhook_events_total{result="ok",type="InvoiceSettled"} 1`,
		"# TYPE fipsexit_goroutines gauge",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}

	// Token-gated.
	srv2 := httptest.NewServer(routes(h, p, st, "admintok", nil, m, "sekret"))
	defer srv2.Close()
	r1, _ := http.Get(srv2.URL + "/metrics")
	r1.Body.Close()
	if r1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token metrics = %d, want 401", r1.StatusCode)
	}
	req, _ := http.NewRequest("GET", srv2.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer sekret")
	r2, _ := http.DefaultClient.Do(req)
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("token metrics = %d, want 200", r2.StatusCode)
	}
}
