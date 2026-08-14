package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
	"github.com/fr34aky/fips-exit-gate/backend/store"
)

func makeLightning(t *testing.T, st *store.Store, npub string, pkgs []store.Package, hash string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := st.CreateAccount(ctx, npub); err != nil {
		t.Fatal(err)
	}
	pid, err := st.CreatePurchase(ctx, npub, pkgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AttachInvoice(ctx, pid, hash, "http://portal/pay/"+pid, "lnbc1..."); err != nil {
		t.Fatal(err)
	}
	return pid
}

func postPhoenix(t *testing.T, srvURL, secret, typ, hash string, tamper bool) int {
	t.Helper()
	body, _ := json.Marshal(payments.PhoenixEvent{Type: typ, PaymentHash: hash, AmountSat: 10000})
	sig := payments.SignPhoenixSig([]byte(secret), body)
	if tamper {
		sig = payments.SignPhoenixSig([]byte("wrong"), body)
	}
	req, _ := http.NewRequest("POST", srvURL+"/payments/phoenixd/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Phoenix-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestPhoenixdWebhookGrants(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}
	const secret = "whsec"
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	phx := &phoenixdHandler{store: st, secret: []byte(secret)}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, phx, nil, ""))
	defer srv.Close()

	pkgs, _ := st.ListPackages(ctx)
	_, npub, addr := newTestKey(t)
	pid := makeLightning(t, st, npub, pkgs, "ph_1")
	_ = pid

	// Bad signature grants nothing.
	if code := postPhoenix(t, srv.URL, secret, payments.EventPaymentReceived, "ph_1", true); code != http.StatusUnauthorized {
		t.Fatalf("tampered webhook = %d, want 401", code)
	}
	if full, _, _ := st.FullSet(ctx); hasAddr(full, addr) {
		t.Fatal("authorized by a tampered webhook")
	}

	// Valid payment_received -> access granted (Lightning is final on receipt).
	if code := postPhoenix(t, srv.URL, secret, payments.EventPaymentReceived, "ph_1", false); code != http.StatusOK {
		t.Fatalf("webhook = %d, want 200", code)
	}
	if full, _, _ := st.FullSet(ctx); !hasAddr(full, addr) {
		t.Fatal("not authorized after payment_received")
	}
	// Unknown payment hash is acked, not errored.
	if code := postPhoenix(t, srv.URL, secret, payments.EventPaymentReceived, "nope", false); code != http.StatusOK {
		t.Fatalf("unknown-hash webhook = %d, want 200", code)
	}
}

func TestReconcilerSettlesAndExpires(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}

	// Fake phoenixd: paid only for "paid_hash".
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/paid_hash") {
			json.NewEncoder(w).Encode(map[string]any{"isPaid": true, "receivedSat": 10000})
			return
		}
		http.NotFound(w, r)
	}))
	defer fake.Close()

	pkgs, _ := st.ListPackages(ctx)
	_, paidNpub, paidAddr := newTestKey(t)
	_, expNpub, expAddr := newTestKey(t)
	makeLightning(t, st, paidNpub, pkgs, "paid_hash")
	makeLightning(t, st, expNpub, pkgs, "unpaid_hash")

	// A negative TTL forces the unpaid invoice past expiry regardless of clock;
	// the paid one settles first (the paid branch wins).
	rec := &reconciler{store: st, ln: payments.NewPhoenixd(fake.URL, "pw", fake.Client()), ttl: -time.Hour}
	rec.sweep(ctx)

	full, _, _ := st.FullSet(ctx)
	if !hasAddr(full, paidAddr) {
		t.Fatal("paid purchase not settled by reconciler")
	}
	if hasAddr(full, expAddr) {
		t.Fatal("expired purchase should not be authorized")
	}
}

func TestBuyLightningRendersPayPage(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"amountSat": 10000, "paymentHash": "ph_buy", "serialized": "lnbc1buy..."})
	}))
	defer fake.Close()

	p := testPortal(t, st, false)
	p.pay = payments.NewPhoenixd(fake.URL, "pw", fake.Client())
	p.publicURL = "http://portal"
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar} // follow the redirect to /pay/{id}
	ownerPriv, _, _ := newTestKey(t)
	resp, _ := c.Get(srv.URL + "/auth/challenge")
	var ch struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()
	ev := signAuthEvent(t, ownerPriv, ch.Challenge)
	body, _ := json.Marshal(map[string]any{"event": ev})
	resp, _ = c.Post(srv.URL+"/auth/verify", "application/json", strings.NewReader(string(body)))
	resp.Body.Close()

	pkgs, _ := st.ListPackages(ctx)
	resp, err := c.PostForm(srv.URL+"/buy", url.Values{"package_id": {pkgs[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, "Pay with Lightning") || !strings.Contains(page, "lnbc1buy...") {
		t.Fatalf("pay page missing the BOLT11 (status %d):\n%s", resp.StatusCode, page)
	}
	if !strings.Contains(page, "data:image/png;base64,") {
		t.Errorf("pay page missing the QR code image")
	}
}

// A NUT-18 wallet POSTs a token to the cashu-receive transport (no session); we
// melt its proofs to the purchase's invoice.
func TestCashuReceiveMelts(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}
	pkgs, _ := st.ListPackages(ctx)

	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/melt/quote/bolt11":
			json.NewEncoder(w).Encode(map[string]any{"quote": "q", "amount": 2000, "fee_reserve": 10, "state": "UNPAID"})
		case "/v1/melt/bolt11":
			json.NewEncoder(w).Encode(map[string]any{"state": "PAID"})
		}
	}))
	defer mint.Close()

	p := testPortal(t, st, false)
	p.cashu = payments.NewCashuRedeemer(nil, mint.Client())
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()

	_, npub, _ := newTestKey(t)
	pid := makeLightning(t, st, npub, pkgs, "ph_cashu")

	payload, _ := json.Marshal(map[string]any{
		"mint": mint.URL, "unit": "sat",
		"proofs": []map[string]any{{"amount": 2100, "id": "009a1f293253e41e", "secret": "s", "C": "02aa"}},
	})
	resp, err := http.Post(srv.URL+"/pay/"+pid+"/cashu-receive", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cashu-receive status = %d, want 200", resp.StatusCode)
	}
}

// Regression: a rejected cashu-receive POST must answer with JSON, not a
// plain-text body. NUT-18 wallets JSON.parse the response, so a "bad payload"
// text body surfaces to the payer as "JSON Parse Error: Unexpected character: b".
func TestCashuReceiveErrorIsJSON(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}
	pkgs, _ := st.ListPackages(ctx)

	p := testPortal(t, st, false)
	p.cashu = payments.NewCashuRedeemer(nil, nil)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()

	_, npub, _ := newTestKey(t)
	pid := makeLightning(t, st, npub, pkgs, "ph_cashu_err")

	// A body that is neither a NUT-18 payload nor a decodable token.
	resp, err := http.Post(srv.URL+"/pay/"+pid+"/cashu-receive", "application/json",
		bytes.NewReader([]byte("bad payload not a token")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("cashu-receive accepted a bogus body (status %d)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 || body[0] != '{' {
		t.Fatalf("error response is not JSON (first byte %q): %s", firstByte(body), body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("error response does not parse as JSON: %v (body: %s)", err, body)
	}
	if _, ok := out["error"]; !ok {
		t.Fatalf("error response missing \"error\" key: %s", body)
	}
}

func firstByte(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b[:1])
}
