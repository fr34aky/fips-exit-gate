package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
)

// postWebhook fires a signed BTCPay webhook at the backend and returns the status.
func postWebhook(t *testing.T, srvURL, secret, typ, invoiceID string, tamper bool) int {
	t.Helper()
	body, _ := json.Marshal(payments.WebhookEvent{Type: typ, InvoiceID: invoiceID, StoreID: "STORE1"})
	sig := payments.SignWebhook([]byte(secret), body)
	if tamper {
		sig = payments.SignWebhook([]byte("wrong-secret"), body)
	}
	req, _ := http.NewRequest("POST", srvURL+"/payments/btcpay/webhook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("BTCPay-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestWebhookDrivesAuthz(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}
	const secret = "whsec"
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	ph := &payHandler{store: st, secret: []byte(secret)}
	srv := httptest.NewServer(routes(h, p, st, "admintok", ph))
	defer srv.Close()

	_, npub, addr := newTestKey(t)
	if _, err := st.CreateAccount(ctx, npub); err != nil {
		t.Fatal(err)
	}
	pkgs, _ := st.ListPackages(ctx)
	pid, err := st.CreatePurchase(ctx, npub, pkgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AttachInvoice(ctx, pid, "inv_wh", "http://checkout/inv_wh"); err != nil {
		t.Fatal(err)
	}

	// Bad signature is rejected and grants nothing.
	if code := postWebhook(t, srv.URL, secret, payments.EventInvoiceProcessing, "inv_wh", true); code != http.StatusUnauthorized {
		t.Fatalf("tampered webhook status = %d, want 401", code)
	}
	if full, _, _ := st.FullSet(ctx); hasAddr(full, addr) {
		t.Fatal("authorized by a tampered webhook")
	}

	// Valid Processing records the payment as SEEN but must NOT authorize — an
	// on-chain 0-conf payment is reversible, so access waits for settlement.
	if code := postWebhook(t, srv.URL, secret, payments.EventInvoiceProcessing, "inv_wh", false); code != http.StatusOK {
		t.Fatalf("processing webhook status = %d, want 200", code)
	}
	if full, _, _ := st.FullSet(ctx); hasAddr(full, addr) {
		t.Fatal("authorized on unconfirmed Processing webhook (must wait for settle)")
	}

	// Settled -> payment final -> access granted.
	if code := postWebhook(t, srv.URL, secret, payments.EventInvoiceSettled, "inv_wh", false); code != http.StatusOK {
		t.Fatalf("settled webhook status = %d, want 200", code)
	}
	if full, _, _ := st.FullSet(ctx); !hasAddr(full, addr) {
		t.Fatal("not authorized after Settled webhook")
	}

	// An unknown invoice is acked (200), not errored.
	if code := postWebhook(t, srv.URL, secret, payments.EventInvoiceSettled, "does-not-exist", false); code != http.StatusOK {
		t.Fatalf("unknown-invoice webhook status = %d, want 200", code)
	}
}

// TestBuyCreatesInvoice drives the portal /buy through a fake BTCPay endpoint,
// asserting an invoice is created, attached, and the buyer is redirected to it.
func TestBuyCreatesInvoice(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}

	// Fake BTCPay: returns a canned invoice for any create request.
	var created bool
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		created = true
		json.NewEncoder(w).Encode(map[string]any{
			"id": "inv_buy", "checkoutLink": "http://checkout/inv_buy", "status": "New",
		})
	}))
	defer fake.Close()

	p := testPortal(t, st, false)
	p.pay = payments.NewClient(fake.URL, "k", "STORE1", fake.Client())
	p.publicURL = "http://portal"
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	// Don't follow the final redirect to the (external) checkout link.
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	ownerPriv, ownerNpub, _ := newTestKey(t)
	// Log in.
	resp, _ := c.Get(srv.URL + "/auth/challenge")
	var ch struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()
	ev := signAuthEvent(t, ownerPriv, ch.Challenge)
	body, _ := json.Marshal(map[string]any{"event": ev})
	resp, _ = c.Post(srv.URL+"/auth/verify", "application/json", strings.NewReader(string(body)))
	resp.Body.Close()

	// Buy: expect a redirect to the checkout link.
	pkgs, _ := st.ListPackages(ctx)
	resp, err := c.PostForm(srv.URL+"/buy", url.Values{"package_id": {pkgs[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("buy status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "http://checkout/inv_buy" {
		t.Fatalf("redirect Location = %q, want checkout link", loc)
	}
	if !created {
		t.Fatal("BTCPay invoice was not created")
	}

	// The purchase is pending with the checkout link attached (set by AttachInvoice).
	open, err := st.OpenPurchases(ctx, ownerNpub)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Status != "pending" || open[0].CheckoutURL != "http://checkout/inv_buy" {
		t.Fatalf("open purchase = %+v, want one pending with the checkout link", open)
	}
}
