package payments

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBTCAmount(t *testing.T) {
	cases := []struct {
		msat int64
		want string
	}{
		{70_000_000, "0.00070000"},              // 70k sats
		{100_000_000_000, "1.00000000"},         // 1 BTC
		{100_000_000_000 + 1_000, "1.00000001"}, // 1 BTC + 1 sat
		{5_000_000, "0.00005000"},               // 5k sats
		{0, "0.00000000"},
	}
	for _, c := range cases {
		if got := btcAmount(c.msat); got != c.want {
			t.Errorf("btcAmount(%d) = %q, want %q", c.msat, got, c.want)
		}
	}
}

func TestCreateInvoice(t *testing.T) {
	var gotPath, gotAuth, gotAmount, gotCurrency, gotOrder, gotRedirect string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Amount   string         `json:"amount"`
			Currency string         `json:"currency"`
			Metadata map[string]any `json:"metadata"`
			Checkout map[string]any `json:"checkout"`
		}
		json.Unmarshal(body, &req)
		gotAmount, gotCurrency = req.Amount, req.Currency
		gotOrder, _ = req.Metadata["orderId"].(string)
		gotRedirect, _ = req.Checkout["redirectURL"].(string)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "inv_abc", "checkoutLink": srv0(r) + "/i/inv_abc", "status": "New",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "APIKEY", "STORE1", srv.Client())
	inv, err := c.CreateInvoice(context.Background(), InvoiceRequest{
		PriceMsat: 70_000_000, OrderID: "purch-1", Description: "50 GB", RedirectURL: "https://portal/dashboard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if inv.ID != "inv_abc" {
		t.Errorf("invoice id = %q", inv.ID)
	}
	if gotPath != "/api/v1/stores/STORE1/invoices" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "token APIKEY" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotAmount != "0.00070000" || gotCurrency != "BTC" {
		t.Errorf("amount/currency = %q/%q", gotAmount, gotCurrency)
	}
	if gotOrder != "purch-1" {
		t.Errorf("orderId = %q", gotOrder)
	}
	if gotRedirect != "https://portal/dashboard" {
		t.Errorf("redirect = %q", gotRedirect)
	}
}

func TestCreateInvoiceError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "bad", "STORE1", srv.Client())
	if _, err := c.CreateInvoice(context.Background(), InvoiceRequest{PriceMsat: 1000}); err == nil {
		t.Fatal("expected error on non-2xx")
	}
}

func TestVerifyWebhook(t *testing.T) {
	secret := []byte("whsec")
	body := []byte(`{"type":"InvoiceSettled","invoiceId":"inv_abc"}`)
	sig := SignWebhook(secret, body)

	if !VerifyWebhook(secret, body, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyWebhook(secret, append(body, 'x'), sig) {
		t.Fatal("tampered body accepted")
	}
	if VerifyWebhook([]byte("wrong"), body, sig) {
		t.Fatal("wrong secret accepted")
	}
	if VerifyWebhook(secret, body, "md5=deadbeef") {
		t.Fatal("bad prefix accepted")
	}
	if VerifyWebhook(secret, body, "sha256=nothex") {
		t.Fatal("non-hex accepted")
	}
	// Fail-safe: an empty secret can never verify, even against a MAC computed
	// with an empty key (guards a misconfigured backend against forged webhooks).
	if VerifyWebhook(nil, body, SignWebhook(nil, body)) {
		t.Fatal("empty secret verified a webhook")
	}
}

// srv0 returns the test server's base URL from the request host.
func srv0(r *http.Request) string { return "http://" + r.Host }
