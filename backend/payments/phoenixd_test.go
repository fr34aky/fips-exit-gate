package payments

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPhoenixdCreateInvoice(t *testing.T) {
	var gotPath, gotAuth, gotAmount, gotExternal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, gotAuth, _ = r.BasicAuth() // returns (user, pass, ok); grab pass below
		r.ParseForm()
		gotAmount = r.FormValue("amountSat")
		gotExternal = r.FormValue("externalId")
		json.NewEncoder(w).Encode(map[string]any{
			"amountSat": 10000, "paymentHash": "ph_abc", "serialized": "lnbc100...",
		})
	}))
	defer srv.Close()

	c := NewPhoenixd(srv.URL, "hunter2", srv.Client())
	inv, err := c.CreateInvoice(context.Background(), InvoiceRequest{PriceMsat: 10_000_000, OrderID: "purch-1", Description: "10 GB"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.ID != "ph_abc" || inv.Bolt11 != "lnbc100..." {
		t.Fatalf("invoice = %+v", inv)
	}
	if gotPath != "/createinvoice" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "hunter2" {
		t.Errorf("basic-auth password = %q", gotAuth)
	}
	if gotAmount != "10000" { // 10_000_000 msat -> 10000 sat
		t.Errorf("amountSat = %q", gotAmount)
	}
	if gotExternal != "purch-1" {
		t.Errorf("externalId = %q", gotExternal)
	}
}

func TestPhoenixdLookupIncoming(t *testing.T) {
	var paid bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !paid {
			http.NotFound(w, r) // not seen yet
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"isPaid": true, "receivedSat": 10000, "completedAt": 1700000000})
	}))
	defer srv.Close()
	c := NewPhoenixd(srv.URL, "pw", srv.Client())

	if got, err := c.LookupIncoming(context.Background(), "ph_abc"); err != nil || got {
		t.Fatalf("before payment: paid=%v err=%v, want false/nil", got, err)
	}
	paid = true
	if got, err := c.LookupIncoming(context.Background(), "ph_abc"); err != nil || !got {
		t.Fatalf("after payment: paid=%v err=%v, want true/nil", got, err)
	}
}

func TestVerifyPhoenixSig(t *testing.T) {
	secret := []byte("whsec")
	body := []byte(`{"type":"payment_received","paymentHash":"ph_abc"}`)
	sig := SignPhoenixSig(secret, body)

	if !VerifyPhoenixSig(secret, body, sig) {
		t.Fatal("valid signature rejected")
	}
	if !VerifyPhoenixSig(secret, body, "sha256="+sig) {
		t.Fatal("prefixed signature rejected")
	}
	if VerifyPhoenixSig(secret, append(body, 'x'), sig) {
		t.Fatal("tampered body accepted")
	}
	if VerifyPhoenixSig(nil, body, SignPhoenixSig(nil, body)) {
		t.Fatal("empty secret verified")
	}
	if VerifyPhoenixSig(secret, body, "nothex") {
		t.Fatal("non-hex accepted")
	}
}
