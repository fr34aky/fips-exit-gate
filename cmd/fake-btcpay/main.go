// Command fake-btcpay is a minimal BTCPay Server stand-in for developing and
// smoke-testing the fips-exit payment flow without a real BTCPay instance (the
// analogue of cmd/fake-backend for the agent).
//
// It implements just enough of the Greenfield API to create invoices, and it
// serves a tiny checkout page with buttons that fire the corresponding signed
// webhook at the backend:
//
//	Processing  -> optimistic unlock
//	Settled     -> confirm
//	Expired     -> revoke (unpaid)
//	Invalid     -> revoke
//
// Webhooks are signed with the same shared secret the backend verifies, so this
// exercises the real HMAC path end to end.
//
// Usage:
//
//	fake-btcpay -listen :9000 \
//	  -webhook-url http://localhost:8080/payments/btcpay/webhook \
//	  -secret whsec -base http://localhost:9000
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
)

type invoice struct {
	ID      string
	OrderID string
	Amount  string
	Status  string
}

type server struct {
	mu         sync.Mutex
	invoices   map[string]*invoice
	base       string
	webhookURL string
	secret     []byte
}

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	base := flag.String("base", "http://localhost:9000", "public base URL for checkout links")
	webhookURL := flag.String("webhook-url", "http://localhost:8080/payments/btcpay/webhook", "backend webhook endpoint")
	secret := flag.String("secret", "whsec", "webhook signing secret (must match backend BTCPAY_WEBHOOK_SECRET)")
	flag.Parse()

	s := &server{
		invoices:   map[string]*invoice{},
		base:       *base,
		webhookURL: *webhookURL,
		secret:     []byte(*secret),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/stores/{store}/invoices", s.createInvoice)
	mux.HandleFunc("GET /i/{id}", s.checkoutPage)
	mux.HandleFunc("POST /sim/{id}/{type}", s.simulate)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "fake-btcpay: POST /api/v1/stores/{store}/invoices, GET /i/{id}, POST /sim/{id}/{type}\n")
	})

	log.Printf("fake-btcpay listening on %s (base=%s) -> webhooks to %s", *listen, *base, *webhookURL)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func (s *server) createInvoice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Amount   string         `json:"amount"`
		Currency string         `json:"currency"`
		Metadata map[string]any `json:"metadata"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := "inv_" + randHex(8)
	order, _ := req.Metadata["orderId"].(string)
	inv := &invoice{ID: id, OrderID: order, Amount: req.Amount, Status: "New"}
	s.mu.Lock()
	s.invoices[id] = inv
	s.mu.Unlock()

	log.Printf("created invoice %s amount=%s %s order=%s", id, req.Amount, req.Currency, order)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":           id,
		"checkoutLink": s.base + "/i/" + id,
		"status":       "New",
	})
}

func (s *server) checkoutPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	inv := s.invoices[id]
	s.mu.Unlock()
	if inv == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>fake-btcpay checkout</title>
<body style="font-family:system-ui;max-width:32rem;margin:3rem auto">
<h1>fake-btcpay</h1>
<p>Invoice <code>%s</code> — <strong>%s BTC</strong> — status <strong>%s</strong></p>
<p>Simulate a payment lifecycle event (fires a signed webhook at the backend):</p>
<form method=post action="/sim/%s/InvoiceProcessing"><button>Payment detected (Processing)</button></form>
<form method=post action="/sim/%s/InvoiceSettled" style=margin-top:.5rem><button>Confirmed (Settled)</button></form>
<form method=post action="/sim/%s/InvoiceExpired" style=margin-top:.5rem><button>Expired (unpaid)</button></form>
<form method=post action="/sim/%s/InvoiceInvalid" style=margin-top:.5rem><button>Invalid</button></form>
</body>`, inv.ID, inv.Amount, inv.Status, id, id, id, id)
}

func (s *server) simulate(w http.ResponseWriter, r *http.Request) {
	id, typ := r.PathValue("id"), r.PathValue("type")
	s.mu.Lock()
	inv := s.invoices[id]
	if inv != nil {
		inv.Status = typ
	}
	s.mu.Unlock()
	if inv == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.fireWebhook(typ, id); err != nil {
		http.Error(w, "webhook failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	// If the checkout page triggered this, send them back to it.
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" || r.Header.Get("Accept") != "" {
		http.Redirect(w, r, "/i/"+id, http.StatusSeeOther)
		return
	}
	fmt.Fprintf(w, "fired %s for %s\n", typ, id)
}

func (s *server) fireWebhook(typ, invoiceID string) error {
	ev := payments.WebhookEvent{
		DeliveryID: randHex(6),
		WebhookID:  "wh_fake",
		Type:       typ,
		StoreID:    "STORE1",
		InvoiceID:  invoiceID,
	}
	body, _ := json.Marshal(ev)
	req, err := http.NewRequest(http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("BTCPay-Sig", payments.SignWebhook(s.secret, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Printf("webhook %s invoice=%s -> %s", typ, invoiceID, resp.Status)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backend returned %s", resp.Status)
	}
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
