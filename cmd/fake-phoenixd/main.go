// Command fake-phoenixd is a minimal phoenixd (ACINQ Lightning) stand-in for
// developing and testing the fips-exit Lightning payment flow without a real
// node — the Lightning analogue of cmd/fake-btcpay.
//
// It implements just enough of the phoenixd HTTP API — POST /createinvoice and
// GET /payments/incoming/{hash} — plus POST /sim/{hash}/pay which marks an
// invoice paid and fires the signed payment_received webhook at the backend.
//
// Usage:
//
//	fake-phoenixd -listen :9740 \
//	  -webhook-url http://127.0.0.1:8080/payments/phoenixd/webhook -secret whsec
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
	Hash       string
	ExternalID string
	AmountSat  int64
	Paid       bool
}

type server struct {
	mu         sync.Mutex
	inv        map[string]*invoice
	webhookURL string
	secret     []byte
}

func main() {
	listen := flag.String("listen", ":9740", "listen address")
	webhookURL := flag.String("webhook-url", "http://127.0.0.1:8080/payments/phoenixd/webhook", "backend webhook endpoint")
	secret := flag.String("secret", "whsec", "webhook signing secret (must match backend PHOENIXD_WEBHOOK_SECRET)")
	flag.Parse()

	s := &server{inv: map[string]*invoice{}, webhookURL: *webhookURL, secret: []byte(*secret)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /createinvoice", s.createInvoice)
	mux.HandleFunc("GET /payments/incoming/{hash}", s.lookup)
	mux.HandleFunc("POST /sim/{hash}/pay", s.simPay)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "fake-phoenixd: POST /createinvoice, GET /payments/incoming/{hash}, POST /sim/{hash}/pay\n")
	})
	log.Printf("fake-phoenixd listening on %s -> webhooks to %s", *listen, *webhookURL)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func (s *server) createInvoice(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	amount, _ := parseInt(r.FormValue("amountSat"))
	hash := randHex(16)
	inv := &invoice{Hash: hash, ExternalID: r.FormValue("externalId"), AmountSat: amount}
	s.mu.Lock()
	s.inv[hash] = inv
	s.mu.Unlock()
	log.Printf("created invoice %s amountSat=%d externalId=%s", hash, amount, inv.ExternalID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"amountSat": amount, "paymentHash": hash, "serialized": "lnbcrt-fake-" + hash,
	})
}

func (s *server) lookup(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	inv := s.inv[r.PathValue("hash")]
	s.mu.Unlock()
	if inv == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"isPaid": inv.Paid, "receivedSat": paidSat(inv), "amountSat": inv.AmountSat})
}

func (s *server) simPay(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	s.mu.Lock()
	inv := s.inv[hash]
	if inv != nil {
		inv.Paid = true
	}
	s.mu.Unlock()
	if inv == nil {
		http.NotFound(w, r)
		return
	}
	if err := s.fireWebhook(inv); err != nil {
		http.Error(w, "webhook failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	fmt.Fprintf(w, "paid %s\n", hash)
}

func (s *server) fireWebhook(inv *invoice) error {
	body, _ := json.Marshal(payments.PhoenixEvent{
		Type: payments.EventPaymentReceived, AmountSat: inv.AmountSat,
		PaymentHash: inv.Hash, ExternalID: inv.ExternalID,
	})
	req, err := http.NewRequest(http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Phoenix-Signature", payments.SignPhoenixSig(s.secret, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Printf("webhook payment_received %s -> %s", inv.Hash, resp.Status)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backend returned %s", resp.Status)
	}
	return nil
}

func paidSat(inv *invoice) int64 {
	if inv.Paid {
		return inv.AmountSat
	}
	return 0
}

func parseInt(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
