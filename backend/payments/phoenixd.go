package payments

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Phoenixd talks to a phoenixd (ACINQ) Lightning node's HTTP API. phoenixd is a
// self-custodial single binary with automated channel management (ACINQ acts as
// LSP), so there is no bitcoind/channel ops. Auth is HTTP basic: empty username
// plus the node's http-password.
//
// It implements Provider. Because a raw Lightning node has no BTCPay-style
// settlement state machine, settlement is delivered two ways (see the backend
// wiring): a payment_received webhook for speed, and a reconciler that polls
// LookupIncoming so a missed webhook still settles and unpaid invoices expire.
type Phoenixd struct {
	baseURL  string
	password string
	hc       *http.Client
}

// NewPhoenixd builds a phoenixd client. hc may be nil (a client with a sane
// timeout is used); pass a Tor-dialing http.Client to reach an onion.
func NewPhoenixd(baseURL, password string, hc *http.Client) *Phoenixd {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Phoenixd{baseURL: strings.TrimRight(baseURL, "/"), password: password, hc: hc}
}

// CreateInvoice creates a BOLT11 invoice for the purchase. externalId carries
// our purchase id back on the webhook; the returned Invoice.ID is the payment
// hash (the key the store settlement seam uses).
func (p *Phoenixd) CreateInvoice(ctx context.Context, req InvoiceRequest) (Invoice, error) {
	form := url.Values{}
	form.Set("amountSat", strconv.FormatInt(req.PriceMsat/1000, 10))
	form.Set("description", req.Description)
	form.Set("externalId", req.OrderID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/createinvoice", strings.NewReader(form.Encode()))
	if err != nil {
		return Invoice{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.SetBasicAuth("", p.password)

	resp, err := p.hc.Do(httpReq)
	if err != nil {
		return Invoice{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Invoice{}, fmt.Errorf("phoenixd: create invoice: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		AmountSat   int64  `json:"amountSat"`
		PaymentHash string `json:"paymentHash"`
		Serialized  string `json:"serialized"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return Invoice{}, fmt.Errorf("phoenixd: decode invoice: %w", err)
	}
	if out.PaymentHash == "" || out.Serialized == "" {
		return Invoice{}, fmt.Errorf("phoenixd: invoice response missing paymentHash/serialized")
	}
	return Invoice{ID: out.PaymentHash, Bolt11: out.Serialized, Status: "New"}, nil
}

// LookupIncoming reports whether the invoice for paymentHash has been paid.
// A 404 (not seen yet) is reported as not-paid without error.
func (p *Phoenixd) LookupIncoming(ctx context.Context, paymentHash string) (paid bool, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/payments/incoming/"+url.PathEscape(paymentHash), nil)
	if err != nil {
		return false, err
	}
	httpReq.SetBasicAuth("", p.password)

	resp, err := p.hc.Do(httpReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("phoenixd: lookup: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		IsPaid      bool  `json:"isPaid"`
		ReceivedSat int64 `json:"receivedSat"`
		CompletedAt int64 `json:"completedAt"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return false, fmt.Errorf("phoenixd: decode lookup: %w", err)
	}
	return out.IsPaid || out.CompletedAt > 0 || out.ReceivedSat > 0, nil
}

// EventPaymentReceived is phoenixd's incoming-payment webhook type.
const EventPaymentReceived = "payment_received"

// PhoenixEvent is the webhook body phoenixd POSTs on a payment event.
type PhoenixEvent struct {
	Type        string `json:"type"`
	AmountSat   int64  `json:"amountSat"`
	PaymentHash string `json:"paymentHash"`
	ExternalID  string `json:"externalId"`
	Timestamp   int64  `json:"timestamp"`
}

// VerifyPhoenixSig verifies a phoenixd webhook: HMAC-SHA256 (hex) over the raw
// body, from the X-Phoenix-Signature header (an optional "sha256=" prefix is
// tolerated). An empty secret never verifies. The reconciler is the safety net
// if a version signs differently — payments still settle by polling.
func VerifyPhoenixSig(secret, body []byte, sigHeader string) bool {
	if len(secret) == 0 {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(sigHeader), "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

// SignPhoenixSig returns the hex HMAC for a body (tests / cmd/fake-phoenixd).
func SignPhoenixSig(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
