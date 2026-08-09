// Package payments integrates the fips-exit backend with a self-hosted BTCPay
// Server over its Greenfield API: it creates an invoice per package purchase
// and verifies the signed webhooks BTCPay sends on invoice state changes.
//
// Invoices are denominated in BTC for the package's sats price; BTCPay offers
// BTC on-chain, Lightning, and Monero (via its rate provider) as payment
// methods. The webhook drives the purchase lifecycle in the store:
//
//	InvoiceProcessing -> GrantByInvoice(confirmed=false)  (optimistic unlock)
//	InvoiceSettled    -> GrantByInvoice(confirmed=true)   (confirm)
//	InvoiceInvalid    -> VoidByInvoice("invalid")         (revoke)
//	InvoiceExpired    -> VoidByInvoice("expired")         (revoke)
package payments

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BTCPay webhook event types we act on (a subset of the Greenfield set).
const (
	EventInvoiceProcessing = "InvoiceProcessing"
	EventInvoiceSettled    = "InvoiceSettled"
	EventInvoiceInvalid    = "InvoiceInvalid"
	EventInvoiceExpired    = "InvoiceExpired"
)

// msatPerBTC is 1e8 sats * 1e3 msat/sat.
const msatPerBTC = 100_000_000_000

// Client talks to a BTCPay store's Greenfield API.
type Client struct {
	baseURL string // e.g. https://btcpay.example.onion
	apiKey  string // Greenfield API key (store-scoped, CanCreateInvoice)
	storeID string
	hc      *http.Client
}

// NewClient builds a BTCPay Greenfield client. hc may be nil (a client with a
// sane timeout is used); pass a Tor-dialing http.Client to reach an onion.
func NewClient(baseURL, apiKey, storeID string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		storeID: storeID,
		hc:      hc,
	}
}

// InvoiceRequest is the portal's ask: charge PriceMsat worth of BTC for the
// purchase identified by OrderID, redirecting the buyer to RedirectURL after.
type InvoiceRequest struct {
	PriceMsat   int64
	OrderID     string // our purchase id — echoed back in webhook metadata
	Description string
	RedirectURL string
}

// Invoice is the created BTCPay invoice.
type Invoice struct {
	ID           string `json:"id"`
	CheckoutLink string `json:"checkoutLink"`
	Status       string `json:"status"`
}

// btcAmount formats msat as a BTC decimal string (8 dp — the on-chain unit).
func btcAmount(msat int64) string {
	whole := msat / msatPerBTC
	frac := msat % msatPerBTC
	sats := frac / 1000 // msat -> sats within the fractional BTC
	return fmt.Sprintf("%d.%08d", whole, sats)
}

// CreateInvoice posts a new invoice to the store and returns it.
func (c *Client) CreateInvoice(ctx context.Context, req InvoiceRequest) (Invoice, error) {
	body := map[string]any{
		"amount":   btcAmount(req.PriceMsat),
		"currency": "BTC",
		"metadata": map[string]any{
			"orderId":     req.OrderID,
			"itemDesc":    req.Description,
			"buyerFips":   req.OrderID, // no PII; the purchase id is the anchor
			"purchase_id": req.OrderID,
		},
		"checkout": map[string]any{
			"redirectURL":           req.RedirectURL,
			"redirectAutomatically": true,
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return Invoice{}, err
	}
	url := c.baseURL + "/api/v1/stores/" + c.storeID + "/invoices"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return Invoice{}, err
	}
	httpReq.Header.Set("Authorization", "token "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(httpReq)
	if err != nil {
		return Invoice{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Invoice{}, fmt.Errorf("btcpay: create invoice: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	var inv Invoice
	if err := json.Unmarshal(respBody, &inv); err != nil {
		return Invoice{}, fmt.Errorf("btcpay: decode invoice: %w", err)
	}
	if inv.ID == "" {
		return Invoice{}, fmt.Errorf("btcpay: invoice response missing id")
	}
	return inv, nil
}

// WebhookEvent is the JSON body BTCPay POSTs to the webhook endpoint.
type WebhookEvent struct {
	DeliveryID string `json:"deliveryId"`
	WebhookID  string `json:"webhookId"`
	Type       string `json:"type"`
	Timestamp  int64  `json:"timestamp"`
	StoreID    string `json:"storeId"`
	InvoiceID  string `json:"invoiceId"`
}

// VerifyWebhook checks the BTCPay-Sig header ("sha256=<hex>") against an
// HMAC-SHA256 of the raw request body keyed by the webhook secret.
func VerifyWebhook(secret, body []byte, sigHeader string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(sigHeader, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

// SignWebhook returns the BTCPay-Sig header value for a body (used by tests and
// cmd/fake-btcpay).
func SignWebhook(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// SatsFromMsat is a small helper for display/logging.
func SatsFromMsat(msat int64) string { return strconv.FormatInt(msat/1000, 10) }
