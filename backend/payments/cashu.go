package payments

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/elnosh/gonuts/cashu"
	"github.com/fxamacker/cbor/v2"
)

// CashuRedeemer accepts Cashu ecash and melts it at the token's OWN mint (NUT-05)
// to pay a given BOLT11 — the "accept-and-melt" rail layered on phoenixd. No
// custody: we grant only on the resulting Lightning receipt into our node, so a
// mint that won't melt just yields a failed payment (no grant, no loss). The
// buyer's proofs are spent atomically by the mint on a successful melt.
//
// Two ways in: a pasted token (Melt), or a NUT-18 payment request the buyer's
// wallet scans and posts back (PaymentRequest + MeltProofs).
// See docs/design/cashu-accept-and-melt.md.
type CashuRedeemer struct {
	accepted map[string]bool // optional mint allowlist; empty = accept any mint
	hc       *http.Client
}

// NewCashuRedeemer builds a redeemer. acceptedMints is an optional allowlist of
// mint base URLs; empty means accept a token from any mint (safe here, since
// access is granted only on realized receipt).
func NewCashuRedeemer(acceptedMints []string, hc *http.Client) *CashuRedeemer {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	m := map[string]bool{}
	for _, u := range acceptedMints {
		if u = normalizeMint(u); u != "" {
			m[u] = true
		}
	}
	return &CashuRedeemer{accepted: m, hc: hc}
}

var (
	// ErrMintNotAccepted means the token's mint is not in the allowlist.
	ErrMintNotAccepted = errors.New("payments: cashu mint not accepted")
	// ErrTokenUnderfunded means the proofs can't cover the invoice plus fees.
	ErrTokenUnderfunded = errors.New("payments: cashu token does not cover invoice + fees")
)

func normalizeMint(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

type meltQuoteResp struct {
	Quote      string `json:"quote"`
	Amount     uint64 `json:"amount"`
	FeeReserve uint64 `json:"fee_reserve"`
	State      string `json:"state"`
	Paid       bool   `json:"paid"` // legacy pre-state field
}

type meltResp struct {
	State string `json:"state"`
	Paid  bool   `json:"paid"` // legacy pre-state field
}

// Melt decodes a serialized Cashu token and melts its proofs to pay bolt11.
func (c *CashuRedeemer) Melt(ctx context.Context, token, bolt11 string) (uint64, error) {
	tok, err := cashu.DecodeToken(strings.TrimSpace(token))
	if err != nil {
		return 0, fmt.Errorf("payments: decode cashu token: %w", err)
	}
	return c.MeltProofs(ctx, tok.Mint(), tok.Proofs(), bolt11)
}

// MeltProofs melts the given proofs at `mint` to pay bolt11, returning the sats
// that will land (the invoice amount). Any overpayment above amount+fee_reserve
// is forfeited to the mint (no change is requested — a v1 cut), so callers should
// tell buyers to present proofs sized to the package price.
func (c *CashuRedeemer) MeltProofs(ctx context.Context, mint string, proofs cashu.Proofs, bolt11 string) (uint64, error) {
	mint = normalizeMint(mint)
	if len(c.accepted) > 0 && !c.accepted[mint] {
		return 0, ErrMintNotAccepted
	}

	// 1. Ask the mint for a melt quote for our invoice.
	var q meltQuoteResp
	if err := c.post(ctx, mint+"/v1/melt/quote/bolt11",
		map[string]string{"request": bolt11, "unit": "sat"}, &q); err != nil {
		return 0, fmt.Errorf("payments: cashu melt quote: %w", err)
	}
	if need := q.Amount + q.FeeReserve; proofs.Amount() < need {
		return 0, fmt.Errorf("%w: have %d sat, need %d", ErrTokenUnderfunded, proofs.Amount(), need)
	}

	// 2. Melt: hand the proofs to the mint, which pays our invoice.
	var m meltResp
	if err := c.post(ctx, mint+"/v1/melt/bolt11",
		map[string]any{"quote": q.Quote, "inputs": proofs}, &m); err != nil {
		return 0, fmt.Errorf("payments: cashu melt: %w", err)
	}
	// UNPAID = the mint could not pay (proofs returned); anything else (PAID, or
	// PENDING = in flight) means it was initiated — the real grant is gated on our
	// phoenixd receiving it, so optimistic here is safe.
	if !m.Paid && strings.EqualFold(m.State, "UNPAID") {
		return 0, fmt.Errorf("payments: cashu melt not paid (state=%q)", m.State)
	}
	return q.Amount, nil
}

// --- NUT-18 payment request (a QR the buyer's Cashu wallet scans to pay) ---

type prTransport struct {
	Type   string `cbor:"t"`
	Target string `cbor:"a"`
}

type nut18Request struct {
	Amount     uint64        `cbor:"a,omitempty"`
	Unit       string        `cbor:"u,omitempty"`
	SingleUse  bool          `cbor:"s,omitempty"`
	Mints      []string      `cbor:"m,omitempty"`
	Transports []prTransport `cbor:"t,omitempty"`
}

// PaymentRequest builds a NUT-18 payment request (creqA…) for amountSat that asks
// the payer's wallet to POST the token to postTarget. Wallets that support NUT-18
// can scan it; others fall back to the paste box.
func (c *CashuRedeemer) PaymentRequest(amountSat uint64, postTarget string) (string, error) {
	req := nut18Request{
		Amount: amountSat, Unit: "sat", SingleUse: true,
		Transports: []prTransport{{Type: "post", Target: postTarget}},
	}
	for m := range c.accepted {
		req.Mints = append(req.Mints, m)
	}
	b, err := cbor.Marshal(req)
	if err != nil {
		return "", err
	}
	return "creqA" + base64.RawURLEncoding.EncodeToString(b), nil
}

// PaymentRequestPayload is the NUT-18 body a wallet POSTs to the transport target.
type PaymentRequestPayload struct {
	ID     string       `json:"id"`
	Memo   string       `json:"memo"`
	Mint   string       `json:"mint"`
	Unit   string       `json:"unit"`
	Proofs cashu.Proofs `json:"proofs"`
}

func (c *CashuRedeemer) post(ctx context.Context, url string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Detail string `json:"detail"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("mint HTTP %d: %s", resp.StatusCode, e.Detail)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
