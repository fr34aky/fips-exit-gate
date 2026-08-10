package payments

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elnosh/gonuts/cashu"
	"github.com/fxamacker/cbor/v2"
)

// fakeMint answers the NUT-05 melt endpoints: a quote for 2000 sat + feeReserve,
// and a PAID melt.
func fakeMint(feeReserve uint64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/melt/quote/bolt11":
			json.NewEncoder(w).Encode(map[string]any{"quote": "q1", "amount": 2000, "fee_reserve": feeReserve, "state": "UNPAID"})
		case "/v1/melt/bolt11":
			json.NewEncoder(w).Encode(map[string]any{"state": "PAID"})
		default:
			http.NotFound(w, r)
		}
	}))
}

func cashuToken(t *testing.T, mint string, amount uint64) string {
	t.Helper()
	proofs := cashu.Proofs{{Amount: amount, Id: "009a1f293253e41e", Secret: "test-secret", C: "02aabbcc"}}
	tok, err := cashu.NewTokenV3(proofs, mint, cashu.Sat, false)
	if err != nil {
		t.Fatal(err)
	}
	s, err := tok.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCashuMelt(t *testing.T) {
	srv := fakeMint(50)
	defer srv.Close()
	c := NewCashuRedeemer(nil, srv.Client())
	got, err := c.Melt(context.Background(), cashuToken(t, srv.URL, 2100), "lnbc2u...")
	if err != nil {
		t.Fatalf("melt: %v", err)
	}
	if got != 2000 {
		t.Fatalf("landed = %d, want 2000", got)
	}
}

func TestCashuMeltUnderfunded(t *testing.T) {
	srv := fakeMint(50)
	defer srv.Close()
	c := NewCashuRedeemer(nil, srv.Client())
	// 2000 < 2000 + 50 fee reserve.
	if _, err := c.Melt(context.Background(), cashuToken(t, srv.URL, 2000), "lnbc2u..."); !errors.Is(err, ErrTokenUnderfunded) {
		t.Fatalf("want ErrTokenUnderfunded, got %v", err)
	}
}

func TestCashuMeltMintNotAccepted(t *testing.T) {
	srv := fakeMint(50)
	defer srv.Close()
	c := NewCashuRedeemer([]string{"https://other.example"}, srv.Client())
	if _, err := c.Melt(context.Background(), cashuToken(t, srv.URL, 2100), "lnbc2u..."); !errors.Is(err, ErrMintNotAccepted) {
		t.Fatalf("want ErrMintNotAccepted, got %v", err)
	}
}

func TestCashuPaymentRequest(t *testing.T) {
	c := NewCashuRedeemer([]string{"https://mint.example/"}, nil)
	req, err := c.PaymentRequest(2000, "http://portal.fips:8080/pay/abc/cashu-receive")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req, "creqA") {
		t.Fatalf("want creqA prefix, got %q", req)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(req, "creqA"))
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	var got nut18Request
	if err := cbor.Unmarshal(raw, &got); err != nil {
		t.Fatalf("cbor: %v", err)
	}
	if got.Amount != 2000 || got.Unit != "sat" || !got.SingleUse {
		t.Fatalf("request fields: %+v", got)
	}
	if len(got.Transports) != 1 || got.Transports[0].Type != "post" ||
		got.Transports[0].Target != "http://portal.fips:8080/pay/abc/cashu-receive" {
		t.Fatalf("transport: %+v", got.Transports)
	}
	if len(got.Mints) != 1 || got.Mints[0] != "https://mint.example" {
		t.Fatalf("mints: %+v", got.Mints)
	}
}
