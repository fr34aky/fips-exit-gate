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

func TestMeltAmount(t *testing.T) {
	for _, c := range []struct{ in, want uint64 }{
		{2000, 2020}, // 1% = 20
		{150, 152},   // ceil(1.5) -> 2
		{50, 51},     // ceil(0.5) -> 1
		{100, 101},
		{0, 0},
	} {
		if got := MeltAmount(c.in); got != c.want {
			t.Errorf("MeltAmount(%d) = %d, want %d", c.in, got, c.want)
		}
	}
	// A token sized by MeltAmount clears a mint reserving exactly 1% — the case a
	// bare-price token fails (see TestCashuMeltUnderfunded).
	srv := fakeMint(20) // 1% of the 2000-sat quote
	defer srv.Close()
	c := NewCashuRedeemer(nil, srv.Client())
	if _, err := c.Melt(context.Background(), cashuToken(t, srv.URL, MeltAmount(2000)), "lnbc2u..."); err != nil {
		t.Fatalf("MeltAmount token rejected by a 1%% mint: %v", err)
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

func TestPaymentRequestPayloadStringAmount(t *testing.T) {
	// Minibits serializes proof amounts as JSON strings; others as numbers. Both
	// must decode (mixed here) and map to gonuts proofs.
	body := []byte(`{"mint":"https://m.example","unit":"sat","proofs":[` +
		`{"amount":"512","id":"00aa","secret":"s1","C":"02"},` +
		`{"amount":8,"id":"00aa","secret":"s2","C":"03"}]}`)
	var p PaymentRequestPayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := p.Cashu()
	if len(got) != 2 {
		t.Fatalf("got %d proofs, want 2", len(got))
	}
	if got.Amount() != 520 {
		t.Fatalf("total = %d, want 520", got.Amount())
	}
	if got[0].Amount != 512 || got[1].Amount != 8 {
		t.Fatalf("amounts = %d,%d, want 512,8", got[0].Amount, got[1].Amount)
	}
	if got[0].Secret != "s1" || got[0].C != "02" || got[0].Id != "00aa" {
		t.Fatalf("proof fields not mapped: %+v", got[0])
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
