package payments

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elnosh/gonuts/cashu"
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
