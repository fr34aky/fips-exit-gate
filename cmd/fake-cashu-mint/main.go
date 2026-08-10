// Command fake-cashu-mint is a minimal Cashu mint stand-in for testing the
// fips-exit accept-and-melt flow locally without a real mint — the Cashu analogue
// of cmd/fake-phoenixd. It implements just the NUT-05 melt endpoints, and on melt
// it drives cmd/fake-phoenixd's /sim endpoint so the phoenixd payment "arrives"
// and the backend grants access.
//
// It also serves GET /sim/token?amount=N, which returns a Cashu token pointing at
// this mint that you can paste into the pay page (for the paste flow).
//
// Usage:
//
//	fake-cashu-mint -listen :3338 \
//	  -phoenixd-url http://127.0.0.1:9740 -mint-url http://127.0.0.1:3338
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/elnosh/gonuts/cashu"
)

var (
	phoenixdURL string
	mintURL     string
)

func main() {
	listen := flag.String("listen", ":3338", "listen address")
	flag.StringVar(&phoenixdURL, "phoenixd-url", "http://127.0.0.1:9740", "fake-phoenixd base URL (to drive /sim)")
	flag.StringVar(&mintURL, "mint-url", "http://127.0.0.1:3338", "this mint's URL as the backend reaches it (embedded in issued tokens)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/melt/quote/bolt11", meltQuote)
	mux.HandleFunc("POST /v1/melt/bolt11", melt)
	mux.HandleFunc("GET /sim/token", simToken)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "fake-cashu-mint (%s): NUT-05 melt drives fake-phoenixd /sim.\nGET /sim/token?amount=N returns a pasteable token.\n", mintURL)
	})
	log.Printf("fake-cashu-mint listening on %s (mint-url %s, phoenixd %s)", *listen, mintURL, phoenixdURL)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

// hashFromBolt11 recovers the fake-phoenixd payment hash from its "lnbcrt-fake-<hash>".
func hashFromBolt11(b string) string { return strings.TrimPrefix(b, "lnbcrt-fake-") }

func meltQuote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Request string `json:"request"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	hash := hashFromBolt11(req.Request)
	writeJSON(w, map[string]any{"quote": hash, "amount": lookupAmount(hash), "fee_reserve": 0, "state": "UNPAID"})
}

func melt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Quote string `json:"quote"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	// Drive fake-phoenixd: mark the invoice paid and fire its webhook.
	resp, err := http.Post(phoenixdURL+"/sim/"+req.Quote+"/pay", "", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		http.Error(w, "phoenixd sim failed", http.StatusBadGateway)
		return
	}
	log.Printf("melt quote=%s -> fake-phoenixd sim pay", req.Quote)
	writeJSON(w, map[string]any{"state": "PAID"})
}

func simToken(w http.ResponseWriter, r *http.Request) {
	amount := uint64(2000)
	fmt.Sscanf(r.URL.Query().Get("amount"), "%d", &amount)
	proofs := cashu.Proofs{{Amount: amount, Id: "00ffffffffffffff", Secret: "fake-secret", C: "02" + strings.Repeat("00", 32)}}
	tok, err := cashu.NewTokenV3(proofs, mintURL, cashu.Sat, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s, err := tok.Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, s)
}

func lookupAmount(hash string) int64 {
	resp, err := http.Get(phoenixdURL + "/payments/incoming/" + hash)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	var out struct {
		AmountSat int64 `json:"amountSat"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	return out.AmountSat
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
