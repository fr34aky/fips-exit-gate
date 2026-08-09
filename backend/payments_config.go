package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/proxy"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
)

// newPaymentsProvider selects the payment rail from PAYMENT_RAIL
// (btcpay | phoenixd | empty=disabled) and builds it, returning the provider and
// its kind. For back-compat, an unset PAYMENT_RAIL with BTCPAY_URL set means
// btcpay. Returns (nil, "") when payments are disabled/misconfigured.
func newPaymentsProvider() (payments.Provider, string) {
	rail := os.Getenv("PAYMENT_RAIL")
	if rail == "" && os.Getenv("BTCPAY_URL") != "" {
		rail = "btcpay"
	}
	switch rail {
	case "btcpay":
		base := os.Getenv("BTCPAY_URL")
		apiKey := os.Getenv("BTCPAY_API_KEY")
		storeID := os.Getenv("BTCPAY_STORE_ID")
		if base == "" || apiKey == "" || storeID == "" {
			log.Printf("backend: PAYMENT_RAIL=btcpay but BTCPAY_URL/API_KEY/STORE_ID incomplete — payments disabled")
			return nil, ""
		}
		return payments.NewClient(base, apiKey, storeID, torHTTPClient(os.Getenv("BTCPAY_SOCKS5"))), "btcpay"
	case "phoenixd":
		base := os.Getenv("PHOENIXD_URL")
		pw := os.Getenv("PHOENIXD_PASSWORD")
		if base == "" || pw == "" {
			log.Printf("backend: PAYMENT_RAIL=phoenixd but PHOENIXD_URL/PASSWORD incomplete — payments disabled")
			return nil, ""
		}
		return payments.NewPhoenixd(base, pw, torHTTPClient(os.Getenv("PHOENIXD_SOCKS5"))), "phoenixd"
	case "", "none":
		return nil, ""
	default:
		log.Fatalf("backend: unknown PAYMENT_RAIL %q (want btcpay | phoenixd | none)", rail)
		return nil, ""
	}
}

// torHTTPClient returns an http.Client dialing through the given SOCKS5 proxy
// (e.g. 127.0.0.1:9050 to reach an onion over Tor), or a plain client if empty.
func torHTTPClient(socks string) *http.Client {
	hc := &http.Client{Timeout: 60 * time.Second}
	if socks == "" {
		return hc
	}
	dialer, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("backend: SOCKS5 %q: %v", socks, err)
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		log.Fatalf("backend: SOCKS5 dialer lacks context support")
	}
	hc.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cd.DialContext(ctx, network, addr)
		},
	}
	log.Printf("backend: payment provider reached via SOCKS5 %s", socks)
	return hc
}
