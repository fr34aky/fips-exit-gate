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

// newPaymentsClient builds a BTCPay Greenfield client from the environment, or
// returns nil if BTCPay is not configured (payments disabled). When
// BTCPAY_SOCKS5 is set (e.g. 127.0.0.1:9050), requests are dialed through that
// SOCKS5 proxy — the way to reach a BTCPay .onion over Tor.
func newPaymentsClient() *payments.Client {
	base := os.Getenv("BTCPAY_URL")
	apiKey := os.Getenv("BTCPAY_API_KEY")
	storeID := os.Getenv("BTCPAY_STORE_ID")
	if base == "" || apiKey == "" || storeID == "" {
		return nil
	}

	hc := &http.Client{Timeout: 60 * time.Second}
	if socks := os.Getenv("BTCPAY_SOCKS5"); socks != "" {
		dialer, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
		if err != nil {
			log.Fatalf("backend: BTCPAY_SOCKS5 %q: %v", socks, err)
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
		log.Printf("backend: BTCPay reached via SOCKS5 %s", socks)
	}
	return payments.NewClient(base, apiKey, storeID, hc)
}
