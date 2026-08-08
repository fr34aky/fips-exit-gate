package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// A captive token is a signed hint the portal can use to greet the visitor:
// it names the fips source address the exit saw and an expiry, authenticated
// with an HMAC over a shared secret. It is NOT an access credential — it only
// tells the portal "this address hit the exit and was not authorized", so the
// portal can show the right account/purchase state. Short-lived by design.
//
// Wire form (base64url, no padding) of: "<addr>|<exp_unix>|<mac>" where mac =
// HMAC-SHA256(secret, "<addr>|<exp_unix>") truncated to 16 bytes.

const tokenTTLSeconds = 300

func signToken(secret []byte, addr netip.Addr, expUnix int64) string {
	payload := addr.String() + "|" + strconv.FormatInt(expUnix, 10)
	mac := hmacTrunc(secret, payload)
	raw := payload + "|" + base64.RawURLEncoding.EncodeToString(mac)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// VerifyToken re-derives the MAC and checks expiry; exported shape mirrors what
// the portal will implement. now is the current unix time.
func verifyToken(secret []byte, token string, now int64) (netip.Addr, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("captive token: bad base64: %w", err)
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return netip.Addr{}, fmt.Errorf("captive token: malformed")
	}
	addr, err := netip.ParseAddr(parts[0])
	if err != nil {
		return netip.Addr{}, fmt.Errorf("captive token: bad addr: %w", err)
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("captive token: bad exp: %w", err)
	}
	want := hmacTrunc(secret, parts[0]+"|"+parts[1])
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(want, got) {
		return netip.Addr{}, fmt.Errorf("captive token: bad signature")
	}
	if now > exp {
		return netip.Addr{}, fmt.Errorf("captive token: expired")
	}
	return addr, nil
}

func hmacTrunc(secret []byte, msg string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	return h.Sum(nil)[:16]
}
