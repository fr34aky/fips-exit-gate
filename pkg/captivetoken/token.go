// Package captivetoken is the signed hint the captive daemon embeds in its
// portal redirect and the portal verifies. It names the fips source address
// the exit saw and an expiry, authenticated with an HMAC over a shared secret.
// It is NOT an access credential — it only tells the portal "this address hit
// the exit and was not authorized", so the portal can greet the visitor with
// the right account/purchase state. Short-lived by design.
//
// Wire form (base64url, no padding) of: "<addr>|<exp_unix>|<mac>" where mac =
// base64url(HMAC-SHA256(secret, "<addr>|<exp_unix>")[:16]).
package captivetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// TTLSeconds is how long a token stays valid.
const TTLSeconds = 300

// ErrExpired is returned for a well-formed, correctly signed but stale token.
var ErrExpired = errors.New("captive token: expired")

// Sign produces a token for addr expiring at expUnix.
func Sign(secret []byte, addr netip.Addr, expUnix int64) string {
	payload := addr.String() + "|" + strconv.FormatInt(expUnix, 10)
	raw := payload + "|" + base64.RawURLEncoding.EncodeToString(mac(secret, payload))
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// Verify re-derives the MAC and checks expiry against now (unix seconds).
func Verify(secret []byte, token string, now int64) (netip.Addr, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("captive token: bad base64: %w", err)
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return netip.Addr{}, errors.New("captive token: malformed")
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(mac(secret, parts[0]+"|"+parts[1]), got) {
		return netip.Addr{}, errors.New("captive token: bad signature")
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return netip.Addr{}, errors.New("captive token: bad expiry")
	}
	if now > exp {
		return netip.Addr{}, ErrExpired
	}
	addr, err := netip.ParseAddr(parts[0])
	if err != nil {
		return netip.Addr{}, fmt.Errorf("captive token: bad addr: %w", err)
	}
	return addr, nil
}

func mac(secret []byte, msg string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(msg))
	return h.Sum(nil)[:16]
}
