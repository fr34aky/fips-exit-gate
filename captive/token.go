package main

import (
	"net/netip"

	"github.com/fr34aky/fips-exit-gate/pkg/captivetoken"
)

// The captive token format lives in pkg/captivetoken (shared with the portal,
// which verifies it); these wrappers keep the daemon's call sites unchanged.

const tokenTTLSeconds = captivetoken.TTLSeconds

func signToken(secret []byte, addr netip.Addr, expUnix int64) string {
	return captivetoken.Sign(secret, addr, expUnix)
}

func verifyToken(secret []byte, token string, now int64) (netip.Addr, error) {
	return captivetoken.Verify(secret, token, now)
}
