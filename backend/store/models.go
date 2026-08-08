package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"time"
)

// AuthzMember is one authorized fips address and the account it belongs to.
type AuthzMember struct {
	Addr    netip.Addr
	Account string // account id
}

// Service is an egress service the agent should gate + meter.
type Service struct {
	Key  string
	Port uint16
	Rate int64 // rate_ppm
}

// Account is a nostr-identity account (the owner).
type Account struct {
	ID       string
	Npub     string
	FipsAddr netip.Addr
	Status   string
}

// SampleInput is one metered total for a client on a service, from the agent.
type SampleInput struct {
	Service string // service key
	Addr    netip.Addr
	Bytes   uint64
}

// ReportInput is a full usage report from the agent.
type ReportInput struct {
	ReportID     string
	CounterEpoch string
	WindowEnd    time.Time
	Samples      []SampleInput
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// randToken returns a URL-safe random secret (32 bytes of entropy).
func randToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
