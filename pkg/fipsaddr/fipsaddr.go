// Package fipsaddr derives FIPS mesh addresses (fd00::/8) from nostr
// identities (npub), mirroring the reference implementation in
// https://github.com/jmcorgan/fips (src/identity/{node_addr,address}.rs).
//
// Derivation:
//
//	pubkey    = 32-byte x-only secp256k1 key, NIP-19 bech32-decoded from "npub1..."
//	node_addr = SHA-256(pubkey)[0:16]
//	address   = 0xfd || node_addr[0:15]   (an IPv6 address in fd00::/8)
//
// The package is dependency-free (stdlib only) so it can be reused by the
// exit agent, captive daemon, and backend, and later cross-compiled for
// OpenWrt.
package fipsaddr

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
)

// AddressPrefix is the first byte of every FIPS mesh address.
const AddressPrefix = 0xfd

// Prefix is the IPv6 range FIPS operates in.
var Prefix = netip.MustParsePrefix("fd00::/8")

// NodeAddr returns the 16-byte fips node identifier for an x-only pubkey:
// the first 16 bytes of SHA-256(pubkey).
func NodeAddr(pubkey [32]byte) [16]byte {
	sum := sha256.Sum256(pubkey[:])
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// FromPubkey derives the FIPS mesh address for an x-only pubkey:
// 0xfd followed by the first 15 bytes of the node_addr.
func FromPubkey(pubkey [32]byte) netip.Addr {
	node := NodeAddr(pubkey)
	var b [16]byte
	b[0] = AddressPrefix
	copy(b[1:], node[:15])
	return netip.AddrFrom16(b)
}

// FromNpub decodes a NIP-19 npub string, validates the key, and returns the
// derived FIPS mesh address.
func FromNpub(npub string) (netip.Addr, error) {
	pubkey, err := DecodeNpub(npub)
	if err != nil {
		return netip.Addr{}, err
	}
	return FromPubkey(pubkey), nil
}

// Valid reports whether addr lies inside the FIPS mesh range fd00::/8.
func Valid(addr netip.Addr) bool {
	return addr.Is6() && !addr.Is4In6() && Prefix.Contains(addr)
}

// CheckDerivation verifies that addr is the FIPS address of npub. It is the
// primitive behind transparent fips login and whitelist validation.
func CheckDerivation(npub string, addr netip.Addr) error {
	derived, err := FromNpub(npub)
	if err != nil {
		return err
	}
	if derived != addr.Unmap() {
		return fmt.Errorf("fipsaddr: address %s does not match %s (expected %s)", addr, npub, derived)
	}
	return nil
}
