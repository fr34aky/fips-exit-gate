// Package authzhash computes an order-independent fingerprint of an authorized
// address set. The agent hashes the live kernel set and the backend hashes
// authz_current; equal hashes at an equal revision mean the two agree member
// by member, which a size comparison cannot tell (same count, different
// members). Both sides must use this package so the fingerprints line up.
package authzhash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
)

// Of returns the hex fingerprint of the set formed by addrs. Duplicates are
// collapsed and order is irrelevant; the empty set has a well-defined value.
func Of(addrs []netip.Addr) string {
	keys := make([][16]byte, 0, len(addrs))
	for _, a := range addrs {
		keys = append(keys, a.As16())
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	h := sha256.New()
	var prev [16]byte
	for i, k := range keys {
		if i > 0 && k == prev {
			continue
		}
		h.Write(k[:])
		prev = k
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// OfSet is Of over the keys of a set-shaped map.
func OfSet(set map[netip.Addr]struct{}) string {
	addrs := make([]netip.Addr, 0, len(set))
	for a := range set {
		addrs = append(addrs, a)
	}
	return Of(addrs)
}
