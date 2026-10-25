package authzhash

import (
	"net/netip"
	"testing"
)

func TestOfIsOrderAndDuplicateIndependent(t *testing.T) {
	a, b, c := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::3")
	h1 := Of([]netip.Addr{a, b, c})
	h2 := Of([]netip.Addr{c, a, b, a})
	if h1 != h2 {
		t.Fatalf("order/duplicates changed the hash: %s vs %s", h1, h2)
	}
	if Of([]netip.Addr{a, b}) == h1 {
		t.Fatal("different sets hashed equal")
	}
	if Of(nil) != Of([]netip.Addr{}) || Of(nil) == h1 {
		t.Fatal("empty set hash is not stable/distinct")
	}
	if OfSet(map[netip.Addr]struct{}{a: {}, b: {}, c: {}}) != h1 {
		t.Fatal("OfSet disagrees with Of")
	}
	if len(h1) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(h1))
	}
}
