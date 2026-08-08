package fipsaddr

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

// Vectors cross-generated with an independent Python implementation
// (bech32 reference code + hashlib); the first entry is the NIP-19 spec
// example pubkey, the second and third are the NIP-06 test-vector pubkeys.
var vectors = []struct {
	npub     string
	pubkey   string
	nodeAddr string
	addr     string
}{
	{
		npub:     "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
		pubkey:   "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
		nodeAddr: "1093b285866046e42dc0893228ccffb4",
		addr:     "fd10:93b2:8586:6046:e42d:c089:3228:ccff",
	},
	{
		npub:     "npub1l2vyh47mk2p0qlsku7hg0vn29faehy9hy34ygaclpn66ukqp3afqutajft",
		pubkey:   "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52",
		nodeAddr: "54dc855ad5c438acd60aa8849513dd18",
		addr:     "fd54:dc85:5ad5:c438:acd6:aa8:8495:13dd",
	},
	{
		npub:     "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu",
		pubkey:   "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
		nodeAddr: "e4f76c66657548be8645ec3f9bfbb58c",
		addr:     "fde4:f76c:6665:7548:be86:45ec:3f9b:fbb5",
	},
}

func TestVectors(t *testing.T) {
	for _, v := range vectors {
		pk, err := DecodeNpub(v.npub)
		if err != nil {
			t.Fatalf("DecodeNpub(%s): %v", v.npub, err)
		}
		if hex.EncodeToString(pk[:]) != v.pubkey {
			t.Errorf("DecodeNpub(%s) = %x, want %s", v.npub, pk, v.pubkey)
		}
		if got := EncodeNpub(pk); got != v.npub {
			t.Errorf("EncodeNpub roundtrip = %s, want %s", got, v.npub)
		}
		node := NodeAddr(pk)
		if hex.EncodeToString(node[:]) != v.nodeAddr {
			t.Errorf("NodeAddr(%s) = %x, want %s", v.npub, node, v.nodeAddr)
		}
		addr := FromPubkey(pk)
		if addr != netip.MustParseAddr(v.addr) {
			t.Errorf("FromPubkey(%s) = %s, want %s", v.npub, addr, v.addr)
		}
		fromNpub, err := FromNpub(v.npub)
		if err != nil || fromNpub != addr {
			t.Errorf("FromNpub(%s) = %s, %v; want %s", v.npub, fromNpub, err, addr)
		}
		if !Valid(addr) {
			t.Errorf("Valid(%s) = false, want true", addr)
		}
		if err := CheckDerivation(v.npub, addr); err != nil {
			t.Errorf("CheckDerivation(%s, %s): %v", v.npub, addr, err)
		}
	}
}

func TestDecodeNpubErrors(t *testing.T) {
	// x = 0 is not on the secp256k1 curve; its correctly-checksummed npub
	// must be rejected by point validation.
	npubZero := EncodeNpub([32]byte{})
	// x = 1 IS on the curve; the same shape with a valid point must pass.
	npubOne := EncodeNpub([32]byte{31: 1})
	if _, err := DecodeNpub(npubOne); err != nil {
		t.Errorf("DecodeNpub(x=1) unexpectedly failed: %v", err)
	}

	shortData, _ := convertBits(make([]byte, 20), 8, 5, true)
	cases := map[string]string{
		"empty":          "",
		"not bech32":     "hello world",
		"wrong hrp":      "nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
		"bad checksum":   "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w7",
		"mixed case":     "Npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
		"short payload":  bech32Encode("npub", shortData),
		"x not on curve": npubZero,
	}
	for name, in := range cases {
		if _, err := DecodeNpub(in); err == nil {
			t.Errorf("%s: DecodeNpub(%q) succeeded, want error", name, in)
		}
	}
}

func TestValid(t *testing.T) {
	cases := map[string]bool{
		"fd00::1":        true,
		"fdff:ffff::":    true,
		"fc00::1":        false, // fc-prefixed ULA is NOT fips
		"fe80::1":        false,
		"2001:db8::1":    false,
		"::ffff:1.2.3.4": false,
	}
	for addr, want := range cases {
		if got := Valid(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Valid(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestCheckDerivationMismatch(t *testing.T) {
	if err := CheckDerivation(vectors[0].npub, netip.MustParseAddr(vectors[1].addr)); err == nil {
		t.Error("CheckDerivation with mismatched address succeeded, want error")
	}
}
