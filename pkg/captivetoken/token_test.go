package captivetoken

import (
	"net/netip"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("s3cret")
	addr := netip.MustParseAddr("fd00::1234")
	tok := Sign(secret, addr, 1000)
	got, err := Verify(secret, tok, 999)
	if err != nil || got != addr {
		t.Fatalf("verify: %v %v", got, err)
	}
	if _, err := Verify(secret, tok, 1001); err != ErrExpired {
		t.Fatalf("expired token accepted: %v", err)
	}
	if _, err := Verify([]byte("other"), tok, 999); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := Verify(secret, tok[:len(tok)-2]+"zz", 999); err == nil {
		t.Fatal("tampered token accepted")
	}
	if _, err := Verify(secret, "", 999); err == nil {
		t.Fatal("empty token accepted")
	}
}
