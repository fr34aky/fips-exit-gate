package nostr

import (
	"strings"
	"testing"
)

// Clock-skew / replay: a challenge is valid up to its expiry and rejected after.
func TestVerifyChallengeExpiry(t *testing.T) {
	secret := []byte("s3cret")
	ch := IssueChallenge(secret, 1000)
	if err := VerifyChallenge(secret, ch, 1000+ChallengeTTLSeconds); err != nil {
		t.Fatalf("challenge rejected at the expiry boundary: %v", err)
	}
	if err := VerifyChallenge(secret, ch, 1000+ChallengeTTLSeconds+1); err == nil {
		t.Fatal("expired challenge was accepted")
	}
}

// Forgery: extending the expiry or using the wrong secret must fail the HMAC;
// malformed input is rejected without panicking.
func TestVerifyChallengeForgery(t *testing.T) {
	secret := []byte("s3cret")
	ch := IssueChallenge(secret, 1000)
	parts := strings.Split(ch, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected challenge shape: %q", ch)
	}
	forgedExpiry := parts[0] + "." + "9999999999" + "." + parts[2]
	if err := VerifyChallenge(secret, forgedExpiry, 1000); err == nil {
		t.Fatal("challenge with a forged (extended) expiry was accepted")
	}
	if err := VerifyChallenge([]byte("other-secret"), ch, 1000); err == nil {
		t.Fatal("challenge accepted under the wrong secret")
	}
	for _, bad := range []string{"", "a.b", "a.b.c.d", "nonce.notanumber.mac"} {
		if err := VerifyChallenge(secret, bad, 1000); err == nil {
			t.Fatalf("malformed challenge %q was accepted", bad)
		}
	}
}
