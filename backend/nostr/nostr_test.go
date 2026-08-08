package nostr

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

// signEvent fills in Pubkey/ID/Sig for e using priv (test helper).
func signEvent(t *testing.T, priv *btcec.PrivateKey, e *Event) {
	t.Helper()
	xonly := priv.PubKey().SerializeCompressed()[1:33] // drop parity byte -> x-only
	e.Pubkey = hex.EncodeToString(xonly)
	id, err := ComputeID(e)
	if err != nil {
		t.Fatal(err)
	}
	e.ID = hex.EncodeToString(id[:])
	sig, err := schnorr.Sign(priv, id[:])
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = hex.EncodeToString(sig.Serialize())
}

func TestVerifyRoundTrip(t *testing.T) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &Event{Kind: 27235, CreatedAt: 1_700_000_000, Content: "hello <fips> & co", Tags: [][]string{{"t", "auth"}}}
	signEvent(t, priv, e)

	npub, err := Verify(e)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// npub must correspond to the signing key.
	var pk [32]byte
	copy(pk[:], priv.PubKey().SerializeCompressed()[1:33])
	if npub != fipsaddr.EncodeNpub(pk) {
		t.Fatalf("npub mismatch: %s", npub)
	}

	// Tamper with content -> id/sig no longer match.
	e.Content = "tampered"
	if _, err := Verify(e); err == nil {
		t.Fatal("verify accepted tampered event")
	}
}

func TestVerifyRejectsBadSig(t *testing.T) {
	priv, _ := btcec.NewPrivateKey()
	e := &Event{Kind: 1, CreatedAt: 1, Content: "x"}
	signEvent(t, priv, e)
	// Flip a byte in the signature.
	e.Sig = e.Sig[:10] + "00" + e.Sig[12:]
	if _, err := Verify(e); err == nil {
		t.Fatal("verify accepted bad signature")
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	secret := []byte("challenge-secret")
	now := int64(1_700_000_000)
	c := IssueChallenge(secret, now)
	if err := VerifyChallenge(secret, c, now+10); err != nil {
		t.Fatalf("verify fresh: %v", err)
	}
	if err := VerifyChallenge(secret, c, now+ChallengeTTLSeconds+1); err == nil {
		t.Fatal("verify accepted expired challenge")
	}
	if err := VerifyChallenge([]byte("wrong"), c, now); err == nil {
		t.Fatal("verify accepted wrong secret")
	}
}

func TestExtractChallenge(t *testing.T) {
	e := &Event{Tags: [][]string{{"challenge", "abc"}}, Content: "ignored"}
	if got := ExtractChallenge(e); got != "abc" {
		t.Fatalf("tag challenge = %q", got)
	}
	e2 := &Event{Content: "xyz"}
	if got := ExtractChallenge(e2); got != "xyz" {
		t.Fatalf("content challenge = %q", got)
	}
}
