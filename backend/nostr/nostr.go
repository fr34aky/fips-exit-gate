// Package nostr verifies NIP-01 signed events and issues/verifies the
// stateless login challenges the portal uses for nostr-signature login.
package nostr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

// Event is a NIP-01 nostr event (the fields we need to verify a signature).
type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"` // 32-byte x-only, hex
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// ComputeID returns the NIP-01 event id: the SHA-256 of the canonical
// serialization [0, pubkey, created_at, kind, tags, content] (compact, no
// whitespace, HTML-unescaped).
func ComputeID(e *Event) ([32]byte, error) {
	tags := e.Tags
	if tags == nil {
		tags = [][]string{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // NIP-01 does not escape <, >, &
	if err := enc.Encode([]any{0, e.Pubkey, e.CreatedAt, e.Kind, tags, e.Content}); err != nil {
		return [32]byte{}, err
	}
	// Encoder appends a newline; drop it before hashing.
	return sha256.Sum256(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// Verify checks the event's id and Schnorr signature. On success it returns the
// signer's npub (bech32).
func Verify(e *Event) (npub string, err error) {
	pkBytes, err := hex.DecodeString(e.Pubkey)
	if err != nil || len(pkBytes) != 32 {
		return "", fmt.Errorf("nostr: bad pubkey")
	}
	id, err := ComputeID(e)
	if err != nil {
		return "", err
	}
	if e.ID != "" && e.ID != hex.EncodeToString(id[:]) {
		return "", fmt.Errorf("nostr: event id mismatch")
	}
	sigBytes, err := hex.DecodeString(e.Sig)
	if err != nil || len(sigBytes) != 64 {
		return "", fmt.Errorf("nostr: bad signature encoding")
	}
	pubkey, err := schnorr.ParsePubKey(pkBytes)
	if err != nil {
		return "", fmt.Errorf("nostr: parse pubkey: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return "", fmt.Errorf("nostr: parse signature: %w", err)
	}
	if !sig.Verify(id[:], pubkey) {
		return "", fmt.Errorf("nostr: signature does not verify")
	}
	var pk [32]byte
	copy(pk[:], pkBytes)
	return fipsaddr.EncodeNpub(pk), nil
}
