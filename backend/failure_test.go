package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/fr34aky/fips-exit-gate/backend/nostr"
)

// TestAuthVerifyRejectsStaleEvent covers the clock-skew guard: an auth event
// with a valid signature and a fresh challenge but a created_at far outside the
// freshness window must be rejected (defends against replay of an old signed
// event).
func TestAuthVerifyRejectsStaleEvent(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/auth/challenge")
	if err != nil {
		t.Fatal(err)
	}
	var ch struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()

	priv, _, _ := newTestKey(t)
	// Correctly signed, fresh challenge, but stale created_at.
	e := nostr.Event{
		Kind:      27235,
		CreatedAt: time.Now().Unix() - 100000,
		Tags:      [][]string{{"challenge", ch.Challenge}},
		Content:   "",
	}
	e.Pubkey = hex.EncodeToString(priv.PubKey().SerializeCompressed()[1:33])
	id, _ := nostr.ComputeID(&e)
	e.ID = hex.EncodeToString(id[:])
	sig, _ := schnorr.Sign(priv, id[:])
	e.Sig = hex.EncodeToString(sig.Serialize())

	body, _ := json.Marshal(map[string]any{"event": e})
	resp, err = http.Post(srv.URL+"/auth/verify", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale auth event accepted: status %d", resp.StatusCode)
	}
}

// TestAuthVerifyRejectsWrongKind covers the cross-app-signing defense: a
// correctly-signed, fresh event carrying a valid challenge but the WRONG kind
// (e.g. an ordinary note) must be rejected.
func TestAuthVerifyRejectsWrongKind(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/auth/challenge")
	var ch struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()

	priv, _, _ := newTestKey(t)
	e := nostr.Event{
		Kind:      1, // ordinary note, not the auth kind
		CreatedAt: time.Now().Unix(),
		Tags:      [][]string{{"challenge", ch.Challenge}},
		Content:   "",
	}
	e.Pubkey = hex.EncodeToString(priv.PubKey().SerializeCompressed()[1:33])
	id, _ := nostr.ComputeID(&e)
	e.ID = hex.EncodeToString(id[:])
	sig, _ := schnorr.Sign(priv, id[:])
	e.Sig = hex.EncodeToString(sig.Serialize())

	body, _ := json.Marshal(map[string]any{"event": e})
	resp, err := http.Post(srv.URL+"/auth/verify", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-kind auth event accepted: status %d", resp.StatusCode)
	}
}
