package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/fr34aky/fips-exit-gate/backend/nostr"
	"github.com/fr34aky/fips-exit-gate/backend/payments"
)

func signAuthEventWithTags(t *testing.T, priv *btcec.PrivateKey, tags [][]string) nostr.Event {
	t.Helper()
	e := nostr.Event{Kind: 27235, CreatedAt: time.Now().Unix(), Tags: tags, Content: ""}
	e.Pubkey = hex.EncodeToString(priv.PubKey().SerializeCompressed()[1:33])
	id, _ := nostr.ComputeID(&e)
	e.ID = hex.EncodeToString(id[:])
	sig, _ := schnorr.Sign(priv, id[:])
	e.Sig = hex.EncodeToString(sig.Serialize())
	return e
}

// A captured, correctly signed login event cannot be replayed: the second
// verification of the same challenge is refused.
func TestLoginChallengeIsSingleUse(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, false)
	priv, _, _ := newTestKey(t)

	rec := httptest.NewRecorder()
	p.authChallenge(rec, httptest.NewRequest("GET", "/auth/challenge", nil))
	var ch struct{ Challenge string }
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	ev := signAuthEvent(t, priv, ch.Challenge)
	body, _ := json.Marshal(map[string]any{"event": ev})

	verify := func() int {
		req := httptest.NewRequest("POST", "/auth/verify", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		p.authVerify(rec, req)
		return rec.Code
	}
	if code := verify(); code != http.StatusOK {
		t.Fatalf("first verify: %d", code)
	}
	if code := verify(); code != http.StatusUnauthorized {
		t.Fatalf("replayed event accepted: %d", code)
	}
}

// An event whose "u" tag names another site (a phishing page relaying a
// signature it obtained for its own challenge) is refused.
func TestLoginRejectsEventSignedForAnotherSite(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, false)
	priv, _, _ := newTestKey(t)
	rec := httptest.NewRecorder()
	p.authChallenge(rec, httptest.NewRequest("GET", "/auth/challenge", nil))
	var ch struct{ Challenge string }
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)

	post := func(u string) int {
		ev := signAuthEventWithTags(t, priv, [][]string{{"challenge", ch.Challenge}, {"u", u}, {"method", "POST"}})
		body, _ := json.Marshal(map[string]any{"event": ev})
		req := httptest.NewRequest("POST", "http://portal.fips:8080/auth/verify", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		p.authVerify(rec, req)
		return rec.Code
	}
	if code := post("https://evil.example/auth/verify"); code != http.StatusUnauthorized {
		t.Fatalf("event for another site accepted: %d", code)
	}
	if code := post("http://portal.fips:8080/auth/verify"); code != http.StatusOK {
		t.Fatalf("event for this site refused: %d", code)
	}
}

// Cross-site browser POSTs are refused by the built-in protection; same-site
// and non-browser requests pass, and the Cashu receiver is exempt.
func TestCrossSitePostsAreRejected(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()
	do := func(path, site string) int {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader("x=1"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := do("/auth/logout", "cross-site"); code != http.StatusForbidden {
		t.Fatalf("cross-site POST got %d, want 403", code)
	}
	if code := do("/auth/logout", "same-origin"); code == http.StatusForbidden {
		t.Fatal("same-origin POST rejected")
	}
	if code := do("/auth/logout", ""); code == http.StatusForbidden {
		t.Fatal("non-browser POST (no Sec-Fetch-Site) rejected")
	}
	if code := do("/pay/abc/cashu-receive", "cross-site"); code == http.StatusForbidden {
		t.Fatal("Cashu NUT-18 receiver must accept cross-origin wallet POSTs")
	}
}

type fakeChecker struct {
	status string
	err    error
}

func (f fakeChecker) InvoiceStatus(context.Context, string) (string, error) { return f.status, f.err }

// A Settled webhook grants only when the provider confirms the invoice is
// settled; otherwise it is acked without granting (or retried on error).
func TestSettledWebhookIsRecheckedAgainstTheProvider(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	_, npub, addr := newTestKey(t)
	if _, err := st.CreateAccount(ctx, npub); err != nil {
		t.Fatal(err)
	}
	pkgs, _ := st.ListPackages(ctx)
	pid, err := st.CreatePurchase(ctx, npub, pkgs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AttachInvoice(ctx, pid, "inv_recheck", "http://x", ""); err != nil {
		t.Fatal(err)
	}
	const secret = "whsec"
	run := func(c invoiceChecker) int {
		ph := &payHandler{store: st, secret: []byte(secret), checker: c}
		srv := httptest.NewServer(routes(h, p, st, "admintok", ph, nil, nil, ""))
		defer srv.Close()
		return postWebhook(t, srv.URL, secret, payments.EventInvoiceSettled, "inv_recheck", false)
	}
	authorized := func() bool {
		full, _, _ := st.FullSet(ctx)
		return hasAddr(full, addr)
	}
	if code := run(fakeChecker{status: "Processing"}); code != http.StatusOK || authorized() {
		t.Fatalf("unconfirmed settlement: code %d authorized %v", code, authorized())
	}
	if code := run(fakeChecker{err: errors.New("down")}); code != http.StatusBadGateway || authorized() {
		t.Fatalf("provider error: code %d authorized %v", code, authorized())
	}
	if code := run(fakeChecker{status: "Settled"}); code != http.StatusOK || !authorized() {
		t.Fatalf("confirmed settlement: code %d authorized %v", code, authorized())
	}
}
