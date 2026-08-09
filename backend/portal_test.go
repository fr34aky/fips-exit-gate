package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fr34aky/fips-exit-gate/backend/nostr"
	"github.com/fr34aky/fips-exit-gate/backend/store"
	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

func testStoreMain(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	resetSchema(t, dsn)
	st, err := store.Open(ctx, dsn) // runs migrations on the clean schema
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SeedDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func resetSchema(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
}

func newTestKey(t *testing.T) (priv *btcec.PrivateKey, npub string, addr netip.Addr) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	var pk [32]byte
	copy(pk[:], priv.PubKey().SerializeCompressed()[1:33])
	npub = fipsaddr.EncodeNpub(pk)
	addr = fipsaddr.FromPubkey(pk)
	return priv, npub, addr
}

func signAuthEvent(t *testing.T, priv *btcec.PrivateKey, challenge string) nostr.Event {
	t.Helper()
	e := nostr.Event{
		Kind: 27235, CreatedAt: time.Now().Unix(),
		Tags: [][]string{{"challenge", challenge}}, Content: "",
	}
	e.Pubkey = hex.EncodeToString(priv.PubKey().SerializeCompressed()[1:33])
	id, _ := nostr.ComputeID(&e)
	e.ID = hex.EncodeToString(id[:])
	sig, _ := schnorr.Sign(priv, id[:])
	e.Sig = hex.EncodeToString(sig.Serialize())
	return e
}

func testPortal(t *testing.T, st *store.Store, trustFips bool) *portal {
	t.Helper()
	p, err := newPortal(st, []byte("sess"), []byte("chal"), []byte("capt"), trustFips, false)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPortalLoginAndWhitelist(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, ""))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}

	ownerPriv, ownerNpub, ownerAddr := newTestKey(t)
	_, guestNpub, guestAddr := newTestKey(t)

	// 1. Get a challenge.
	resp, err := c.Get(srv.URL + "/auth/challenge")
	if err != nil {
		t.Fatal(err)
	}
	var ch struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()
	if ch.Challenge == "" {
		t.Fatal("no challenge issued")
	}

	// 2. Sign it and verify (NIP-07-style JSON body).
	ev := signAuthEvent(t, ownerPriv, ch.Challenge)
	body, _ := json.Marshal(map[string]any{"event": ev})
	resp, err = c.Post(srv.URL+"/auth/verify", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	var vr struct{ Redirect, Error string }
	json.NewDecoder(resp.Body).Decode(&vr)
	resp.Body.Close()
	if vr.Redirect != "/dashboard" {
		t.Fatalf("login failed: %+v", vr)
	}

	// 3. Dashboard is reachable and shows the owner npub.
	resp, err = c.Get(srv.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, ownerNpub) {
		t.Fatalf("dashboard missing owner npub (status %d)", resp.StatusCode)
	}

	// 4. Credit the owner so authorization can take effect.
	if err := st.CreditVolume(ctx, ownerNpub, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}

	// 5. Add a guest via the portal form.
	resp, err = c.PostForm(srv.URL+"/whitelist/add", url.Values{"guest_npub": {guestNpub}, "label": {"laptop"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 6. Both owner and guest addresses are now authorized.
	full, _, err := st.FullSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAddr(full, ownerAddr) || !hasAddr(full, guestAddr) {
		t.Fatalf("expected owner+guest authorized, got %v", full)
	}
}

func TestTransparentLogin(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, true)

	_, ownerNpub, ownerAddr := newTestKey(t)

	// Simulate a request arriving over fips from the owner's derived address,
	// carrying the npub claim (verified against the trusted source address).
	form := url.Values{"npub": {ownerNpub}}
	req := httptest.NewRequest("POST", "/auth/fips", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "[" + ownerAddr.String() + "]:40000"
	rec := httptest.NewRecorder()

	p.authFips(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("transparent login status = %d", rec.Code)
	}
	if !strings.Contains(strings.Join(rec.Result().Header["Set-Cookie"], ";"), sessionCookie) {
		t.Fatal("no session cookie set for transparent login")
	}

	// A spoofed claim (npub that does NOT derive to the source address) fails.
	_, otherNpub, _ := newTestKey(t)
	form = url.Values{"npub": {otherNpub}}
	req = httptest.NewRequest("POST", "/auth/fips", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "[" + ownerAddr.String() + "]:40000"
	rec = httptest.NewRecorder()
	p.authFips(rec, req)
	if strings.Contains(strings.Join(rec.Result().Header["Set-Cookie"], ";"), sessionCookie) {
		t.Fatal("spoofed npub claim was accepted")
	}
	_ = ownerNpub
}

// TestLoginPageFipsNpubEntry covers the self-service onboarding path: an unknown
// visitor arriving over fips is offered npub entry (verified against their source
// address), while a non-fips visitor is not.
func TestLoginPageFipsNpubEntry(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, true) // trustFipsSource on

	// Unknown fips source -> login page offers npub entry.
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "[fd54:83c5:c670:a2fb:c5ef:f643:8541:9361]:40000"
	rec := httptest.NewRecorder()
	p.loginPage(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "connecting over fips") || !strings.Contains(body, `name="npub"`) {
		t.Fatal("unknown fips source was not offered npub entry")
	}

	// Non-fips source -> no transparent form.
	req2 := httptest.NewRequest("GET", "/login", nil)
	req2.RemoteAddr = "203.0.113.5:40000"
	rec2 := httptest.NewRecorder()
	p.loginPage(rec2, req2)
	if strings.Contains(rec2.Body.String(), "connecting over fips") {
		t.Fatal("non-fips source was offered transparent login")
	}
}

func hasAddr(ms []store.AuthzMember, a netip.Addr) bool {
	for _, m := range ms {
		if m.Addr == a {
			return true
		}
	}
	return false
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}

// TestVerifyCaptiveToken checks the portal verifies a token minted exactly as
// captive/token.go does (cross-component contract; no DB needed).
func TestVerifyCaptiveToken(t *testing.T) {
	secret := []byte("capt")
	p, err := newPortal(nil, []byte("s"), []byte("c"), secret, false, false)
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("fd10:93b2:8586:6046:e42d:c089:3228:ccff")
	exp := time.Now().Add(time.Minute).Unix()
	payload := addr.String() + "|" + strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	raw := payload + "|" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	token := base64.RawURLEncoding.EncodeToString([]byte(raw))

	got, err := p.verifyCaptiveToken(token)
	if err != nil || got != addr {
		t.Fatalf("verify captive token: got=%s err=%v", got, err)
	}
	if _, err := p.verifyCaptiveToken(token + "x"); err == nil {
		t.Fatal("accepted tampered captive token")
	}
}

func TestPortalBuyAutosettle(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	if err := st.SeedPackages(ctx); err != nil {
		t.Fatal(err)
	}
	p := testPortal(t, st, false)
	p.autoSettle = true
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, ""))
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	ownerPriv, ownerNpub, ownerAddr := newTestKey(t)

	// Log in.
	resp, _ := c.Get(srv.URL + "/auth/challenge")
	var ch struct{ Challenge string }
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()
	ev := signAuthEvent(t, ownerPriv, ch.Challenge)
	body, _ := json.Marshal(map[string]any{"event": ev})
	resp, _ = c.Post(srv.URL+"/auth/verify", "application/json", strings.NewReader(string(body)))
	resp.Body.Close()

	// The packages page renders the catalog.
	resp, _ = c.Get(srv.URL + "/packages")
	page := readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, "Buy") {
		t.Fatalf("packages page did not render (status %d)", resp.StatusCode)
	}

	// Buy the first package (autosettle grants immediately).
	pkgs, _ := st.ListPackages(ctx)
	resp, err := c.PostForm(srv.URL+"/buy", url.Values{"package_id": {pkgs[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	full, _, _ := st.FullSet(ctx)
	if !hasAddr(full, ownerAddr) {
		t.Fatalf("owner %s not authorized after autosettled purchase", ownerNpub)
	}
}
