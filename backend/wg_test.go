package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fr34aky/fips-exit-gate/backend/store"
)

func wgTestKey(b byte) string {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

func TestWgKeygenAndConfigRender(t *testing.T) {
	priv, pub, err := genWgKeypair()
	if err != nil || !store.ValidWgKey(priv) || !store.ValidWgKey(pub) || priv == pub {
		t.Fatalf("keygen: %v %q %q", err, priv, pub)
	}
	s := loadWgSettings()
	peer := store.WgPeer{Npub: "npub1dev", Pubkey: pub, Idx: 5}
	peer.IP4, peer.IP6 = s.pools.Gateway4(), s.pools.Gateway6() // any addresses
	cfg := renderWgConfig(priv, peer, store.WgNode{Name: "exit-01", Pubkey: wgTestKey(9), Endpoint: "npub1exit.fips:51820"}, s, "http://portal.fips:8080")
	for _, want := range []string{"PrivateKey = " + priv, "Endpoint = npub1exit.fips:51820", "AllowedIPs = " + wgAllowedIPs, "DNS = 10.64.0.1, fc10:f1b5:ea17::1", "MTU = 1280", "PersistentKeepalive = 25"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(wgAllowedIPs, "fd00::/8") || !strings.Contains(wgAllowedIPs, "fc00::/8") {
		t.Fatal("AllowedIPs must exclude fd00::/8 and include fc00::/8")
	}
}

// Full flow over HTTP: node announces its key via the heartbeat, the user
// creates a device on the dashboard, the config page shows the private key
// once, the agent fetches the peer table with etag semantics.
func TestWgPortalAndAgentFlow(t *testing.T) {
	st := testStoreMain(t)
	ctx := context.Background()
	p := testPortal(t, st, false)
	wg := loadWgSettings()
	st.WgPools = wg.pools
	p.wg = wg
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240, wg: wg}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()

	// Catalog + node with WireGuard.
	if err := st.CreateService(ctx, "wg", "WireGuard", 51820, 1_000_000, true); err != nil {
		t.Fatal(err)
	}
	tok, _ := st.CreateEnrollToken(ctx, "n")
	nodeID, nodeTok, err := st.EnrollNode(ctx, tok, "pk", "exit-01")
	if err != nil {
		t.Fatal(err)
	}
	nodeReq := func(method, path, body string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+nodeTok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := nodeReq("POST", "/v1/nodes/"+nodeID+"/heartbeat", `{"version":"t","authz_rev":0,"set_size":0,"wg_pubkey":"`+wgTestKey(9)+`","wg_endpoint":"npub1exit.fips:51820"}`)
	var hb struct {
		Config struct {
			Wg struct {
				Port  int    `json:"port"`
				Pool4 string `json:"pool4"`
			} `json:"wg"`
		} `json:"config"`
	}
	json.NewDecoder(resp.Body).Decode(&hb)
	resp.Body.Close()
	if hb.Config.Wg.Port != 51820 || hb.Config.Wg.Pool4 != "10.64.0.0/16" {
		t.Fatalf("heartbeat wg config: %+v", hb)
	}

	// Empty peer table: 200 with an etag, then 204 on the same etag.
	resp = nodeReq("GET", "/v1/nodes/"+nodeID+"/wg", "")
	var tbl struct {
		Etag  string           `json:"etag"`
		Peers []map[string]any `json:"peers"`
	}
	json.NewDecoder(resp.Body).Decode(&tbl)
	resp.Body.Close()
	if resp.StatusCode != 200 || tbl.Etag == "" || len(tbl.Peers) != 0 {
		t.Fatalf("initial table: %d %+v", resp.StatusCode, tbl)
	}
	resp = nodeReq("GET", "/v1/nodes/"+nodeID+"/wg?etag="+tbl.Etag, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unchanged table: %d", resp.StatusCode)
	}

	// User: credited account, session, dashboard shows the section, creates a device.
	_, npub, _ := newTestKey(t)
	if err := st.CreditVolume(ctx, npub, 1_000_000, 30); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	rec := httptest.NewRecorder()
	p.setSession(rec, npub)
	u, _ := url.Parse(srv.URL)
	jar.SetCookies(u, rec.Result().Cookies())

	dash, _ := c.Get(srv.URL + "/dashboard")
	if page := readAll(dash); !strings.Contains(page, "WireGuard (whole-device VPN)") {
		t.Fatal("dashboard does not offer WireGuard although a node announced a key")
	}
	resp, err = c.PostForm(srv.URL+"/wg/new", url.Values{"device_npub": {npub}, "label": {"laptop"}})
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, "PrivateKey = ") || !strings.Contains(page, "data:image/png") || !strings.Contains(page, "Endpoint = npub1exit.fips:51820") {
		t.Fatalf("wg_new page: status %d, page %q", resp.StatusCode, page[:min(len(page), 400)])
	}
	// The DB holds only the public key; the dashboard lists the device without secrets.
	if all, _, _ := st.WgPeerTable(ctx); len(all) != 1 || all[0].Pubkey == "" {
		t.Fatalf("expected 1 peer row with a public key, got %+v", all)
	}
	dash, _ = c.Get(srv.URL + "/dashboard")
	if page := readAll(dash); !strings.Contains(page, "laptop") || strings.Contains(page, "PrivateKey") {
		t.Fatal("dashboard should list the device and never a private key")
	}

	// Agent sees the peer; etag changed.
	resp = nodeReq("GET", "/v1/nodes/"+nodeID+"/wg?etag="+tbl.Etag, "")
	var tbl2 struct {
		Etag  string           `json:"etag"`
		Peers []map[string]any `json:"peers"`
	}
	json.NewDecoder(resp.Body).Decode(&tbl2)
	resp.Body.Close()
	if resp.StatusCode != 200 || tbl2.Etag == tbl.Etag || len(tbl2.Peers) != 1 || tbl2.Peers[0]["ip4"] == nil {
		t.Fatalf("table after create: %d %+v", resp.StatusCode, tbl2)
	}

	// Unauthenticated creation is refused.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ = noRedirect.Post(srv.URL+"/wg/new", "application/x-www-form-urlencoded", strings.NewReader("device_npub="+npub))
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "/login") {
		t.Fatalf("unauthenticated /wg/new: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()
}
