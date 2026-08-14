package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fr34aky/fips-exit-gate/backend/nostr"
	"github.com/fr34aky/fips-exit-gate/backend/payments"
	"github.com/fr34aky/fips-exit-gate/backend/store"
	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
)

//go:embed templates/*.html
var templatesFS embed.FS

type portal struct {
	store           *store.Store
	sessionSecret   []byte
	challengeSecret []byte
	captiveSecret   []byte
	trustFipsSource bool
	secureCookies   bool
	autoSettle      bool                    // dev: settle purchases immediately (no payment)
	pay             payments.Provider       // nil until a payment rail is configured
	cashu           *payments.CashuRedeemer // nil unless the Cashu accept-and-melt option is enabled
	publicURL       string                  // portal base URL for checkout/pay redirects
	pacHost         string                  // exit <npub>.fips host for served PACs ("" = derive from publicURL)
	tmpl            *template.Template
}

func newPortal(st *store.Store, sessionSecret, challengeSecret, captiveSecret []byte, trustFips, secure bool) (*portal, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{"bytes": humanBytes, "sats": sats, "rate": rate}).
		ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &portal{
		store: st, sessionSecret: sessionSecret, challengeSecret: challengeSecret,
		captiveSecret: captiveSecret, trustFipsSource: trustFips, secureCookies: secure, tmpl: tmpl,
	}, nil
}

func (p *portal) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", p.root)
	mux.HandleFunc("GET /login", p.loginPage)
	mux.HandleFunc("GET /auth/challenge", p.authChallenge)
	mux.HandleFunc("POST /auth/verify", p.authVerify)
	mux.HandleFunc("POST /auth/fips", p.authFips)
	mux.HandleFunc("POST /auth/logout", p.logout)
	mux.HandleFunc("GET /dashboard", p.dashboard)
	mux.HandleFunc("POST /whitelist/add", p.whitelistAdd)
	mux.HandleFunc("POST /whitelist/toggle", p.whitelistToggle)
	mux.HandleFunc("GET /captive", p.captive)
	mux.HandleFunc("GET /help", p.help)
	mux.HandleFunc("GET /proxy-clear.pac", p.pacFor("clearnet")) // Connectivity profile
	mux.HandleFunc("GET /proxy-priv.pac", p.pacFor("tor"))       // Privacy profile
	mux.HandleFunc("GET /fips.pac", p.pacFor("clearnet"))        // back-compat alias
	mux.HandleFunc("GET /packages", p.packagesPage)
	mux.HandleFunc("GET /status", p.status)
	mux.HandleFunc("POST /buy", p.buy)
	mux.HandleFunc("GET /pay/{id}", p.payPage)
	mux.HandleFunc("GET /pay/{id}/status", p.payStatus)
	mux.HandleFunc("POST /pay/{id}/cashu", p.payCashu)
	mux.HandleFunc("POST /pay/{id}/cashu-receive", p.cashuReceive)
}

// payPage shows a Lightning invoice (BOLT11) for a pending purchase and polls
// for payment; once settled it sends the buyer to the dashboard.
func (p *portal) payPage(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	v, err := p.store.PurchaseForPay(r.Context(), r.PathValue("id"), npub)
	if err != nil {
		http.Error(w, "purchase not found", http.StatusNotFound)
		return
	}
	if v.Status == "settled" {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	var qr template.URL
	if v.Bolt11 != "" {
		// Uppercase → QR alphanumeric mode (denser, easier to scan); bech32 is
		// case-insensitive so wallets accept it.
		qr = qrDataURI(strings.ToUpper(v.Bolt11))
	}
	data := map[string]any{
		"ID": r.PathValue("id"), "Bolt11": v.Bolt11, "Name": v.PackageName,
		"PriceMsat": v.PriceMsat, "Status": v.Status, "QR": qr,
		"Cashu": p.cashu != nil,
	}
	// Cashu: a NUT-18 payment request (creqA…) the buyer's wallet can scan, with
	// its own QR — paying it POSTs a token to /pay/{id}/cashu-receive. The paste
	// box works for wallets without NUT-18.
	if p.cashu != nil && v.Bolt11 != "" {
		// Ask for the invoice plus a 1% fee headroom: a Cashu melt needs proofs
		// covering amount + the mint's fee_reserve, so a token equal to the bare
		// price is rejected as underfunded (both the scanned request and the paste
		// box must be sized this way).
		meltSat := payments.MeltAmount(uint64(v.PriceMsat / 1000))
		data["CashuAmount"] = meltSat
		target := p.publicURL + "/pay/" + r.PathValue("id") + "/cashu-receive"
		if req, err := p.cashu.PaymentRequest(meltSat, target); err == nil {
			data["CashuReq"] = req
			data["CashuQR"] = qrDataURI(req)
		}
	}
	p.render(w, "pay.html", data)
}

// cashuReceive is the NUT-18 transport target: the payer's Cashu wallet POSTs a
// token here (no portal session — it's a separate app), and we melt its proofs to
// the purchase's invoice. Grant then flows via the phoenixd receipt like any
// other payment. Unscoped by owner: paying only ever credits the purchase owner.
func (p *portal) cashuReceive(w http.ResponseWriter, r *http.Request) {
	// NUT-18 wallets parse this response as JSON, so every reply here must be
	// JSON — a plain-text body makes the payer's wallet throw a JSON parse error
	// ("Unexpected character: b" from "bad payload") instead of showing the real
	// outcome.
	if p.cashu == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "cashu payments not enabled"})
		return
	}
	id := r.PathValue("id")
	bolt11, status, err := p.store.PurchaseInvoice(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "purchase not found"})
		return
	}
	if status == "settled" {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	if bolt11 == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no lightning invoice for this purchase"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		log.Printf("portal: cashu-receive read body for purchase %s: %v", id, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not read body"})
		return
	}
	var meltErr error
	var payload payments.PaymentRequestPayload
	if err := json.Unmarshal(body, &payload); err == nil && len(payload.Proofs) > 0 {
		_, meltErr = p.cashu.MeltProofs(r.Context(), payload.Mint, payload.Proofs, bolt11)
	} else {
		// Fallback: some wallets POST a bare serialized token (cashuA…/cashuB…)
		// rather than a NUT-18 JSON payload. Log why the JSON path was skipped so
		// the real cause is visible, then try the body as a token.
		log.Printf("portal: cashu-receive body for %s not a NUT-18 payload (err=%v, proofs=%d); trying as bare token", id, err, len(payload.Proofs))
		_, meltErr = p.cashu.Melt(r.Context(), string(body), bolt11)
	}
	if meltErr != nil {
		log.Printf("portal: cashu-receive melt for purchase %s: %v", id, meltErr)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "melt failed: " + meltErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// payCashu redeems a pasted Cashu token by melting it (at the token's own mint)
// to the purchase's Lightning invoice. The mint pays our phoenixd invoice, and
// the normal phoenixd webhook/reconciler path grants the entitlement — so this
// handler just kicks off the melt and the pay page's poll finishes the job.
func (p *portal) payCashu(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if p.cashu == nil {
		http.Error(w, "cashu payments not enabled", http.StatusNotFound)
		return
	}
	v, err := p.store.PurchaseForPay(r.Context(), r.PathValue("id"), npub)
	if err != nil {
		http.Error(w, "purchase not found", http.StatusNotFound)
		return
	}
	if v.Status == "settled" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if v.Bolt11 == "" {
		http.Error(w, "no lightning invoice for this purchase", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		http.Error(w, "no token", http.StatusBadRequest)
		return
	}
	if _, err := p.cashu.Melt(r.Context(), token, v.Bolt11); err != nil {
		log.Printf("portal: cashu melt for purchase %s: %v", r.PathValue("id"), err)
		http.Error(w, "token rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Payment initiated; phoenixd receipt -> webhook/reconciler -> grant. The pay
	// page keeps polling /pay/{id}/status and redirects on settle.
	w.WriteHeader(http.StatusAccepted)
}

// payStatus returns the purchase status as JSON for the pay page's poll.
func (p *portal) payStatus(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	v, err := p.store.PurchaseForPay(r.Context(), r.PathValue("id"), npub)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": v.Status})
}

func (p *portal) root(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.session(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (p *portal) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.session(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	data := map[string]any{}
	if npub, ok := p.transparentNpub(r); ok {
		data["FipsHint"] = npub // known address — one-click continue
	} else if p.fipsSource(r) {
		data["FipsSource"] = true // on fips but unknown — offer npub entry (verified against the source)
	}
	p.render(w, "login.html", data)
}

// fipsSource reports whether transparent login is enabled and the request
// arrives from a valid fips (fd00::/8) source address.
func (p *portal) fipsSource(r *http.Request) bool {
	if !p.trustFipsSource {
		return false
	}
	src, err := sourceAddr(r)
	return err == nil && fipsaddr.Valid(src)
}

func (p *portal) authChallenge(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"challenge": nostr.IssueChallenge(p.challengeSecret, time.Now().Unix()),
	})
}

func (p *portal) authVerify(w http.ResponseWriter, r *http.Request) {
	var ev nostr.Event
	jsonReq := strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
	if jsonReq {
		var body struct {
			Event nostr.Event `json:"event"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			p.authFail(w, jsonReq, "bad request")
			return
		}
		ev = body.Event
	} else {
		if err := json.Unmarshal([]byte(r.FormValue("event")), &ev); err != nil {
			p.authFail(w, jsonReq, "invalid event JSON")
			return
		}
	}

	npub, err := nostr.Verify(&ev)
	if err != nil {
		p.authFail(w, jsonReq, "signature did not verify")
		return
	}
	if ev.Kind != nostr.AuthEventKind {
		p.authFail(w, jsonReq, "wrong event kind")
		return
	}
	now := time.Now().Unix()
	if err := nostr.VerifyChallenge(p.challengeSecret, nostr.ExtractChallenge(&ev), now); err != nil {
		p.authFail(w, jsonReq, "invalid or expired challenge")
		return
	}
	if ev.CreatedAt < now-nostr.ChallengeTTLSeconds || ev.CreatedAt > now+60 {
		p.authFail(w, jsonReq, "stale event")
		return
	}
	if _, err := p.store.CreateAccount(r.Context(), npub); err != nil {
		p.authFail(w, jsonReq, "could not create account")
		return
	}
	p.setSession(w, npub)
	if jsonReq {
		writeJSON(w, http.StatusOK, map[string]string{"redirect": "/dashboard"})
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (p *portal) authFail(w http.ResponseWriter, jsonReq bool, msg string) {
	if jsonReq {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
		return
	}
	http.Error(w, msg, http.StatusUnauthorized)
}

// authFips is the transparent fips-source login: the trusted source address
// (npub-derived) authenticates the identity, no signature required.
func (p *portal) authFips(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.transparentNpub(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if _, err := p.store.CreateAccount(r.Context(), npub); err != nil {
		log.Printf("portal: authFips CreateAccount(%s): %v", npub, err)
		http.Error(w, "could not create account", http.StatusInternalServerError)
		return
	}
	p.setSession(w, npub)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (p *portal) logout(w http.ResponseWriter, r *http.Request) {
	p.clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (p *portal) dashboard(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	summary, err := p.store.Summary(r.Context(), npub)
	if err == store.ErrAccountNotFound {
		if _, err = p.store.CreateAccount(r.Context(), npub); err == nil {
			summary, err = p.store.Summary(r.Context(), npub)
		}
	}
	if err != nil {
		http.Error(w, "error loading account", http.StatusInternalServerError)
		return
	}
	data := map[string]any{"S": summary, "Active": anyActive(summary), "Err": r.URL.Query().Get("err")}
	if clear, priv := p.pacLinks(r.Context()); clear != "" {
		data["PacClearURL"] = clear
		data["PacPrivURL"] = priv // may be "" if Privacy isn't enabled
	}
	p.render(w, "dashboard.html", data)
}

func (p *portal) whitelistAdd(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	err := p.store.AddWhitelist(r.Context(), npub, strings.TrimSpace(r.FormValue("guest_npub")), strings.TrimSpace(r.FormValue("label")))
	if err != nil {
		http.Redirect(w, r, "/dashboard?err="+urlq(friendlyErr(err)), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (p *portal) whitelistToggle(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	enabled := r.FormValue("enabled") == "true"
	if err := p.store.SetWhitelistEnabled(r.Context(), npub, strings.TrimSpace(r.FormValue("guest_npub")), enabled); err != nil {
		http.Redirect(w, r, "/dashboard?err="+urlq(friendlyErr(err)), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (p *portal) packagesPage(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		// Direct-buy entry: /packages?npub=<npub> arriving over fips. Verify the
		// claimed npub against the fd00::/8 source address and open a session, so
		// a buyer can purchase without first visiting /login. Falls back to the
		// bare source address when no npub is supplied (a known fips visitor).
		npub, ok = p.transparentNpub(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, err := p.store.CreateAccount(r.Context(), npub); err != nil {
			log.Printf("portal: packages CreateAccount(%s): %v", npub, err)
			http.Error(w, "could not create account", http.StatusInternalServerError)
			return
		}
		p.setSession(w, npub)
	}
	pkgs, err := p.store.ListPackages(r.Context())
	if err != nil {
		http.Error(w, "error loading packages", http.StatusInternalServerError)
		return
	}
	services, _ := p.store.EnabledServices(r.Context()) // non-fatal; the explainer is optional
	// Npub goes into the buy form as a hidden field so a cookie-less client
	// (captive webview / script) still authenticates /buy against its fips source.
	p.render(w, "packages.html", map[string]any{
		"Packages": pkgs, "Services": services, "Npub": npub, "Pending": r.URL.Query().Get("pending") != "",
	})
}

// status is a machine-readable payment check for the direct-buy flow. It
// identifies the caller — session cookie first, else a ?npub= claim verified
// against the fips source address, else the bare fips source — and reports
// whether that account has an active data package:
//
//	200 OK               — active package (JSON {"active":true,"expires_at":...})
//	402 Payment Required — identified but no active package (JSON {"active":false,"buy_url":...})
//	401 Unauthorized     — the caller can't be identified (no session, not on fips)
//
// A client polls this after sending a buyer to /packages?npub=<npub>; the flip
// from 402 to 200 signals that the purchase has settled.
func (p *portal) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	npub, ok := p.session(r)
	if !ok {
		npub, ok = p.transparentNpub(r)
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"active": false,
			"error":  "cannot identify account: sign in, or request over fips with ?npub=<npub>",
		})
		return
	}
	active := false
	var expiresAt time.Time
	switch s, err := p.store.Summary(r.Context(), npub); {
	case err == store.ErrAccountNotFound:
		// A valid identity that simply has no account (never bought anything) yet.
	case err != nil:
		http.Error(w, "error loading account", http.StatusInternalServerError)
		return
	default:
		for _, e := range s.Entitlements {
			if e.Active {
				active = true
				if e.ExpiresAt.After(expiresAt) {
					expiresAt = e.ExpiresAt // access lasts until the last active grant lapses
				}
			}
		}
	}
	body := map[string]any{"active": active, "npub": npub}
	if active {
		if !expiresAt.IsZero() {
			body["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	body["buy_url"] = p.publicURL + "/packages?npub=" + url.QueryEscape(npub)
	writeJSON(w, http.StatusPaymentRequired, body)
}

// help serves the public FAQ / help page. No session required — it's linked from
// the captive and login pages so a not-yet-signed-in visitor can read it.
func (p *portal) help(w http.ResponseWriter, r *http.Request) {
	services, _ := p.store.EnabledServices(r.Context())
	data := map[string]any{"Services": services}
	if clear, priv := p.pacLinks(r.Context()); clear != "" {
		data["PacClearURL"] = clear
		data["PacPrivURL"] = priv // may be "" if Privacy isn't enabled
	}
	p.render(w, "help.html", data)
}

// pacTemplate is the browser proxy auto-config served per profile. %s is the
// exit's <npub>.fips:PORT SOCKS target for that profile. Mirrors deploy/fips.pac:
// .fips / fd00::/8 / localhost go DIRECT, everything else through the exit (no
// DIRECT fallback, so a down exit fails closed rather than leaking around it).
const pacTemplate = `// Generated by the fips-exit portal.
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  var EXIT = "%s";
  if (dnsDomainIs(host, ".fips")) return "DIRECT";
  if (host.indexOf(":") !== -1 && host.substr(0, 2) === "fd") return "DIRECT";
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") return "DIRECT";
  return "SOCKS5 " + EXIT;
}
`

// exitHost is the exit's <npub>.fips host the PACs point at: PORTAL_PAC_HOST if
// set (a bare host, or host:port whose host part is used), else the portal's own
// <npub>.fips host (works when the portal and exit are the same machine). It must
// be a .fips name, since a proxied browser can't reliably bypass an IPv6 literal.
func (p *portal) exitHost() string {
	h := p.pacHost
	if h == "" {
		if u, err := url.Parse(p.publicURL); err == nil {
			h = u.Hostname()
		}
	} else if host, _, err := net.SplitHostPort(h); err == nil {
		h = host // tolerate a host:port value
	}
	if strings.HasSuffix(h, ".fips") {
		return h
	}
	return ""
}

// pacTarget returns the SOCKS target (<host>:<port>) for a service key, using the
// catalog port for that service and the exit host. "" if the service isn't
// enabled on this node or no exit host is known.
func (p *portal) pacTarget(ctx context.Context, key string) string {
	host := p.exitHost()
	if host == "" {
		return ""
	}
	services, err := p.store.EnabledServices(ctx)
	if err != nil {
		return ""
	}
	for _, s := range services {
		if s.Key == key {
			return fmt.Sprintf("%s:%d", host, s.Port)
		}
	}
	return ""
}

// pacLinks returns the absolute PAC URLs to advertise for each profile — empty
// string when that profile isn't available (no exit host, or the service isn't
// enabled). Connectivity maps to the 'clearnet' service, Privacy to 'tor'.
func (p *portal) pacLinks(ctx context.Context) (clear, priv string) {
	host := p.exitHost()
	if host == "" {
		return
	}
	services, err := p.store.EnabledServices(ctx)
	if err != nil {
		return
	}
	for _, s := range services {
		switch s.Key {
		case "clearnet":
			clear = p.publicURL + "/proxy-clear.pac"
		case "tor":
			priv = p.publicURL + "/proxy-priv.pac"
		}
	}
	return
}

// pacFor serves the browser proxy auto-config for one service profile. Public
// (linked from the dashboard and FAQ).
func (p *portal) pacFor(key string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := p.pacTarget(r.Context(), key)
		if target == "" {
			http.Error(w, "PAC not available for this profile on this exit", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, pacTemplate, template.JSEscapeString(target))
	}
}

func (p *portal) buy(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		// Direct-buy: a cookie-less fips client (captive webview / script) posts
		// its npub, verified against the fd00::/8 source address — no session
		// round-trip required. Mirrors packagesPage's direct-buy entry, so buying
		// works even when the client that hit /packages?npub= keeps no cookies.
		npub, ok = p.transparentNpub(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, err := p.store.CreateAccount(r.Context(), npub); err != nil {
			log.Printf("portal: buy CreateAccount(%s): %v", npub, err)
			http.Error(w, "could not create account", http.StatusInternalServerError)
			return
		}
	}
	ctx := r.Context()
	packageID := strings.TrimSpace(r.FormValue("package_id"))
	id, err := p.store.CreatePurchase(ctx, npub, packageID)
	if err != nil {
		http.Redirect(w, r, "/packages?err=1", http.StatusSeeOther)
		return
	}

	// Real payment rail: create an invoice. The settlement webhook (+ reconciler
	// for Lightning) grants the entitlement.
	if p.pay != nil {
		pkg, err := p.store.GetPackage(ctx, packageID)
		if err != nil {
			http.Redirect(w, r, "/packages?err=1", http.StatusSeeOther)
			return
		}
		inv, err := p.pay.CreateInvoice(ctx, payments.InvoiceRequest{
			PriceMsat:   pkg.PriceMsat,
			OrderID:     id,
			Description: pkg.Name,
			RedirectURL: p.publicURL + "/dashboard",
		})
		if err != nil {
			http.Redirect(w, r, "/packages?err=1", http.StatusSeeOther)
			return
		}
		if inv.Bolt11 != "" {
			// Lightning: display the invoice on our own page and poll for payment.
			if err := p.store.AttachInvoice(ctx, id, inv.ID, p.publicURL+"/pay/"+id, inv.Bolt11); err != nil {
				http.Redirect(w, r, "/packages?err=1", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/pay/"+id, http.StatusSeeOther)
			return
		}
		// Hosted checkout (BTCPay): redirect the buyer there.
		if err := p.store.AttachInvoice(ctx, id, inv.ID, inv.CheckoutLink, ""); err != nil {
			http.Redirect(w, r, "/packages?err=1", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, inv.CheckoutLink, http.StatusSeeOther)
		return
	}

	if p.autoSettle {
		// Dev shortcut: no payment rail configured — grant immediately.
		if err := p.store.SettlePurchase(ctx, id); err != nil {
			http.Error(w, "settle failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	// No payment rail and not autosettling: the purchase stays pending.
	http.Redirect(w, r, "/packages?pending=1", http.StatusSeeOther)
}

func (p *portal) captive(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Sign in to get online", "Message": "You're not signed in yet. Sign in with your nostr identity to buy access and start browsing."}
	if addr, err := p.verifyCaptiveToken(r.URL.Query().Get("t")); err == nil {
		data["Addr"] = addr.String()
		if npub, err := p.store.NpubByAddr(r.Context(), addr); err == nil {
			data["Npub"] = npub
			if s, err := p.store.Summary(r.Context(), npub); err == nil && !anyActive(s) {
				data["Title"] = "Out of data"
				data["Message"] = "Your data package has run out or expired. Top up in a few taps and you'll be back online right away — Lightning payments unlock instantly."
			}
		} else {
			data["Title"] = "Welcome to fips-exit"
			data["Message"] = "We don't recognize this fips identity yet. Sign in with your nostr key to get started — it only takes a moment."
		}
	}
	p.render(w, "captive.html", data)
}

// transparentNpub resolves the source address to an npub when transparent fips
// login is enabled and the source is a fips (fd00::/8) address. A ?npub= claim
// is accepted only if it derives to the trusted source address.
func (p *portal) transparentNpub(r *http.Request) (string, bool) {
	if !p.trustFipsSource {
		return "", false
	}
	src, err := sourceAddr(r)
	if err != nil || !fipsaddr.Valid(src) {
		return "", false
	}
	if claim := r.FormValue("npub"); claim != "" {
		if fipsaddr.CheckDerivation(claim, src) == nil {
			return claim, true
		}
		return "", false
	}
	npub, err := p.store.NpubByAddr(r.Context(), src)
	if err != nil {
		return "", false
	}
	return npub, true
}

func (p *portal) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Portal pages are dynamic and per-session; never let a browser (or the
	// captive bounce) serve a stale copy — otherwise customers see old copy,
	// prices, or account state after an update.
	w.Header().Set("Cache-Control", "no-store")
	if err := p.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// verifyCaptiveToken re-derives the captive daemon's token MAC (see
// captive/token.go): outer = base64url("<addr>|<exp>|<mac>").
func (p *portal) verifyCaptiveToken(token string) (netip.Addr, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return netip.Addr{}, err
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return netip.Addr{}, fmt.Errorf("malformed token")
	}
	h := hmac.New(sha256.New, p.captiveSecret)
	h.Write([]byte(parts[0] + "|" + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])
	if !hmac.Equal([]byte(parts[2]), []byte(want)) {
		return netip.Addr{}, fmt.Errorf("bad token signature")
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return netip.Addr{}, fmt.Errorf("expired token")
	}
	return netip.ParseAddr(parts[0])
}

func sourceAddr(r *http.Request) (netip.Addr, error) {
	host := r.RemoteAddr
	if h, _, err := splitHostPort(host); err == nil {
		host = h
	}
	return netip.ParseAddr(host)
}

func splitHostPort(hostport string) (host, port string, err error) {
	// net.SplitHostPort but tolerant of a bare host.
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 {
		return hostport, "", fmt.Errorf("no port")
	}
	if strings.HasPrefix(hostport, "[") {
		end := strings.IndexByte(hostport, ']')
		if end < 0 {
			return "", "", fmt.Errorf("bad bracket")
		}
		return hostport[1:end], hostport[end+2:], nil
	}
	return hostport[:i], hostport[i+1:], nil
}

func anyActive(s store.AccountSummary) bool {
	for _, e := range s.Entitlements {
		if e.Active {
			return true
		}
	}
	return false
}

func friendlyErr(err error) string {
	switch err {
	case store.ErrAddressInUse:
		return "That identity is already active on another account."
	default:
		return "Could not add that identity (check the npub)."
	}
}

func urlq(s string) string { return strings.ReplaceAll(template.URLQueryEscaper(s), "+", "%20") }

// sats renders a millisatoshi price as a whole-sat string.
func sats(msat int64) string {
	return strconv.FormatInt(msat/1000, 10) + " sats"
}

// rate renders a rate_ppm (1e6 = 1.0) as a human multiplier, e.g. "1.5×".
func rate(ppm int64) string {
	return strconv.FormatFloat(float64(ppm)/1_000_000, 'f', -1, 64) + "×"
}

func humanBytes(n int64) string {
	const u = 1000
	if n < u {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}
