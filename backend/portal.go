package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
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
	autoSettle      bool             // dev: settle purchases immediately (no payment)
	pay             *payments.Client // nil until BTCPay is configured
	publicURL       string           // portal base URL for BTCPay checkout redirects
	tmpl            *template.Template
}

func newPortal(st *store.Store, sessionSecret, challengeSecret, captiveSecret []byte, trustFips, secure bool) (*portal, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{"bytes": humanBytes, "sats": sats}).
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
	mux.HandleFunc("GET /packages", p.packagesPage)
	mux.HandleFunc("POST /buy", p.buy)
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
	hint := ""
	if npub, ok := p.transparentNpub(r); ok {
		hint = npub
	}
	p.render(w, "login.html", map[string]any{"FipsHint": hint})
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
	p.render(w, "dashboard.html", map[string]any{"S": summary, "Err": r.URL.Query().Get("err")})
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
	if _, ok := p.session(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	pkgs, err := p.store.ListPackages(r.Context())
	if err != nil {
		http.Error(w, "error loading packages", http.StatusInternalServerError)
		return
	}
	p.render(w, "packages.html", map[string]any{"Packages": pkgs, "Pending": r.URL.Query().Get("pending") != ""})
}

func (p *portal) buy(w http.ResponseWriter, r *http.Request) {
	npub, ok := p.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	packageID := strings.TrimSpace(r.FormValue("package_id"))
	id, err := p.store.CreatePurchase(ctx, npub, packageID)
	if err != nil {
		http.Redirect(w, r, "/packages?err=1", http.StatusSeeOther)
		return
	}

	// Real payment rail: create a BTCPay invoice and send the buyer to checkout.
	// The webhook grants the entitlement (optimistically on Processing).
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
		if err := p.store.AttachInvoice(ctx, id, inv.ID, inv.CheckoutLink); err != nil {
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
	data := map[string]any{"Title": "Sign in to continue", "Message": "This identity is not currently authorized for internet access."}
	if addr, err := p.verifyCaptiveToken(r.URL.Query().Get("t")); err == nil {
		data["Addr"] = addr.String()
		if npub, err := p.store.NpubByAddr(r.Context(), addr); err == nil {
			data["Npub"] = npub
			if s, err := p.store.Summary(r.Context(), npub); err == nil && !anyActive(s) {
				data["Title"] = "Out of data"
				data["Message"] = "Your packages are exhausted or expired. Buy more to continue."
			}
		} else {
			data["Title"] = "Unknown identity"
			data["Message"] = "We don't recognize this fips identity yet. Sign in to get started."
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
