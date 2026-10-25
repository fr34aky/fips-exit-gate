// Command backend is the fips-exit control plane: the agent-facing API
// (enroll/authz/usage/heartbeat) plus admin endpoints, backed by Postgres.
// It is the production replacement for cmd/fake-backend.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fr34aky/fips-exit-gate/backend/payments"
	"github.com/fr34aky/fips-exit-gate/backend/store"
	"github.com/fr34aky/fips-exit-gate/pkg/version"
	"github.com/fr34aky/fips-exit-gate/pkg/logging"
)

func main() {
	logging.Setup("backend")
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("backend: DATABASE_URL is required")
	}
	listen := getenv("LISTEN", ":8080")
	// Admin API and metrics get their own listener, loopback by default, so the
	// static admin token is never reachable from the fips-facing portal port.
	listenAdmin := getenv("LISTEN_ADMIN", "127.0.0.1:8081")
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		log.Fatal("backend: ADMIN_TOKEN is required (protects /admin)")
	}
	if os.Getenv("CAPTIVE_TOKEN_SECRET") == "" {
		// The captive daemon requires it; with an empty secret here anyone could
		// forge tokens and have /captive reveal an address's account state.
		log.Fatal("backend: CAPTIVE_TOKEN_SECRET is required (must equal the exit nodes' value)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		log.Fatalf("backend: %v", err)
	}
	defer st.Close()
	if err := st.SeedDefaults(ctx); err != nil {
		log.Fatalf("backend: seed: %v", err)
	}
	if err := st.SeedPackages(ctx); err != nil {
		log.Fatalf("backend: seed packages: %v", err)
	}
	st.MaxGuests = getenvInt("MAX_GUESTS_PER_ACCOUNT", store.DefaultMaxGuests)

	wg := loadWgSettings()
	st.WgPools = wg.pools
	st.MaxWgPeersPerAddr = getenvInt("WG_MAX_PEERS_PER_ADDR", store.DefaultMaxWgPeersPerAddr)
	h := &handlers{
		store:           st,
		usageIntervalS:  getenvInt("USAGE_INTERVAL_S", 30),
		graceMinutes:    getenvInt("GRACE_MINUTES", 240),
		revs:            newRevWaiter(),
		allowMassRevoke: os.Getenv("AUTHZ_ALLOW_MASS_REVOKE") == "1",
		wg:              wg,
	}
	if h.allowMassRevoke {
		log.Printf("backend: AUTHZ_ALLOW_MASS_REVOKE=1 — agents will apply full reconciles that revoke most of their set")
	}
	// Wake agent long-polls the moment RecomputeAuthz commits (LISTEN/NOTIFY);
	// the handler keeps a slow poll as a backstop.
	go st.ListenAuthz(ctx, h.revs.broadcast)
	// Time-driven expiry: entitlements that lapse while their account is idle.
	go runExpirySweep(ctx, st, time.Duration(getenvInt("EXPIRY_SWEEP_S", 60))*time.Second)
	p, err := newPortal(st,
		secretEnv("SESSION_SECRET"),
		secretEnv("CHALLENGE_SECRET"),
		[]byte(os.Getenv("CAPTIVE_TOKEN_SECRET")),
		// Transparent fips-source login is ON by default (the portal is meant to
		// be reached natively over fips, and it shares the same source-address
		// trust model the exit gate already relies on). Set 0 only when a reverse
		// proxy masks the source (e.g. a public HTTPS-fronted portal).
		os.Getenv("PORTAL_TRUST_FIPS_SOURCE") != "0",
		// Secure cookies OFF by default so login works over the fips portal (HTTP).
		// Set 1 when the portal is served over HTTPS.
		os.Getenv("PORTAL_SECURE_COOKIES") == "1",
	)
	if err != nil {
		log.Fatalf("backend: portal: %v", err)
	}
	p.autoSettle = os.Getenv("PORTAL_DEV_AUTOSETTLE") == "1"
	p.publicURL = strings.TrimRight(getenv("PORTAL_PUBLIC_URL", "http://localhost:8080"), "/")
	p.pacHost = os.Getenv("PORTAL_PAC_HOST") // e.g. npub1…exit….fips; empty = derive from PORTAL_PUBLIC_URL
	p.wg = wg

	m := newAppMetrics(st)

	// Payments: the rail is chosen by PAYMENT_RAIL (btcpay | phoenixd). Each rail
	// requires its webhook secret so settlements can't be forged. Without a rail
	// the portal falls back to pending purchases (or dev autosettle).
	var ph *payHandler
	var phx *phoenixdHandler
	var rec *reconciler
	if provider, rail := newPaymentsProvider(); provider != nil {
		p.pay = provider
		switch rail {
		case "btcpay":
			whSecret := os.Getenv("BTCPAY_WEBHOOK_SECRET")
			if whSecret == "" {
				// Without it the webhook HMAC can't be verified and settlements
				// would be forgeable — refuse to start rather than run insecurely.
				log.Fatal("backend: BTCPAY_WEBHOOK_SECRET is required with PAYMENT_RAIL=btcpay")
			}
			ph = &payHandler{store: st, secret: []byte(whSecret), metrics: m.webhook}
			if c, ok := provider.(invoiceChecker); ok {
				ph.checker = c
			} else {
				log.Printf("backend: BTCPay provider cannot re-check invoices; settlement webhooks are trusted on their HMAC alone")
			}
			log.Printf("backend: BTCPay payments enabled")
		case "phoenixd":
			whSecret := os.Getenv("PHOENIXD_WEBHOOK_SECRET")
			if whSecret == "" {
				log.Fatal("backend: PHOENIXD_WEBHOOK_SECRET is required with PAYMENT_RAIL=phoenixd")
			}
			phx = &phoenixdHandler{store: st, secret: []byte(whSecret), metrics: m.webhook}
			rec = &reconciler{
				store:    st,
				ln:       provider.(*payments.Phoenixd),
				interval: time.Duration(getenvInt("PHOENIXD_POLL_INTERVAL_S", 15)) * time.Second,
				ttl:      time.Duration(getenvInt("PHOENIXD_INVOICE_TTL_S", 3600)) * time.Second,
				metrics:  m.webhook,
			}
			log.Printf("backend: phoenixd (Lightning) payments enabled")
			// Cashu accept-and-melt rides the phoenixd rail: a pasted token is
			// melted at its mint to the purchase's bolt11, which phoenixd receives.
			if os.Getenv("CASHU_ACCEPT") == "1" {
				var mints []string
				if s := os.Getenv("CASHU_ACCEPTED_MINTS"); s != "" {
					mints = strings.Split(s, ",")
				}
				var hc *http.Client
				if s := os.Getenv("CASHU_SOCKS5"); s != "" {
					hc = torHTTPClient(s)
				}
				p.cashu = payments.NewCashuRedeemer(mints, hc)
				log.Printf("backend: Cashu accept-and-melt enabled (%d mint(s) allowlisted; 0 = any)", len(mints))
			}
		}
	}
	if os.Getenv("METRICS_TOKEN") == "" {
		log.Printf("backend: METRICS_TOKEN unset — /metrics is open; restrict it by network")
	}

	metricsToken := os.Getenv("METRICS_TOKEN")
	var servers []*http.Server
	if listenAdmin == "" || listenAdmin == listen {
		// Single listener (explicitly requested): everything together.
		servers = append(servers, &http.Server{Addr: listen,
			Handler: routes(h, p, st, adminToken, ph, phx, m, metricsToken), ReadHeaderTimeout: 10 * time.Second})
	} else {
		servers = append(servers,
			&http.Server{Addr: listen, Handler: publicRoutes(h, p, ph, phx), ReadHeaderTimeout: 10 * time.Second},
			&http.Server{Addr: listenAdmin, Handler: adminRoutes(h, adminToken, m, metricsToken), ReadHeaderTimeout: 10 * time.Second})
	}
	if rec != nil {
		go rec.run(ctx)
	}
	go runRetention(ctx, st,
		time.Duration(getenvInt("RETENTION_SWEEP_S", 3600))*time.Second,
		time.Duration(getenvInt("RETENTION_DAYS", 90))*24*time.Hour,
		time.Duration(getenvInt("REVISION_RETENTION_DAYS", 30))*24*time.Hour)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(sctx)
		}
	}()

	errc := make(chan error, len(servers))
	for _, s := range servers {
		s := s
		log.Printf("backend %s listening on %s", version.String(), s.Addr)
		go func() { errc <- s.ListenAndServe() }()
	}
	if err := <-errc; err != nil && err != http.ErrServerClosed {
		log.Fatalf("backend: %v", err)
	}
	<-ctx.Done()
}

// routes mounts everything on one mux (single-listener mode and tests).
func routes(h *handlers, p *portal, st *store.Store, adminToken string, ph *payHandler, phx *phoenixdHandler, m *appMetrics, metricsToken string) http.Handler {
	mux := http.NewServeMux()
	mountPublic(mux, h, p, ph, phx)
	mountAdmin(mux, h, adminToken, m, metricsToken)
	return csrfProtect(mux)
}

// publicRoutes is the fips/Internet-facing listener: portal, agent API,
// payment webhooks. No admin, no metrics.
func publicRoutes(h *handlers, p *portal, ph *payHandler, phx *phoenixdHandler) http.Handler {
	mux := http.NewServeMux()
	mountPublic(mux, h, p, ph, phx)
	return csrfProtect(mux)
}

// adminRoutes is the operator listener (LISTEN_ADMIN, loopback by default).
func adminRoutes(h *handlers, adminToken string, m *appMetrics, metricsToken string) http.Handler {
	mux := http.NewServeMux()
	mountAdmin(mux, h, adminToken, m, metricsToken)
	return mux
}

// csrfProtect rejects state-changing cross-site browser requests using the
// Sec-Fetch-Site / Origin headers every browser sends since 2023 (Go's
// built-in CrossOriginProtection). Non-browser clients (agents, webhooks,
// wallets) send neither header and are unaffected. The Cashu NUT-18 receiver
// is explicitly exempt: web wallets legitimately POST to it cross-origin.
func csrfProtect(mux *http.ServeMux) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern("POST /pay/{id}/cashu-receive")
	return cop.Handler(mux)
}

func mountPublic(mux *http.ServeMux, h *handlers, p *portal, ph *payHandler, phx *phoenixdHandler) {
	st := h.store
	// Liveness / readiness (no auth, no body of interest): /healthz says the
	// process serves requests; /readyz additionally checks the database and
	// that every migration is applied. For load balancers and compose/systemd
	// health checks.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	// /readyz is public and touches the database, so its verdict is cached
	// for a few seconds: a flood of probes costs one query per window, not
	// one pool connection per request.
	ready := &readyCache{check: st.Ready}
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if err := ready.get(r.Context()); err != nil {
			http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})

	// Agent API: enroll is unauthenticated (uses the enroll token in-body);
	// the rest require the node's bearer auth token.
	mux.HandleFunc("POST /v1/nodes/enroll", h.enroll)
	mux.Handle("GET /v1/nodes/{id}/authz", requireNode(st, h.authz))
	mux.Handle("POST /v1/nodes/{id}/usage", requireNode(st, h.usage))
	mux.Handle("POST /v1/nodes/{id}/heartbeat", requireNode(st, h.heartbeat))
	mux.Handle("GET /v1/nodes/{id}/wg", requireNode(st, h.wgPeers))

	// Payment webhooks (HMAC-verified in the handler, so no bearer middleware).
	if ph != nil {
		mux.HandleFunc("POST /payments/btcpay/webhook", ph.webhook)
	}
	if phx != nil {
		mux.HandleFunc("POST /payments/phoenixd/webhook", phx.webhook)
	}

	// User portal (login, dashboard, whitelist, captive landing).
	p.routes(mux)
}

func mountAdmin(mux *http.ServeMux, h *handlers, adminToken string, m *appMetrics, metricsToken string) {
	// Metrics (Prometheus text format). Gated by METRICS_TOKEN if set.
	if m != nil {
		mux.HandleFunc("GET /metrics", serveMetrics(m, metricsToken))
	}
	// Admin API (static bearer token).
	mux.Handle("POST /admin/enroll-token", requireAdmin(adminToken, h.adminEnrollToken))
	mux.Handle("POST /admin/accounts", requireAdmin(adminToken, h.adminCreateAccount))
	mux.Handle("POST /admin/whitelist", requireAdmin(adminToken, h.adminWhitelist))
	mux.Handle("POST /admin/credit", requireAdmin(adminToken, h.adminCredit))
	mux.Handle("GET /admin/authz", requireAdmin(adminToken, h.adminAuthz))
	mux.Handle("GET /admin/accounts/{npub}", requireAdmin(adminToken, h.adminInspect))
	mux.Handle("GET /admin/packages", requireAdmin(adminToken, h.adminListPackages))
	mux.Handle("POST /admin/packages", requireAdmin(adminToken, h.adminCreatePackage))
	mux.Handle("DELETE /admin/packages/{id}", requireAdmin(adminToken, h.adminDeactivatePackage))
	mux.Handle("POST /admin/settle", requireAdmin(adminToken, h.adminSettle))
	mux.Handle("GET /admin/services", requireAdmin(adminToken, h.adminListServices))
	mux.Handle("POST /admin/services", requireAdmin(adminToken, h.adminCreateService))
}

// readyCache memoizes a readiness check for readyTTL.
type readyCache struct {
	check func(context.Context) error
	mu    sync.Mutex
	at    time.Time
	err   error
}

const readyTTL = 5 * time.Second

func (c *readyCache) get(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < readyTTL {
		return c.err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c.err = c.check(cctx)
	c.at = time.Now()
	return c.err
}

// loadWgSettings reads the WireGuard address plan from the environment. The
// exits render their nftables policy from the same values (deploy/.env), so
// a mismatch is a deployment error the agent warns about via the heartbeat.
func loadWgSettings() wgSettings {
	pools := store.DefaultWgPools
	if v := os.Getenv("WG_POOL4"); v != "" {
		pools.Pool4 = mustPrefix("WG_POOL4", v)
	}
	if v := os.Getenv("WG_POOL6"); v != "" {
		pools.Pool6 = mustPrefix("WG_POOL6", v)
	}
	if pools.Pool4.Bits() > 24 || pools.Pool6.Bits() > 64 {
		log.Fatalf("backend: WG_POOL4 must be a /24 or larger and WG_POOL6 a /64 or larger")
	}
	return wgSettings{
		port:  getenvInt("WG_PORT", 51820),
		pools: pools,
		dns4:  pools.Gateway4(),
		dns6:  pools.Gateway6(),
		mtu:   getenvInt("WG_MTU", 1280),
	}
}

func mustPrefix(name, v string) netip.Prefix {
	p, err := netip.ParsePrefix(v)
	if err != nil {
		log.Fatalf("backend: %s: %v", name, err)
	}
	return p.Masked()
}

// secretEnv returns the named secret, or a random ephemeral one (logged) if
// unset — fine for dev; set it in production so sessions survive restarts.
func secretEnv(name string) []byte {
	if v := os.Getenv(name); v != "" {
		return []byte(v)
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	log.Printf("backend: %s unset, using an ephemeral random secret", name)
	return b
}

// requireNode authenticates the node bearer token against the {id} path value.
func requireNode(st *store.Store, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		if err := st.AuthNode(r.Context(), r.PathValue("id"), token); err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "bad node credentials")
			return
		}
		next(w, r)
	})
}

func requireAdmin(adminToken string, next http.HandlerFunc) http.Handler {
	want := []byte(adminToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok || subtle.ConstantTimeCompare([]byte(token), want) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "bad admin token")
			return
		}
		next(w, r)
	})
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok && after != "" {
		return after, true
	}
	return "", false
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
