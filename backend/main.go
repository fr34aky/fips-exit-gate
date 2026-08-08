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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fr34aky/fips-exit-gate/backend/store"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("backend: DATABASE_URL is required")
	}
	listen := getenv("LISTEN", ":8080")
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		log.Fatal("backend: ADMIN_TOKEN is required (protects /admin)")
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

	h := &handlers{
		store:          st,
		usageIntervalS: getenvInt("USAGE_INTERVAL_S", 30),
		graceMinutes:   getenvInt("GRACE_MINUTES", 240),
	}
	p, err := newPortal(st,
		secretEnv("SESSION_SECRET"),
		secretEnv("CHALLENGE_SECRET"),
		[]byte(os.Getenv("CAPTIVE_TOKEN_SECRET")),
		os.Getenv("PORTAL_TRUST_FIPS_SOURCE") == "1",
		os.Getenv("PORTAL_SECURE_COOKIES") != "0",
	)
	if err != nil {
		log.Fatalf("backend: portal: %v", err)
	}
	p.autoSettle = os.Getenv("PORTAL_DEV_AUTOSETTLE") == "1"
	srv := &http.Server{
		Addr:              listen,
		Handler:           routes(h, p, st, adminToken),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	log.Printf("backend listening on %s", listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("backend: %v", err)
	}
}

func routes(h *handlers, p *portal, st *store.Store, adminToken string) http.Handler {
	mux := http.NewServeMux()

	// Agent API: enroll is unauthenticated (uses the enroll token in-body);
	// the rest require the node's bearer auth token.
	mux.HandleFunc("POST /v1/nodes/enroll", h.enroll)
	mux.Handle("GET /v1/nodes/{id}/authz", requireNode(st, h.authz))
	mux.Handle("POST /v1/nodes/{id}/usage", requireNode(st, h.usage))
	mux.Handle("POST /v1/nodes/{id}/heartbeat", requireNode(st, h.heartbeat))

	// Admin API (static bearer token).
	mux.Handle("POST /admin/enroll-token", requireAdmin(adminToken, h.adminEnrollToken))
	mux.Handle("POST /admin/accounts", requireAdmin(adminToken, h.adminCreateAccount))
	mux.Handle("POST /admin/whitelist", requireAdmin(adminToken, h.adminWhitelist))
	mux.Handle("POST /admin/credit", requireAdmin(adminToken, h.adminCredit))
	mux.Handle("GET /admin/authz", requireAdmin(adminToken, h.adminAuthz))
	mux.Handle("GET /admin/packages", requireAdmin(adminToken, h.adminListPackages))
	mux.Handle("POST /admin/packages", requireAdmin(adminToken, h.adminCreatePackage))
	mux.Handle("POST /admin/settle", requireAdmin(adminToken, h.adminSettle))

	// User portal (login, dashboard, whitelist, captive landing).
	p.routes(mux)

	return mux
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
