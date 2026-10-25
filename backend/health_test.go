package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHealthAndReadiness(t *testing.T) {
	st := testStoreMain(t)
	p := testPortal(t, st, false)
	h := &handlers{store: st, usageIntervalS: 30, graceMinutes: 240}
	srv := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv.Close()
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	// A missing migration row makes readiness fail.
	pool, err := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), `DELETE FROM schema_migrations WHERE version = '0001_init.sql'`); err != nil {
		t.Fatal(err)
	}
	// A fresh router has an empty readiness cache.
	srv2 := httptest.NewServer(routes(h, p, st, "admintok", nil, nil, nil, ""))
	defer srv2.Close()
	resp, err := http.Get(srv2.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(resp); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "0001_init.sql") {
		t.Fatalf("readyz with a missing migration: %d %s", resp.StatusCode, body)
	}
}
