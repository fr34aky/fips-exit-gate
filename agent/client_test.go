package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestBackendClientRoundTrips(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/nodes/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"node_id":"n1","auth_token":"t1"}`))
	})
	// authz: return 204 when rev=5, else a full set.
	mux.HandleFunc("GET /v1/nodes/{id}/authz", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("rev") == "5" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer t1" {
			t.Errorf("missing bearer auth, got %q", got)
		}
		w.Write([]byte(`{"rev":6,"full":true,"addresses":[{"addr":"fd00::1","account":"a"}]}`))
	})
	mux.HandleFunc("POST /v1/nodes/{id}/usage", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ack":"ok","revoke":["fd00::9"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newBackendClient(srv.URL)
	ctx := context.Background()

	en, err := c.enroll(ctx, enrollRequest{EnrollToken: "e", NodePubkey: "p", Name: "n"})
	if err != nil || en.NodeID != "n1" || en.AuthToken != "t1" {
		t.Fatalf("enroll: %+v %v", en, err)
	}
	c.setAuth(en.NodeID, en.AuthToken)

	az, err := c.getAuthz(ctx, 0, 1)
	if err != nil {
		t.Fatalf("getAuthz: %v", err)
	}
	if !az.Full || len(az.Addresses) != 1 || az.Addresses[0].Addr != netip.MustParseAddr("fd00::1") {
		t.Fatalf("authz decode wrong: %+v", az)
	}

	if _, err := c.getAuthz(ctx, 5, 1); err != errUnchanged {
		t.Fatalf("expected errUnchanged for 204, got %v", err)
	}

	ack, err := c.postUsage(ctx, usageReport{ReportID: "r1"})
	if err != nil || ack.Ack != "ok" || len(ack.Revoke) != 1 {
		t.Fatalf("usage ack wrong: %+v %v", ack, err)
	}
}
