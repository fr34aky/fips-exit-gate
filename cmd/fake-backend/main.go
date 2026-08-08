// Command fake-backend is a minimal, in-memory stand-in for the fips-exit
// backend API, used to develop and demo the exit-agent before the real backend
// (Phase 3) exists. It implements just enough of docs/api-agent-backend.md to
// drive an agent, plus tiny admin endpoints to grant/revoke and inspect usage.
//
// NOT for production: no auth enforcement, no persistence, single node.
//
//	go run ./cmd/fake-backend           # listens on :8080
//	curl -XPOST localhost:8080/admin/grant  -d fd10::1
//	curl -XPOST localhost:8080/admin/revoke -d fd10::1
//	curl localhost:8080/admin/usage
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"
)

type member struct {
	Addr    netip.Addr `json:"addr"`
	Account string     `json:"account"`
}

type server struct {
	mu       sync.Mutex
	rev      int64
	authz    map[netip.Addr]string // addr -> account
	revoke   []netip.Addr          // queued inline revocations for next usage ack
	usage    map[string]uint64     // "service|addr" -> total bytes
	services []serviceInfo
}

type serviceInfo struct {
	Key  string `json:"key"`
	Port uint16 `json:"port"`
}

func newServer() *server {
	return &server{
		authz: map[netip.Addr]string{},
		usage: map[string]uint64{},
		services: []serviceInfo{
			{Key: "clearnet", Port: 1080},
			{Key: "tor", Port: 1081},
		},
	}
}

func (s *server) enroll(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"node_id": "node-dev", "auth_token": "dev-token"})
}

func (s *server) authzHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Simplest correct behavior: always answer with the full current set. (A
	// real backend would honor rev/wait for long-poll deltas.)
	addrs := make([]member, 0, len(s.authz))
	for a, acct := range s.authz {
		addrs = append(addrs, member{Addr: a, Account: acct})
	}
	writeJSON(w, map[string]any{"rev": s.rev, "full": true, "addresses": addrs})
}

func (s *server) usageHandler(w http.ResponseWriter, r *http.Request) {
	var report struct {
		Samples []struct {
			Service string     `json:"service"`
			Addr    netip.Addr `json:"addr"`
			Bytes   uint64     `json:"bytes"`
		} `json:"samples"`
	}
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	s.mu.Lock()
	for _, smp := range report.Samples {
		s.usage[smp.Service+"|"+smp.Addr.String()] += smp.Bytes
	}
	revoke := s.revoke
	s.revoke = nil
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ack": fmt.Sprintf("%d", time.Now().UnixNano()), "revoke": revoke})
}

func (s *server) heartbeat(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	svc := s.services
	s.mu.Unlock()
	writeJSON(w, map[string]any{"config": map[string]any{
		"usage_interval_s": 5, // fast for demos
		"grace_minutes":    240,
		"services":         svc,
	}})
}

// --- admin ------------------------------------------------------------------

func (s *server) grant(w http.ResponseWriter, r *http.Request) {
	addr, ok := readAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	s.authz[addr] = "dev-account"
	s.rev++
	s.mu.Unlock()
	fmt.Fprintf(w, "granted %s\n", addr)
}

func (s *server) revokeAdmin(w http.ResponseWriter, r *http.Request) {
	addr, ok := readAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	delete(s.authz, addr)
	s.rev++
	s.revoke = append(s.revoke, addr) // also push inline on next usage ack
	s.mu.Unlock()
	fmt.Fprintf(w, "revoked %s\n", addr)
}

func (s *server) usageDump(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, s.usage)
}

func readAddr(w http.ResponseWriter, r *http.Request) (netip.Addr, bool) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 256))
	addr, err := netip.ParseAddr(string(trimSpace(b)))
	if err != nil {
		http.Error(w, "bad address", 400)
		return netip.Addr{}, false
	}
	return addr, true
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	addr := ":8080"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	s := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/nodes/enroll", s.enroll)
	mux.HandleFunc("GET /v1/nodes/{id}/authz", s.authzHandler)
	mux.HandleFunc("POST /v1/nodes/{id}/usage", s.usageHandler)
	mux.HandleFunc("POST /v1/nodes/{id}/heartbeat", s.heartbeat)
	mux.HandleFunc("POST /admin/grant", s.grant)
	mux.HandleFunc("POST /admin/revoke", s.revokeAdmin)
	mux.HandleFunc("GET /admin/usage", s.usageDump)

	log.Printf("fake-backend listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
