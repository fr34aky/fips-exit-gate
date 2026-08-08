package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// identity is written once at enrollment and is the node's long-lived secret.
type identity struct {
	NodeID      string `json:"node_id"`
	AuthToken   string `json:"auth_token"`
	PrivSeedB64 string `json:"priv_seed_b64"` // Ed25519 seed (32 bytes)
}

func (id *identity) pubkeyB64() string {
	seed, _ := base64.StdEncoding.DecodeString(id.PrivSeedB64)
	priv := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// runtime is the mutable sync state, persisted so restarts resume cleanly.
type runtime struct {
	AuthzRev      int64             `json:"authz_rev"`
	CounterEpoch  string            `json:"counter_epoch"`
	Baselines     map[string]uint64 `json:"baselines"`      // "addr|port" -> last absolute bytes
	BufferedUsage []usageReport     `json:"buffered_usage"` // undelivered reports (bounded)
}

// store persists identity + runtime under a directory, atomically.
type store struct {
	dir string
	mu  sync.Mutex
	id  *identity
	rt  *runtime
}

func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state: mkdir %s: %w", dir, err)
	}
	s := &store{dir: dir}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *store) load() error {
	if b, err := os.ReadFile(filepath.Join(s.dir, "identity.json")); err == nil {
		var id identity
		if err := json.Unmarshal(b, &id); err != nil {
			return fmt.Errorf("state: parse identity: %w", err)
		}
		s.id = &id
	}
	if b, err := os.ReadFile(filepath.Join(s.dir, "runtime.json")); err == nil {
		var rt runtime
		if err := json.Unmarshal(b, &rt); err != nil {
			return fmt.Errorf("state: parse runtime: %w", err)
		}
		s.rt = &rt
	}
	if s.rt == nil {
		s.rt = &runtime{Baselines: map[string]uint64{}}
	}
	if s.rt.Baselines == nil {
		s.rt.Baselines = map[string]uint64{}
	}
	return nil
}

func (s *store) enrolled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id != nil
}

// newIdentity generates a fresh keypair and returns the pubkey to enroll with;
// the identity is not persisted until saveIdentity is called with the token.
func (s *store) newIdentity() (pubkeyB64 string, seedB64 string) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	seed := priv.Seed()
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(seed)
}

func (s *store) saveIdentity(id identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = &id
	return writeJSONAtomic(filepath.Join(s.dir, "identity.json"), id, 0o600)
}

func (s *store) identity() *identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

// withRuntime runs fn under lock with the runtime, then persists it.
func (s *store) withRuntime(fn func(*runtime)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.rt)
	return writeJSONAtomic(filepath.Join(s.dir, "runtime.json"), s.rt, 0o600)
}

func (s *store) snapshotRuntime() runtime {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.rt
	cp.Baselines = make(map[string]uint64, len(s.rt.Baselines))
	for k, v := range s.rt.Baselines {
		cp.Baselines[k] = v
	}
	cp.BufferedUsage = append([]usageReport(nil), s.rt.BufferedUsage...)
	return cp
}

func writeJSONAtomic(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
