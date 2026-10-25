package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
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
	// LastAuthzOK is when the backend last answered an authz sync. Persisted so
	// the fail-closed grace window keeps counting across restarts; otherwise an
	// agent crash-looping through an outage would never fail closed.
	LastAuthzOK time.Time `json:"last_authz_ok,omitempty"`
	// PrimeBaselines is set when runtime state had to be discarded (corrupt
	// file): the next collection records the current counters as baselines
	// without reporting them, so already-billed bytes aren't billed again.
	PrimeBaselines bool `json:"prime_baselines,omitempty"`
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
	recovered, err := s.load()
	if err != nil {
		return nil, err
	}
	if recovered {
		// Persist the clean state (with PrimeBaselines) right away: a crash
		// before the first collection would otherwise come back with no file
		// at all, no prime flag, and bill every live counter a second time.
		if err := writeJSONAtomic(filepath.Join(dir, "runtime.json"), s.rt, 0o600); err != nil {
			return nil, fmt.Errorf("state: persist recovered runtime: %w", err)
		}
	}
	return s, nil
}

// load reads identity and runtime state; recovered reports that a corrupt
// runtime file was moved aside and a clean state substituted.
func (s *store) load() (recovered bool, err error) {
	if b, err := os.ReadFile(filepath.Join(s.dir, "identity.json")); err == nil {
		var id identity
		if err := json.Unmarshal(b, &id); err != nil {
			return false, fmt.Errorf("state: parse identity: %w", err)
		}
		s.id = &id
	}
	rtPath := filepath.Join(s.dir, "runtime.json")
	if b, err := os.ReadFile(rtPath); err == nil {
		var rt runtime
		if err := json.Unmarshal(b, &rt); err != nil {
			// A torn or corrupt runtime file (crash mid-write before fsync was
			// added, disk trouble) must not keep the agent down: the file only
			// holds resumable state. Keep it for forensics and start clean with
			// a forced full reconcile (rev 0) and primed baselines.
			bak := fmt.Sprintf("%s.corrupt-%d", rtPath, time.Now().Unix())
			if rerr := os.Rename(rtPath, bak); rerr != nil {
				return false, fmt.Errorf("state: parse runtime: %w (and could not move it aside: %v)", err, rerr)
			}
			log.Printf("state: runtime.json unreadable (%v); moved to %s, starting from clean state", err, bak)
			s.rt = &runtime{Baselines: map[string]uint64{}, PrimeBaselines: true}
			recovered = true
		} else {
			s.rt = &rt
		}
	}
	if s.rt == nil {
		s.rt = &runtime{Baselines: map[string]uint64{}}
	}
	if s.rt.Baselines == nil {
		s.rt.Baselines = map[string]uint64{}
	}
	return recovered, nil
}

// authzRev returns the persisted cursor without copying the whole runtime.
func (s *store) authzRev() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rt.AuthzRev
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

// writeJSONAtomic writes v to path via a temp file, fsync and rename, then
// fsyncs the directory so the rename itself is durable. Without the fsyncs a
// power loss shortly after the rename could leave a zero-length or truncated
// file in place, which is exactly the corruption load() has to recover from.
func writeJSONAtomic(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
