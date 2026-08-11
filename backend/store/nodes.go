package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrInvalidEnrollToken is returned for unknown or already-used tokens.
	ErrInvalidEnrollToken = errors.New("store: invalid or used enroll token")
	// ErrUnauthorized is returned for a bad node id / auth token.
	ErrUnauthorized = errors.New("store: unauthorized")
)

// CreateEnrollToken issues a one-time enrollment token, returning the plaintext
// (only the hash is stored).
func (s *Store) CreateEnrollToken(ctx context.Context, note string) (string, error) {
	token := randToken()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO enroll_tokens(token_hash, note) VALUES ($1, $2)`, sha256Hex(token), note)
	if err != nil {
		return "", err
	}
	return token, nil
}

// EnrollNode consumes an enroll token and creates a node, returning its id and
// a freshly generated auth token (plaintext returned once; only the hash kept).
func (s *Store) EnrollNode(ctx context.Context, enrollToken, nodePubkey, name string) (nodeID, authToken string, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var used *string
		row := tx.QueryRow(ctx,
			`SELECT used_at::text FROM enroll_tokens WHERE token_hash = $1 FOR UPDATE`, sha256Hex(enrollToken))
		switch e := row.Scan(&used); {
		case e == pgx.ErrNoRows:
			return ErrInvalidEnrollToken
		case e != nil:
			return e
		case used != nil:
			return ErrInvalidEnrollToken
		}
		authToken = randToken()
		if err := tx.QueryRow(ctx,
			`INSERT INTO exit_nodes(name, node_pubkey, auth_token_hash) VALUES ($1, $2, $3) RETURNING id::text`,
			name, nodePubkey, sha256Hex(authToken)).Scan(&nodeID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE enroll_tokens SET used_at = now(), node_id = $2 WHERE token_hash = $1`,
			sha256Hex(enrollToken), nodeID)
		return err
	})
	return nodeID, authToken, err
}

// AuthNode verifies a node id + bearer token.
func (s *Store) AuthNode(ctx context.Context, nodeID, token string) error {
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT auth_token_hash FROM exit_nodes WHERE id = $1`, nodeID).Scan(&hash)
	if err == pgx.ErrNoRows {
		return ErrUnauthorized
	}
	if err != nil {
		// Malformed UUID etc. read as unauthorized rather than 500.
		return ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(sha256Hex(token))) != 1 {
		return ErrUnauthorized
	}
	return nil
}

// Heartbeat records liveness and returns the node's egress service catalog.
func (s *Store) Heartbeat(ctx context.Context, nodeID, version string) ([]Service, error) {
	if _, err := s.pool.Exec(ctx,
		`UPDATE exit_nodes SET last_seen = now(), version = $2 WHERE id = $1`, nodeID, version); err != nil {
		return nil, err
	}
	return s.Services(ctx)
}

// ServiceInfo is an enabled egress service as shown to customers (name + rate).
type ServiceInfo struct {
	Key     string
	Name    string
	RatePPM int64
}

// EnabledServices returns the enabled egress services with their display name
// and rate, for the portal's "how your data counts" explanation. Only services
// actually enabled on this deployment appear, so the copy never overpromises.
func (s *Store) EnabledServices(ctx context.Context) ([]ServiceInfo, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, name, rate_ppm FROM services WHERE enabled ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceInfo
	for rows.Next() {
		var si ServiceInfo
		if err := rows.Scan(&si.Key, &si.Name, &si.RatePPM); err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// Services returns the enabled egress services.
func (s *Store) Services(ctx context.Context) ([]Service, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, port, rate_ppm FROM services WHERE enabled ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var svc Service
		if err := rows.Scan(&svc.Key, &svc.Port, &svc.Rate); err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

// SeedDefaults inserts the baseline connectivity service if absent. Safe to
// re-run. The key stays 'clearnet' (it's the FK on every usage row); only the
// display name is "Connectivity" — the :1080 service now reaches clearnet plus
// .onion via the dispatcher. ON CONFLICT DO NOTHING means an existing row keeps
// its old name; rename a live catalog with an admin update / UPDATE (see docs).
func (s *Store) SeedDefaults(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO services(key, name, port, rate_ppm)
		 VALUES ('clearnet', 'Connectivity', 1080, 1000000)
		 ON CONFLICT (key) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("store: seed services: %w", err)
	}
	return nil
}

// CreateService registers (or updates) an egress service in the catalog. This
// is the ONLY control-plane change needed to add a new egress layer (e.g. Tor):
// the gate, captive daemon, agent, and billing are all service-agnostic and
// pick it up from here + the rendered nftables ports. Upserts on key.
func (s *Store) CreateService(ctx context.Context, key, name string, port uint16, ratePPM int64, enabled bool) error {
	if ratePPM <= 0 {
		ratePPM = 1_000_000
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO services(key, name, port, rate_ppm, enabled)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (key) DO UPDATE
		   SET name = EXCLUDED.name, port = EXCLUDED.port,
		       rate_ppm = EXCLUDED.rate_ppm, enabled = EXCLUDED.enabled`,
		key, name, int(port), ratePPM, enabled)
	if err != nil {
		return fmt.Errorf("store: create service: %w", err)
	}
	return nil
}
