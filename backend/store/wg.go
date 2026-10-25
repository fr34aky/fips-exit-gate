package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/fr34aky/fips-exit-gate/pkg/fipsaddr"
	"github.com/jackc/pgx/v5"
)

// WireGuard peers
//
// A peer is one client device's WireGuard key, issued to a whitelist npub and
// attached to the account that npub is currently active on. The exit gates the
// WireGuard UDP port by fips source address exactly like the SOCKS ports, so a
// peer only works from an authorized fips node and its traffic is billed to
// that node's account; the peer table just tells the exit which keys and
// inner addresses to accept. Private keys are never stored: the portal shows
// the generated key once (or takes the client's own public key).

var (
	// ErrWgPeerLimit: the address already has MaxWgPeersPerAddr peers.
	ErrWgPeerLimit = errors.New("store: WireGuard peer limit reached for this identity")
	// ErrWgForbidden: the session may not manage peers for that npub.
	ErrWgForbidden = errors.New("store: that identity is not on your account")
	// ErrWgBadKey: the public key is not a valid base64 32-byte key.
	ErrWgBadKey = errors.New("store: invalid WireGuard public key")
	// ErrWgPeerNotFound: no such peer on this account.
	ErrWgPeerNotFound = errors.New("store: WireGuard peer not found")
	// ErrWgPoolFull: no free inner address.
	ErrWgPoolFull = errors.New("store: WireGuard address pool exhausted")
	// ErrWgNotActive: the npub has no active whitelist row anywhere.
	ErrWgNotActive = errors.New("store: that identity is not active on any account")
	// ErrWgBadEndpoint: a node announced an endpoint that is not host:port.
	ErrWgBadEndpoint = errors.New("store: invalid WireGuard endpoint")
)

// wgNodeFreshness: a node that has not announced its key for this long no
// longer appears to customers (it stopped running WireGuard or is down).
const wgNodeFreshness = "15 minutes"

// DefaultMaxWgPeersPerAddr bounds peers per fips address (a gateway router
// legitimately fronts several phones under one npub).
const DefaultMaxWgPeersPerAddr = 5

// WgPools is the inner address plan: peers get pool4+idx and pool6::idx; the
// exit holds .1 / ::1 (gateway + resolver).
type WgPools struct {
	Pool4 netip.Prefix
	Pool6 netip.Prefix
}

// DefaultWgPools is used when the backend is not configured otherwise.
var DefaultWgPools = WgPools{
	Pool4: netip.MustParsePrefix("10.64.0.0/16"),
	Pool6: netip.MustParsePrefix("fc10:f1b5:ea17::/64"),
}

// Gateway addresses (.1 / ::1) of the pools.
func (p WgPools) Gateway4() netip.Addr { return offset4(p.Pool4, 1) }
func (p WgPools) Gateway6() netip.Addr { return offset6(p.Pool6, 1) }

// slots is how many peer indexes the v4 pool allows (excluding network,
// gateway and broadcast).
func (p WgPools) slots() int {
	bits := 32 - p.Pool4.Bits()
	if bits > 24 {
		bits = 24 // never more than a /8's worth; keeps idx small
	}
	return (1 << bits) - 3
}

func offset4(pfx netip.Prefix, n int) netip.Addr {
	a := pfx.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v += uint32(n)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func offset6(pfx netip.Prefix, n int) netip.Addr {
	a := pfx.Masked().Addr().As16()
	// idx fits in the last 4 bytes; the pool is at most a /64.
	v := uint32(a[12])<<24 | uint32(a[13])<<16 | uint32(a[14])<<8 | uint32(a[15])
	v += uint32(n)
	a[12], a[13], a[14], a[15] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	return netip.AddrFrom16(a)
}

// WgPeer is one issued client key.
type WgPeer struct {
	ID        string
	AccountID string
	Npub      string
	FipsAddr  netip.Addr
	Pubkey    string
	Idx       int
	Label     string
	IP4       netip.Addr // inner addresses (host part), derived from Idx
	IP6       netip.Addr
}

// WgNode is an exit that announced a WireGuard public key.
type WgNode struct {
	ID       string
	Name     string
	Pubkey   string
	Endpoint string
}

func (s *Store) wgPools() WgPools {
	if s.WgPools.Pool4.IsValid() && s.WgPools.Pool6.IsValid() {
		return s.WgPools
	}
	return DefaultWgPools
}

func (s *Store) maxWgPeers() int {
	if s.MaxWgPeersPerAddr > 0 {
		return s.MaxWgPeersPerAddr
	}
	return DefaultMaxWgPeersPerAddr
}

// ValidWgKey reports whether k is exactly what `wg` accepts: 44 characters of
// strict base64 (no whitespace, canonical padding bits) decoding to 32 bytes.
// Go's lenient decoder would accept keys that wireguard-tools rejects, and a
// single such row would make every node's batched `wg set` fail forever.
func ValidWgKey(k string) bool {
	if len(k) != 44 || strings.ContainsAny(k, " \t\r\n") {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(k)
	return err == nil && len(b) == 32
}

// validWgEndpoint accepts "host:port" / "[v6]:port" with a numeric port and no
// control characters or spaces: the value is written into every customer's
// INI config, so it must never be able to inject lines.
func validWgEndpoint(e string) bool {
	if e == "" || len(e) > 253 || strings.ContainsAny(e, " \t\r\n\x00") {
		return false
	}
	host, port, err := net.SplitHostPort(e)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536
}

// CreateWgPeer issues a peer for forNpub. Allowed when forNpub is the session
// itself, or an enabled whitelist entry on the session's own account. The peer
// is attached to the account forNpub's address is currently active on (the
// account whose package it will draw from).
func (s *Store) CreateWgPeer(ctx context.Context, sessionNpub, forNpub, label, pubkey string) (WgPeer, error) {
	pubkey = strings.TrimSpace(pubkey)
	if !ValidWgKey(pubkey) {
		return WgPeer{}, ErrWgBadKey
	}
	addr, err := fipsaddr.FromNpub(forNpub)
	if err != nil {
		return WgPeer{}, fmt.Errorf("store: derive address: %w", err)
	}
	var peer WgPeer
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		// Serialize issuance per address so the cap check below cannot be
		// raced by a double-submitted form.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "wg:"+addr.String()); err != nil {
			return err
		}
		// Permission: self, or an accepted (not pending) entry on the session's account.
		if forNpub != sessionNpub {
			var ok bool
			if err := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM whitelist_entries w JOIN accounts a ON a.id = w.account_id
				   WHERE a.npub = $1 AND w.npub = $2 AND w.enabled AND NOT w.pending)`, sessionNpub, forNpub).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return ErrWgForbidden
			}
		}
		// Attach to the account the address is active on.
		var accountID string
		err := tx.QueryRow(ctx,
			`SELECT account_id::text FROM whitelist_entries WHERE fips_addr = $1::inet AND enabled AND NOT pending LIMIT 1`,
			addr.String()).Scan(&accountID)
		if err == pgx.ErrNoRows {
			return ErrWgNotActive
		}
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM wg_peers WHERE fips_addr = $1::inet`, addr.String()).Scan(&n); err != nil {
			return err
		}
		if n >= s.maxWgPeers() {
			return ErrWgPeerLimit
		}
		slots := s.wgPools().slots()
		for attempt := 0; attempt < 64; attempt++ {
			var idx int
			if err := tx.QueryRow(ctx, `SELECT 2 + (nextval('wg_peer_alloc') % $1)::int`, slots).Scan(&idx); err != nil {
				return err
			}
			var id string
			err := tx.QueryRow(ctx,
				`INSERT INTO wg_peers(account_id, npub, fips_addr, pubkey, idx, label, created_by)
				 VALUES ($1, $2, $3::inet, $4, $5, $6, $7)
				 ON CONFLICT (idx) DO NOTHING RETURNING id::text`,
				accountID, forNpub, addr.String(), pubkey, idx, label, sessionNpub).Scan(&id)
			if err == pgx.ErrNoRows {
				continue // slot taken; try the next one
			}
			if err != nil {
				if strings.Contains(err.Error(), "wg_peers_pubkey_key") {
					return ErrWgBadKey // duplicate key: refuse rather than attach a shared key twice
				}
				return err
			}
			peer = WgPeer{ID: id, AccountID: accountID, Npub: forNpub, FipsAddr: addr, Pubkey: pubkey, Idx: idx, Label: label}
			return nil
		}
		return ErrWgPoolFull
	})
	if err != nil {
		return WgPeer{}, err
	}
	s.fillPeerIPs(&peer)
	return peer, nil
}

func (s *Store) fillPeerIPs(p *WgPeer) {
	pools := s.wgPools()
	p.IP4 = offset4(pools.Pool4, p.Idx)
	p.IP6 = offset6(pools.Pool6, p.Idx)
}

// ListWgPeers returns the peers attached to an account.
func (s *Store) ListWgPeers(ctx context.Context, accountID string) ([]WgPeer, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, account_id::text, npub, host(fips_addr), pubkey, idx, COALESCE(label, '')
		 FROM wg_peers WHERE account_id = $1 ORDER BY created_at`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanPeers(rows)
}

func (s *Store) scanPeers(rows pgx.Rows) ([]WgPeer, error) {
	var out []WgPeer
	for rows.Next() {
		var p WgPeer
		var addr string
		if err := rows.Scan(&p.ID, &p.AccountID, &p.Npub, &addr, &p.Pubkey, &p.Idx, &p.Label); err != nil {
			return nil, err
		}
		p.FipsAddr, _ = netip.ParseAddr(addr)
		s.fillPeerIPs(&p)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteWgPeer removes a peer the session controls: one on the session's own
// account, or one issued to the session's own npub.
func (s *Store) DeleteWgPeer(ctx context.Context, sessionNpub, id string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM wg_peers p USING accounts a
		 WHERE p.id = $1::uuid AND a.id = p.account_id AND (a.npub = $2 OR p.npub = $2)`, id, sessionNpub)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrWgPeerNotFound
	}
	return nil
}

// WgPeerTable is the agent's view: every peer, ordered, with an etag that
// changes exactly when the table does. All peers are listed regardless of
// authorization — the nftables gate on the UDP port is the enforcement, so a
// peer whose owner just paid works on its next handshake without a sync.
func (s *Store) WgPeerTable(ctx context.Context) ([]WgPeer, string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, account_id::text, npub, host(fips_addr), pubkey, idx, COALESCE(label, '')
		 FROM wg_peers ORDER BY pubkey`)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	peers, err := s.scanPeers(rows)
	if err != nil {
		return nil, "", err
	}
	h := sha256.New()
	for _, p := range peers {
		fmt.Fprintf(h, "%s|%s|%s\n", p.Pubkey, p.IP4, p.IP6)
	}
	return peers, hex.EncodeToString(h.Sum(nil)[:16]), nil
}

// SetNodeWg records the WireGuard public key and endpoint a node announced.
func (s *Store) SetNodeWg(ctx context.Context, nodeID, pubkey, endpoint string) error {
	pubkey, endpoint = strings.TrimSpace(pubkey), strings.TrimSpace(endpoint)
	if !ValidWgKey(pubkey) {
		return ErrWgBadKey
	}
	if !validWgEndpoint(endpoint) {
		return ErrWgBadEndpoint
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE exit_nodes SET wg_pubkey = $2, wg_endpoint = $3, wg_seen_at = now() WHERE id = $1`,
		nodeID, pubkey, endpoint)
	return err
}

// ClearNodeWg forgets a node's WireGuard announcement (it heartbeats without
// one: the service was turned off there).
func (s *Store) ClearNodeWg(ctx context.Context, nodeID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE exit_nodes SET wg_pubkey = NULL, wg_endpoint = NULL, wg_seen_at = NULL
		 WHERE id = $1 AND wg_pubkey IS NOT NULL`, nodeID)
	return err
}

// WgNodes lists exits that currently offer WireGuard: announced a key and an
// endpoint, and did so recently (see wgNodeFreshness), so configs are never
// rendered for a dead or decommissioned exit.
func (s *Store) WgNodes(ctx context.Context) ([]WgNode, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id::text, name, wg_pubkey, wg_endpoint FROM exit_nodes
		 WHERE wg_pubkey IS NOT NULL AND wg_endpoint IS NOT NULL AND wg_endpoint <> ''
		   AND wg_seen_at > now() - interval '`+wgNodeFreshness+`' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WgNode
	for rows.Next() {
		var n WgNode
		if err := rows.Scan(&n.ID, &n.Name, &n.Pubkey, &n.Endpoint); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
