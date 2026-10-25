package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// WireGuard peer sync
//
// The backend owns the peer table (who may connect, with which inner
// addresses); the agent mirrors it onto the node's WireGuard interface the
// same way it mirrors the authorized set onto nftables. Authorization is NOT
// expressed through the peer list — every issued peer is configured, and the
// nftables gate on the UDP port decides per fips source whether handshakes get
// through — so a customer who just paid connects on their next retry without
// waiting for a peer sync.

// wgPeer is one configured peer: key plus cryptokey-routing allowed IPs.
type wgPeer struct {
	Pubkey     string
	AllowedIPs []string // sorted, e.g. ["10.64.0.5/32", "fc10:...::5/128"]
}

// WgIface is the WireGuard interface surface the agent drives; wgTool shells
// out to `wg`, tests substitute a fake.
type WgIface interface {
	PublicKey() (string, error)
	ListPeers() (map[string]wgPeer, error)
	SetPeers(add []wgPeer, del []string) error
}

type wgTool struct {
	wgPath string
	iface  string
}

func newWgTool(wgPath, iface string) *wgTool { return &wgTool{wgPath: wgPath, iface: iface} }

func (w *wgTool) run(args ...string) ([]byte, error) {
	cmd := exec.Command(w.wgPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("wg %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (w *wgTool) PublicKey() (string, error) {
	out, err := w.run("show", w.iface, "public-key")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (w *wgTool) ListPeers() (map[string]wgPeer, error) {
	out, err := w.run("show", w.iface, "dump")
	if err != nil {
		return nil, err
	}
	return parseWgDump(string(out)), nil
}

// parseWgDump reads `wg show <if> dump`: the first line is the interface
// (private-key, public-key, listen-port, fwmark), each following line a peer
// (public-key, preshared-key, endpoint, allowed-ips, latest-handshake, rx, tx,
// keepalive), tab-separated.
func parseWgDump(dump string) map[string]wgPeer {
	peers := map[string]wgPeer{}
	lines := strings.Split(strings.TrimRight(dump, "\n"), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		var ips []string
		if f[3] != "(none)" && f[3] != "" {
			ips = strings.Split(f[3], ",")
		}
		sort.Strings(ips)
		peers[f[0]] = wgPeer{Pubkey: f[0], AllowedIPs: ips}
	}
	return peers
}

// SetPeers applies adds (set/replace allowed-ips) and removals in one `wg set`.
func (w *wgTool) SetPeers(add []wgPeer, del []string) error {
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	args := []string{"set", w.iface}
	for _, p := range add {
		args = append(args, "peer", p.Pubkey, "allowed-ips", strings.Join(p.AllowedIPs, ","))
	}
	for _, k := range del {
		args = append(args, "peer", k, "remove")
	}
	_, err := w.run(args...)
	return err
}

// diffPeers computes what SetPeers needs to turn current into desired: peers
// missing or with different allowed-ips are (re)added, peers not desired are
// removed.
func diffPeers(current, desired map[string]wgPeer) (add []wgPeer, del []string) {
	for k, want := range desired {
		have, ok := current[k]
		if !ok || strings.Join(have.AllowedIPs, ",") != strings.Join(want.AllowedIPs, ",") {
			add = append(add, want)
		}
	}
	for k := range current {
		if _, ok := desired[k]; !ok {
			del = append(del, k)
		}
	}
	sort.Slice(add, func(i, j int) bool { return add[i].Pubkey < add[j].Pubkey })
	sort.Strings(del)
	return add, del
}

// desiredPeers converts the backend's table into the interface's view.
func desiredPeers(resp wgPeersResponse) map[string]wgPeer {
	out := make(map[string]wgPeer, len(resp.Peers))
	for _, p := range resp.Peers {
		ips := []string{}
		if p.IP4 != "" {
			ips = append(ips, p.IP4)
		}
		if p.IP6 != "" {
			ips = append(ips, p.IP6)
		}
		sort.Strings(ips)
		out[p.Pubkey] = wgPeer{Pubkey: p.Pubkey, AllowedIPs: ips}
	}
	return out
}

// runWgSync keeps the interface's peers equal to the backend's table. It
// polls with an etag (204 = unchanged) every wgSyncEvery and reconciles against
// the live interface each time the table changes, plus a periodic full pass
// so an out-of-band `wg set` is repaired.
func (a *Agent) runWgSync(ctx context.Context) {
	backoff := newBackoff()
	var lastFull time.Time
	for ctx.Err() == nil {
		etag := a.wgEtag
		if a.now().Sub(lastFull) >= a.fullSyncEveryOrDefault() {
			etag = "" // force a full table + reconcile
		}
		resp, err := a.client.getWgPeers(ctx, etag)
		switch {
		case err == errUnchanged:
			backoff.reset()
		case err != nil:
			log.Printf("agent: wg peers: %v", err)
			sleep(ctx, backoff.next())
			continue
		default:
			if err := a.applyWgPeers(resp); err != nil {
				a.metrics.nftErr()
				log.Printf("agent: wg apply: %v", err)
				sleep(ctx, backoff.next())
				continue
			}
			if etag == "" {
				lastFull = a.now()
			}
			backoff.reset()
		}
		if !sleep(ctx, a.wgSyncEvery) {
			return
		}
	}
}

func (a *Agent) fullSyncEveryOrDefault() time.Duration {
	if a.fullSyncEvery > 0 {
		return a.fullSyncEvery
	}
	return 5 * time.Minute
}

func (a *Agent) applyWgPeers(resp wgPeersResponse) error {
	current, err := a.wg.ListPeers()
	if err != nil {
		return err
	}
	desired := desiredPeers(resp)
	add, del := diffPeers(current, desired)
	if err := a.wg.SetPeers(add, del); err != nil {
		return err
	}
	if len(add)+len(del) > 0 {
		log.Printf("agent: wg peers synced: +%d -%d (%d total)", len(add), len(del), len(desired))
	}
	a.wgEtag = resp.Etag
	a.metrics.setWgPeers(len(desired))
	return nil
}
