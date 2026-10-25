package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"

	"github.com/fr34aky/fips-exit-gate/backend/store"
)

// wgSettings is the backend's view of the WireGuard service, handed to agents
// in the heartbeat (so a node can warn on a mismatch with its wg0) and used to
// render client configs.
type wgSettings struct {
	port  int
	pools store.WgPools
	dns4  netip.Addr // resolver inside the tunnel (the gateway address)
	dns6  netip.Addr
	mtu   int
}

// genWgKeypair returns a fresh X25519 key pair in WireGuard's base64 form.
// The private key is shown to the user once and never stored.
func genWgKeypair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// wgAllowedIPs is "everything except fips": 0.0.0.0/0 plus ::/0 minus
// fd00::/8, expressed as prefixes so the mesh (the portal, .fips names, and
// the tunnel's own endpoint) stays native on every platform.
const wgAllowedIPs = "0.0.0.0/0, ::/1, 8000::/2, c000::/3, e000::/4, f000::/5, f800::/6, fc00::/8, fe00::/7"

// iniSafe strips anything that could start a new INI line or key from a value
// that is interpolated into a config (node names, labels, URLs).
func iniSafe(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// renderWgConfig produces one client configuration for peer on node. The
// endpoint was validated as host:port when the node announced it.
func renderWgConfig(priv string, peer store.WgPeer, node store.WgNode, s wgSettings, portalURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "# fips-exit WireGuard, issued to %s (%s). One config per device.\n", iniSafe(peer.Npub), peer.FipsAddr)
	fmt.Fprintf(&b, "# Portal: %s/dashboard  (reachable over fips while the tunnel is up: fd00::/8 is excluded below)\n", iniSafe(portalURL))
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	fmt.Fprintf(&b, "Address = %s/32, %s/128\n", peer.IP4, peer.IP6)
	fmt.Fprintf(&b, "DNS = %s, %s\n", s.dns4, s.dns6)
	fmt.Fprintf(&b, "MTU = %d\n\n", s.mtu)
	fmt.Fprintf(&b, "[Peer]\n# %s\n", iniSafe(node.Name))
	fmt.Fprintf(&b, "PublicKey = %s\n", node.Pubkey)
	fmt.Fprintf(&b, "Endpoint = %s\n", iniSafe(node.Endpoint))
	fmt.Fprintf(&b, "AllowedIPs = %s\n", wgAllowedIPs)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	return b.String()
}
