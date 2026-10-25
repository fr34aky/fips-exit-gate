# WireGuard: the whole-device exit service

The `wg` service turns the exit into a real exit node: a client imports **one
WireGuard configuration** and all of its Internet traffic — IPv4, IPv6, UDP,
every application — goes through the exit, with no proxy settings anywhere.
fips itself (`.fips` names, the portal, other mesh nodes) stays native.

It reuses everything the SOCKS services already have:

- **Authorization** is the same `authorized` nftables set, applied to the
  WireGuard UDP port per packet: an unauthorized fips source's handshake is
  simply dropped. A customer who just paid connects on the next retry.
- **Metering** is the same `acct` set keyed on `(fips source, port)`; the
  agent reports it under the service key `wg` and the backend bills it at the
  service's `rate_ppm`, so one package covers SOCKS and WireGuard alike.
  Metering counts the outer packets, i.e. includes WireGuard's overhead
  (about 5 % at full-size packets, plus keepalives); the help page says so.
- **Identity** stays the fips source address. WireGuard keys only tell the
  exit which inner addresses to accept (cryptokey routing); a configuration
  used from an unauthorized node is dropped, one used from another
  authorized node is billed to that node. One configuration per device.

```
 client app ─▶ wg0 (client) ─▶ UDP :51820 over fips ─▶ [nft gate: src ∈ authorized?] ─▶ wg0 (exit) ─▶ masquerade ─▶ Internet
                                                          └─ acct (src, 51820)
```

## Enabling it

Like Tor, three things must agree: the catalog, the node's ruleset, and the
running endpoint. Do them in any order; until all three are in place the port
is refused from fips (it is one of the guarded ports), never open-but-unmetered.

1. **Backend**: register the service and check the address plan in
   `backend.env` (`WG_POOL4`, `WG_POOL6`, `WG_PORT`, `WG_MTU`,
   `WG_MAX_PEERS_PER_ADDR`; defaults `10.64.0.0/16`, `fc10:f1b5:ea17::/64`,
   `51820`, `1280`, `5`):

   ```sh
   curl -H "$H" -XPOST $URL/admin/services -d '{"key":"wg","name":"WireGuard","port":51820,"rate_ppm":1000000}'
   ```

2. **Exit node**, kernel WireGuard via `wg-quick`:

   ```sh
   # the interface (peers are managed by the agent, not listed here)
   install -Dm600 deploy/wireguard/wg0.conf.example /etc/wireguard/wg0.conf
   wg genkey | tee /etc/wireguard/wg0.key | wg pubkey      # put the private key in wg0.conf
   systemctl enable --now wg-quick@wg0
   # forwarding + RA acceptance
   install -Dm644 deploy/sysctl.d/90-fips-exit-wg.conf /etc/sysctl.d/ && sysctl --system   # edit eth0 -> EXTERNAL_IF
   # let the fips mesh firewall deliver the port to the exit
   install -Dm644 deploy/fips-firewall/fips-exit.nft /etc/fips/fips.d/ && systemctl reload-or-restart fips-firewall
   ```

   Then in `deploy/.env` set `WG_IF=wg0` (and the `WG_*` plan if you changed
   it), uncomment `wg 51820 udp` in `services.conf`, set
   `FIPS_AGENT_WG_IF=wg0` and `FIPS_AGENT_WG_ENDPOINT=[<EXIT_FIPS_ADDR>]:51820`
   (an address literal: see "Names inside the tunnel" below), then
   `sudo ./up.sh reload` and restart the agent. `up.sh` checks the
   forwarding sysctls, that `wg0` exists, and inserts the `DOCKER-USER`
   accepts Docker's `FORWARD DROP` policy would otherwise apply to the tunnel.

3. **Verify**: `nft list table inet fips_exit` shows the `udp dport 51820`
   gate, the `forward`/`wg_egress`/`wg_nat` chains; after the agent's first
   heartbeat `/admin/accounts/<npub>`-style tooling aside, the dashboard shows
   a "WireGuard (whole-device VPN)" section; `wg show wg0` lists peers after
   a customer creates a device.

## What the ruleset does for tunnel traffic

Rendered by `render-nftables.sh` when `WG_IF` is set (mirrors Dante's egress
policy in `exit/sockd.conf`):

- `forward`: only `wg0 ↔ EXTERNAL_IF`; fips is never routed to or from the
  Internet through the host.
- `wg_egress` (client → Internet): clients cannot reach each other
  (`oifname wg0` drop); RFC1918, CGNAT, link-local/metadata, multicast,
  `fc00::/7` (fips and the inner v6 pool), IPv4-mapped v6 and the
  documentation prefix are rejected; outbound mail (25/465/587) is reset;
  anything not leaving via `EXTERNAL_IF` is dropped; TCP MSS is clamped to
  `WG_MSS` (1140) so TCP never needs outer fragmentation over fips.
- `wg_ingress` (Internet → client): replies only.
- `from_wg` (client → the exit host): DNS to the gateway addresses and ICMP;
  everything else (backend, metrics, SSH) is closed from inside the tunnel.
- `wg_nat`: masquerade the inner pools on `EXTERNAL_IF`; with
  `WG_IPV6_EGRESS=0` inner IPv6 is refused fast instead so clients fall back
  to IPv4 (use this when the exit has no global IPv6).

`deploy/test/run-nft-gate-test.sh` exercises all of this against a real
kernel with veth-backed `wg0` and uplink namespaces.

## MTU

fips' TUN MTU is 1280; WireGuard over IPv6 adds 80 bytes, so the
fragmentation-free inner payload is 1200 — below IPv6's 1280 minimum. The
client config therefore uses `MTU = 1280` and the exit clamps TCP MSS to 1140;
non-TCP packets between 1201 and 1280 bytes (QUIC's 1200-byte datagrams land
here) are fragmented at the outer IPv6 layer and reassembled by the far end.
They work, just less efficiently. Confirm on your nodes that fips passes
IPv6 fragments (`ping -6 -s 1232` from a client; `tcpdump -ni fips0
'ip6[6]==44'` on the exit shows fragments).

## Customer flow

On the dashboard, "WireGuard (whole-device VPN)" lists devices and offers
"New WireGuard device": pick the identity (any enabled whitelist entry), an
optional name, and optionally paste your own public key. The next page shows
the configuration **once** — QR for the WireGuard apps, `.conf` download —
one `[Peer]` per exit that offers WireGuard. The private key is generated
server-side and never stored; lose it and you create a new device.

The config's `AllowedIPs` is `::/0` minus `fd00::/8` (spelled out as
prefixes) plus `0.0.0.0/0`, so the mesh stays native on every platform.
`DNS` points at the resolver inside the tunnel (unbound on the gateway
addresses), so names resolve at the exit's location.

### Names inside the tunnel

While the tunnel is up the device's resolver is the tunnel DNS, and unbound
knows nothing about `.fips` (those names resolve by derivation on fips nodes).
Two consequences, both handled by defaults:

- The `Endpoint` the agent announces should be the exit's **fips address
  literal** (`[fd…]:51820`), so reconnects after a network change never
  depend on DNS. Use the `<npub>.fips` name only for clients behind a fips
  gateway, which can reach the mesh by name only — and then wire `.fips` into
  unbound (next point).
- `.fips` names (the portal) do not resolve from a phone while the tunnel is
  up unless unbound forwards the `fips.` zone to the host's fips resolver;
  `deploy/unbound.conf` carries a commented `forward-zone` for that. Linux
  clients with systemd-resolved keep `~fips` routed to `fips0`'s resolver if
  fips installed one. The portal is always reachable by its fips address.

An unauthorized or exhausted customer's handshake is dropped: the app shows
no recent handshake and the Internet is black-holed while the tunnel is up.
The portal still loads over fips, and the FAQ says so. There is no captive
redirect for WireGuard; the SOCKS captive path remains for discovery.

## Operations

- Peers: the agent polls `GET /v1/nodes/{id}/wg` every
  `FIPS_AGENT_WG_SYNC_S` (15 s) with an etag and reconciles `wg show wg0
  dump` against it (full pass every `FIPS_AGENT_FULL_SYNC_S`, so an
  out-of-band `wg set` is repaired). All peers are configured regardless of
  authorization; the UDP gate is the enforcement.
- Address plan: the backend's `WG_POOL4/6` must equal every exit's `.env`
  and `wg0.conf`; the agent logs the backend's plan on heartbeat so a
  mismatch is visible.
- Metrics: `fipsexit_agent_wg_peers`, `fipsexit_agent_wg_errors_total` (a
  peer row `wg` rejects is logged, skipped and counted; the other peers still
  sync). Revocation: the gate drops the next outer packet, so a revoked
  tunnel dies within one keepalive (25 s).
- A node that stops announcing a key (service turned off) is dropped from
  the customer-facing list on its next heartbeat, and any node silent for
  15 minutes disappears from it, so configs are never rendered for a dead
  exit.
- Removing a device on the dashboard removes the peer within one sync.
