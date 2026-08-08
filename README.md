# fips-exit

A paid internet-exit service for the [fips](https://github.com/jmcorgan/fips)
mesh network: a Dante-based SOCKS5 exit node that accepts IPv6 clients from
fips (fd00::/8), egresses via the host's public IPv4/IPv6, resolves DNS
server-side, and is gated by nostr-identity-based accounting with data
packages payable in Bitcoin, Lightning, and Monero.

## Layout

| Path | Contents |
|---|---|
| `pkg/fipsaddr` | npub → fips IPv6 address derivation (stdlib-only Go) |
| `docs/` | Specs: derivation, agent↔backend API, data model, threat model |
| `exit/` | Dante container + nftables ruleset (Phase 1) |
| `captive/` | Captive SOCKS5 daemon: HTTP 302 → portal for unauthorized clients (Phase 1) |
| `agent/` | Exit-node agent: authz set sync + usage accounting (Phase 2) |
| `backend/` | Portal + API + BTCPay integration (Phases 3–4) |
| `deploy/` | Compose files, systemd units, nftables templates |

## Development

```sh
gofmt -l . && go vet ./... && go test ./...
```

## How access works (summary)

A fips client's IPv6 source address is cryptographically derived from its
nostr npub, so the exit authenticates by source address alone — the SOCKS5
handshake is credential-free. The exit-agent keeps an nftables set of
authorized addresses (account owners plus their whitelisted npubs, backed by
paid data packages); everyone else hitting the proxy port is handed to the
captive daemon, which redirects plain HTTP to the user portal and refuses
everything else. The proxy is internet-egress only: fd00::/8 destinations are
blocked, and fips-internal traffic is never metered.

Egress is modular: each service (clearnet via Dante, Tor via a SocksPort,
future overlays) is its own SOCKS endpoint on its own port behind the same
generic gate, and draws on one shared balance at a per-service byte rate.

See `docs/` for the full specifications and the implementation plan.
