# fips-exit-gate

A **paid internet-exit service for the [fips](https://github.com/jmcorgan/fips)
mesh network**. fips clients are IPv6-only (fd00::/8) and their address is
cryptographically derived from their nostr identity (npub), so the exit
authenticates by **source address alone** — the SOCKS5 handshake stays
credential-free and every stock client works unmodified.

A fips client points a SOCKS5 proxy at the exit node; the exit egresses to the
Internet over the host's public IPv4/IPv6, resolves DNS server-side, and meters
usage against **prepaid data packages** bought with Bitcoin, Lightning, or
Monero. Unknown or out-of-quota clients are redirected to a self-service portal
where they log in with their nostr identity and buy access. Egress is
**modular**: clearnet (Dante) and Tor are each a SOCKS endpoint on their own
port behind one shared gate and one shared balance, metered at a per-service
rate.

```
 fips client (IPv6 = f(npub))
        │ SOCKS5 :1080 (clearnet) / :1081 (Tor)  over the fips interface
        ▼
┌─ Exit node (a normal fips participant) ─────────────────────────┐
│  nftables gate ── src ∈ authorized ─▶ Dante / Tor ─▶ Internet   │
│       │            else ─▶ captive daemon ─▶ 302 to the portal   │
│       └─ per-(client,service) byte counters                     │
│  exit-agent ── syncs the authorized set ↓ / reports usage ↑     │
└───────────────────────────┬─────────────────────────────────────┘
                            │  authenticated HTTP API
                            ▼
┌─ Backend host ──────────────────────────────────────────────────┐
│  control plane + portal (Go, Postgres) · nostr login · packages │
│  BTCPay Server ─▶ external bitcoind / monerod over Tor          │
└──────────────────────────────────────────────────────────────────┘
```

## Components

### In this repo

| Path | Purpose |
|---|---|
| `pkg/fipsaddr` | The identity primitive: npub → fips IPv6 address derivation (`0xfd ‖ SHA-256(pubkey)[0:15]`), stdlib-only, shared by every component. |
| `exit/` | The clearnet egress: a **Dante** `sockd` SOCKS5 server built from source, bound to the fips interface, egress-only (blocks fd00::/8, RFC1918, loopback, metadata) with credential-free source-address auth. |
| `captive/` | The captive daemon: a minimal SOCKS5 server that answers **unauthorized** clients with an HTTP `302` to the portal (carrying a signed token) and cleanly refuses everything else. |
| `agent/` | The exit-node agent: reconciles the nftables `authorized` set from the backend (long-poll), reads the per-`(client,service)` byte counters, reports usage, and enforces quota cutoffs. Drives `nft`; otherwise stdlib-only (portable to OpenWrt). |
| `backend/` | The control plane + user portal (Go + Postgres): the agent-facing API (enroll / authz / usage), nostr login (NIP-07 + transparent fips-source), the package catalog, whitelist management, and the BTCPay payment webhook. |
| `deploy/` | Everything to run a node: compose files, the templated **nftables** ruleset (`render-nftables.sh` over `services.conf`), unbound config, `up.sh`, systemd units, and the BTCPay stack. |
| `cmd/` | CLIs: `fips-derive` (npub→address), and `fake-backend` / `fake-btcpay` test doubles for local/hardware bring-up without the real dependencies. |
| `docs/` | This documentation and the specs (derivation, agent↔backend API, data model, threat model). |

### Third-party building blocks

| Component | Purpose |
|---|---|
| **Dante** `sockd` | The clearnet SOCKS5 egress server (compiled from source in `exit/`). |
| **nftables** | The gate: routes authorized source addresses to the service and everyone else to the captive daemon, and holds the per-service byte counters. Gates only the service ports — never general fips traffic. |
| **unbound** | Server-side DNS resolver so clients can send hostnames and leak no DNS locally. |
| **Postgres** | The backend's data store: accounts, entitlements, usage ledger, the materialized authorized set + revision log. |
| **BTCPay Server** (+ Monero plugin) | Self-hosted payments, wired to the operator's **external** bitcoind/monerod over Tor; issues invoices and signs the settlement webhook. |
| **Tor** | An optional second egress service (`:1081`) — the modularity proof — and the transport BTCPay uses to reach the external nodes. |
| **nostr** (Schnorr / `btcec`) | The identity layer: npubs derive fips addresses and sign portal logins (NIP-07 / any signer). |

## How access works

An account is a nostr identity that has bought a package; it may whitelist
further npubs to share it. The backend materializes the set of authorized fips
addresses (owner + enabled guests with an active entitlement) and the agent
mirrors it into the kernel `authorized` set. Traffic from an authorized address
reaches the egress service and is metered — one shared balance, decremented by
`bytes × per-service rate`. Everyone else is handed to the captive daemon.
Access for on-chain payments is granted only once the invoice is **finalized**
(≥ 1 confirmation); Lightning is instant. The proxy is internet-egress only:
fd00::/8 destinations are blocked, so fips-internal traffic is reached natively
and never metered.

## Documentation

- **[Installation](docs/install.md)** — stand up the backend + an exit node end to end.
- **[Configuration](docs/configuration.md)** — every environment variable and config file.
- **[Troubleshooting](docs/troubleshooting.md)** — symptoms, causes, and fixes (including hard-won gotchas).
- **[Maintenance](docs/maintenance.md)** — add nodes/services, admin ops, rotate secrets, back up, upgrade.

Specifications: [derivation](docs/derivation.md) · [agent↔backend API](docs/api-agent-backend.md) · [data model](docs/data-model.md) · [threat model](docs/threat-model.md) · payments: [BTCPay](docs/phase4-btcpay.md) · [Tor egress](docs/phase4b-tor.md).

## Development

```sh
gofmt -l . && go vet ./... && go test ./...
```

Store integration tests run only when `TEST_DATABASE_URL` is set (use a
throwaway database, never a live one — the tests reset the schema) and require
`-p 1`. See [Configuration](docs/configuration.md#tests-and-development).
