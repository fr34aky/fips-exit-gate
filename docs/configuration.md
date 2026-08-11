# Configuration

Every component is configured by environment variables (and, for the exit node,
a couple of small files). Example env files ship in the repo:

| File | Consumed by |
|---|---|
| `deploy/backend.env.example` | the backend host (`backend-compose.yaml`) |
| `deploy/.env.example` | the exit node (`docker-compose.yaml`, `up.sh`) |
| `deploy/systemd/agent.env.example` | the exit-agent under systemd |

Copy each to the name without `.example`, `chmod 600`, and fill it in.
`deploy/.env` and `deploy/backend.env` are gitignored — they hold secrets.

> **Secrets that must match across hosts:** `CAPTIVE_TOKEN_SECRET` must be
> identical on the backend and on the exit node — the captive daemon signs the
> redirect token with it and the portal verifies it. A mismatch makes the
> captive landing page reject every token.

---

## Backend

Read by `backend/` (see `backend/main.go`).

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | — (**required**) | Postgres DSN, e.g. `postgres://fips:pw@db:5432/fips_exit`. Under `backend-compose.yaml` this is **built for you** from `PGUSER`/`PGPASSWORD`/`PGDATABASE` (set those in `backend.env` instead — see below). |
| `ADMIN_TOKEN` | — (**required**) | Bearer token protecting `/admin`. |
| `LISTEN` | `:8080` | Listen address. `:8080` binds all interfaces; use `[<fips-addr>]:8080` to serve the portal only over fips. For **transparent fips login** the backend must see the client's real source address — run it with **host networking**, not behind bridge NAT (see note below). |
| `SESSION_SECRET` | random | HMAC key for portal session cookies. Set it, or sessions drop on restart. |
| `CHALLENGE_SECRET` | random | HMAC key for login challenges. Set it in production. |
| `CAPTIVE_TOKEN_SECRET` | — | Verifies captive redirect tokens. **Must equal the exit node's value.** |
| `PORTAL_PUBLIC_URL` | `http://localhost:8080` | Public base URL; BTCPay redirects buyers back here after paying. Over fips, prefer the portal's `<npub>.fips` URL (see [Addressing the portal](#addressing-the-portal-over-fips)). |
| `PORTAL_PAC_EXIT` | derived | Exit SOCKS target the portal-served `GET /fips.pac` points browsers at (`<npub>.fips:<port>`). Empty = derive from `PORTAL_PUBLIC_URL`'s `<npub>.fips` host + `:1080`. The FAQ (`/help`) links customers to this PAC. |
| `PORTAL_TRUST_FIPS_SOURCE` | **on** | Transparent fips-source login. On by default (the portal is reached natively over fips). Set `0` **only** when a reverse proxy masks the client source (e.g. a public HTTPS portal) — otherwise everyone would appear as the proxy. |
| `PORTAL_SECURE_COOKIES` | **off** | Off by default so login works over the fips portal (HTTP). Set `1` when the portal is served over HTTPS. |
| `PORTAL_DEV_AUTOSETTLE` | `0` | Dev only: `1` grants purchases immediately without any payment rail. **Never in production.** |
| `USAGE_INTERVAL_S` | `30` | Usage-report interval advertised to agents (seconds). |
| `GRACE_MINUTES` | `240` | Outage grace window advertised to agents (fail-open duration). |
| `PAYMENT_RAIL` | — | Payment rail: `btcpay` (on-chain BTC + Lightning + Monero) or `phoenixd` (Lightning-only, direct). Empty = no rail. See [BTCPay](phase4-btcpay.md) / [phoenixd](phoenixd.md). |
| `BTCPAY_URL` | — | BTCPay base URL (e.g. `http://<onion>.onion`). Empty = payments disabled. |
| `BTCPAY_API_KEY` | — | Store-scoped Greenfield API key (`btcpay.store.cancreateinvoice`). |
| `BTCPAY_STORE_ID` | — | BTCPay store id. |
| `BTCPAY_WEBHOOK_SECRET` | — | Verifies the BTCPay webhook HMAC (`BTCPay-Sig`). |
| `BTCPAY_SOCKS5` | — | SOCKS5 proxy (e.g. `127.0.0.1:9050`) to reach a BTCPay `.onion` over Tor. |
| `PHOENIXD_URL` | — | phoenixd base URL (e.g. `http://127.0.0.1:9740`). |
| `PHOENIXD_PASSWORD` | — | phoenixd http-password (basic auth). |
| `PHOENIXD_WEBHOOK_SECRET` | — | Verifies the phoenixd webhook HMAC (`X-Phoenix-Signature`). |
| `PHOENIXD_SOCKS5` | — | Optional SOCKS5 to reach a phoenixd `.onion` over Tor. |
| `PHOENIXD_POLL_INTERVAL_S` | `15` | Reconciler poll interval (settle backup for missed webhooks + expiry). |
| `PHOENIXD_INVOICE_TTL_S` | `3600` | Unpaid Lightning invoice lifetime before it's voided. |
| `CASHU_ACCEPT` | — | `1` enables the Cashu accept-and-melt option on the pay page (needs `PAYMENT_RAIL=phoenixd`): a pasted ecash token is melted at its mint to the purchase's invoice. See [design note](design/cashu-accept-and-melt.md). |
| `CASHU_ACCEPTED_MINTS` | — | Optional comma-separated mint allowlist; empty = accept a token from any mint (safe, since access is granted only on realized receipt). |
| `CASHU_SOCKS5` | — | Optional SOCKS5 to reach an `.onion` mint over Tor. |
| `METRICS_TOKEN` | — | If set, `GET /metrics` requires this bearer token; else `/metrics` is open (restrict by network). See [Observability](observability.md). |

See the [BTCPay runbook](phase4-btcpay.md) for the required store **Transaction
Speed** setting (≥ 1 confirmation) that governs on-chain finalization.

**Under `backend-compose.yaml`** you don't set `DATABASE_URL` directly — set
these, which also configure the bundled Postgres:

| Variable | Default | Purpose |
|---|---|---|
| `PGUSER` | `fips` | Postgres user (compose builds the DSN from it). |
| `PGPASSWORD` | — (**required**) | Postgres password. |
| `PGDATABASE` | `fips_exit` | Postgres database name. |

**Transparent login & host networking.** Transparent fips login only works if
the backend sees the client's genuine npub-derived source address. Behind a
bridge/NAT (the default published-port setup) every client appears as the
gateway, so run the backend with host networking when it serves the portal over
fips — or set `PORTAL_TRUST_FIPS_SOURCE=0` and use nostr-signer login instead.

## Exit node (`deploy/.env`)

Consumed by `docker-compose.yaml` and `up.sh`. Also passed to the Dante and
captive containers.

| Variable | Example | Purpose |
|---|---|---|
| `FIPS_IF` | `fips0` | fips TUN interface; the gate only touches traffic ingressing here. |
| `EXIT_FIPS_ADDR` | `fd6b:b19b:6700:c923:df48:31a8:698b:bb25` | This node's fips address; services listen on it and the gate matches it. |
| `EXTERNAL_IF` | `eth0` | Public egress interface (IPv4/IPv6) Dante exits from. |
| `CONNECTIVITY_PORT` | `1080` | Client-facing **connectivity** port. The dispatcher listens here and routes `*.onion` → Tor, everything else → Dante. Gated + metered; keep in sync with `services.conf`. |
| `CLEARNET_BIND` | `127.0.0.1` | Address Dante's `internal:` binds — **loopback**, reached only by the dispatcher (no longer client-facing). |
| `CLEARNET_PORT` | `1090` | Dante's SOCKS port on `CLEARNET_BIND`; the dispatcher forwards clearnet CONNECTs here. |
| `CAPTIVE_PORT` | `1088` | Captive daemon port (redirect target for unauthorized traffic). |
| `TOR_PORT` | `1081` | Tor SOCKS **privacy** rail — forces *all* traffic through Tor (only with `--profile tor`). |
| `TOR_DISPATCH_PORT` | `9052` | Tor loopback SocksPort the dispatcher uses for the `*.onion` route (only with `--profile tor`). |
| `WORKERS` | `4` | Dante worker processes. |
| `CAPTIVE_PORTAL_URL` | `http://<npub>.fips:8080/captive` | Where the captive `302` sends unauthorized clients. Prefer the portal host's `<npub>.fips` URL (see note below). |
| `CAPTIVE_TOKEN_SECRET` | (secret) | Signs the captive token. **Must equal the backend's value.** |
| `MAX_CONNS_PER_SRC` | `0` | Per-source concurrent-connection ceiling baked into the gate by `render-nftables.sh` (e.g. `256`). `0` = disabled. See [Hardening](hardening.md). |

The same file also carries the agent variables below when the agent runs under
compose.

## Exit-agent

Read by `agent/` (see `agent/main.go`).

| Variable | Default | Purpose |
|---|---|---|
| `FIPS_AGENT_BACKEND_URL` | — (**required**) | Backend base URL. |
| `FIPS_AGENT_ENROLL_TOKEN` | — | One-time enroll token (only needed until the node has enrolled; state persists after). |
| `FIPS_AGENT_NODE_NAME` | hostname | Node name recorded at enrollment. |
| `FIPS_AGENT_TABLE` | `inet fips_exit` | nftables table the agent manages. Must match the loaded ruleset. |
| `FIPS_AGENT_NFT` | `nft` | Path to the `nft` binary. |
| `FIPS_AGENT_STATE_DIR` | `/var/lib/fips-exit-agent` | Durable state (`identity.json` 0600, `runtime.json`). |
| `FIPS_AGENT_FAIL_CLOSED_AFTER_GRACE` | `0` | `1` = revoke all access if the backend is unreachable past the grace window (default is fail-open: keep the last-known set). |
| `FIPS_AGENT_USAGE_BUFFER_CAP` | `2880` | Max buffered usage reports during an outage (≈ 24 h at 30 s). |
| `FIPS_AGENT_METRICS_ADDR` | — | If set (e.g. `:9101`), serve Prometheus `/metrics` here. Empty = disabled. |

The agent needs `CAP_NET_ADMIN` (it shells out to `nft`) — the compose service
grants it; under systemd the unit does.

## Connectivity dispatcher

Read by `dispatch/`. The client-facing SOCKS endpoint on the connectivity port:
it routes each CONNECT by destination — `*.onion` to Tor, everything else to
Dante over loopback (which enforces the egress policy). It carries no egress
policy of its own and never logs destinations. Under compose these come from
`deploy/.env`. Full runbook: [Connectivity](connectivity.md).

| Variable | Default | Purpose |
|---|---|---|
| `DISPATCH_LISTEN` | `[::1]:1080` | Client-facing listen address (compose sets `[EXIT_FIPS_ADDR]:CONNECTIVITY_PORT`). |
| `DISPATCH_CLEARNET_UPSTREAM` | `127.0.0.1:1090` | Dante's loopback SOCKS (`CLEARNET_BIND:CLEARNET_PORT`) — the clearnet route. |
| `DISPATCH_TOR_UPSTREAM` | `127.0.0.1:9052` | Tor's loopback SocksPort — the `*.onion` route. Empty = onion disabled (`.onion` refused; clearnet still works). |
| `DISPATCH_ONION_SUFFIX` | `.onion` | Hostname suffix routed to Tor. |
| `DISPATCH_DIAL_TIMEOUT_S` | `15` | Upstream dial timeout. |
| `DISPATCH_HANDSHAKE_TIMEOUT_S` | `15` | SOCKS handshake deadline (cleared once the tunnel relays). |
| `DISPATCH_MAX_CONNS` | `4096` | Max concurrent connections (load-shed beyond). |

Onion routing needs the `tor` profile running (it provides `TOR_DISPATCH_PORT`);
without it, clearnet still works and `.onion` returns a SOCKS host-unreachable.

## Exit / Dante container

Read by `exit/entrypoint.sh`. Under compose these come from `deploy/.env`.
Dante is no longer client-facing — it listens on loopback behind the dispatcher.

| Variable | Default | Purpose |
|---|---|---|
| `FIPS_IF` | — | Required by `entrypoint.sh` (validated on start). |
| `CLEARNET_BIND` | `127.0.0.1` | Address Dante's `internal:` binds — loopback, reached only by the dispatcher. |
| `CLEARNET_PORT` | `1090` | Dante's SOCKS listen port on `CLEARNET_BIND`. |
| `EXTERNAL_IF` | — | Interface Dante's `external:` egresses from. |
| `WORKERS` | `4` | `sockd` workers. |
| `CONFIG` | `/etc/sockd.conf` | Dante config path (a symlink to `sockd.conf`). |

`exit/sockd.conf` is the Dante policy: credential-free (`socksmethod: none`),
connect-only, and it **blocks** fd00::/8, RFC1918, loopback, and metadata
destinations. It binds `CLEARNET_BIND` (loopback) behind the dispatcher. Edit it
there; it's bind-mounted so no rebuild is needed.

## Captive daemon

Read by `captive/`. Under compose these come from `deploy/.env`/compose.

| Variable | Default | Purpose |
|---|---|---|
| `CAPTIVE_LISTEN` | `[::]:1088` | Listen address (compose sets it from `CAPTIVE_PORT`). |
| `CAPTIVE_PORTAL_URL` | — | Portal base for the `302`; the daemon appends `?t=<token>&dest=<host>`. |
| `CAPTIVE_TOKEN_SECRET` | — | HMAC key for the redirect token. **Must equal the backend's value.** |
| `CAPTIVE_IO_TIMEOUT_S` | (code default) | Per-connection I/O timeout. |
| `CAPTIVE_MAX_CONNS` | (code default) | Max concurrent connections. |
| `CAPTIVE_METRICS_ADDR` | — | If set (e.g. `:9102`), serve Prometheus `/metrics` here. Empty = disabled. |

## Config files

### `deploy/services.conf` — the egress service catalog (gate)

One `<key> <port>` per line; the single source of truth `render-nftables.sh`
templates the gate and per-service counters over. Adding a service (e.g. Tor) is
one line here **plus** a running SOCKS endpoint on that port **plus** a matching
catalog row in the backend (`POST /admin/services`). Keep the three in sync.

```
clearnet 1080
# tor 1081        # uncomment together with `--profile tor` + the /admin/services row
```

Port `1080` is the **connectivity** dispatcher endpoint (clearnet + `.onion`); the
gate only sees the port, so the service key stays `clearnet` (display name
"Connectivity"). See [Connectivity](connectivity.md).

### `deploy/allowlist.txt` — Phase-1 static authorization

Newline-separated fips addresses seeded into the `authorized` set at load time.
**Leave empty when running the agent** (the agent owns the set). Populate it
only for an agent-less static node (`go run ./cmd/fips-derive npub1... >> allowlist.txt`).

### `render-nftables.sh` env

Used by `up.sh` (which sources `deploy/.env`): `FIPS_IF`, `EXIT_FIPS_ADDR`,
`CAPTIVE_PORT`, `MAX_CONNS_PER_SRC` (per-source connection ceiling, `0` =
disabled), `SERVICES_FILE` (default `services.conf`), `ALLOWLIST_FILE`
(default `allowlist.txt`).

### `deploy/unbound.conf`

The server-side resolver config. Point the host resolver at it
(`nameserver 127.0.0.1`) to keep DNS fully server-side.

## Services and packages (data, not env)

Egress **services** and their per-byte **rates** live in the backend catalog,
not in env:

```sh
curl -H "Authorization: Bearer $ADMIN_TOKEN" $URL/admin/services            # list
curl -H "Authorization: Bearer $ADMIN_TOKEN" -XPOST $URL/admin/services \
     -d '{"key":"tor","name":"Tor","port":1081,"rate_ppm":1500000}'         # 1.5x
```

`rate_ppm` is parts-per-million (`1000000` = 1.0×). The shared balance is
decremented by `bytes × rate_ppm / 1e6`. The default `clearnet` service is
displayed as **Connectivity** (its `:1080` dispatcher reaches clearnet + `.onion`
at 1.0×); the optional `tor` service is the **Privacy** rail (`:1081`, forces all
traffic through Tor, typically 1.5×). **Packages** (volume bundles + time
passes) are managed via `/admin/packages`; a default catalog is seeded on first
start. Prices are in **sats** (`price_sats`). A package may carry an
`available_days` window (POST) to make it a **time-limited promo** — the catalog
hides it after that many days, but anyone who already bought it keeps their pass;
`DELETE /admin/packages/{id}` deactivates one. To set the whole catalog at once,
use `deploy/apply-catalog.sh`. See [Maintenance](maintenance.md#admin-quick-reference).

## Addressing the portal over fips

When the portal is reached over fips (for the captive redirect and transparent
login), address it by the portal host's **`<npub>.fips`** name — e.g.
`http://npub1…exit-host-npub….fips:8080/captive`. That name resolves **mesh-wide
by derivation** (every fips node maps `<npub>.fips` to the derived fd00::/8
address with no hosts-file entry), and it keeps working if the host's address
changes. Prefer it for both `CAPTIVE_PORTAL_URL` and `PORTAL_PUBLIC_URL`.

Avoid:

- **Raw IPv6 literals** (`http://[fd..]:8080`) — brittle, and a proxied browser
  can't reliably bypass them (Firefox's "No proxy for" doesn't honor IPv6).
- **Local hostname aliases** (`remote.fips`, `home.fips`) — those come from each
  node's own `/etc/fips/hosts` and mean different things on different nodes.

Client browsers reaching the portal through a SOCKS proxy should route `.fips`
names **direct** (a PAC returning `DIRECT` for `dnsDomainIs(host, ".fips")`), so
the portal is fetched natively over fips while Internet traffic goes through the
exit. See [Troubleshooting](troubleshooting.md#captive-redirect-loops-in-a-browser-or-denied-by-proxy).

## The portal and the fips firewall

The nftables gate deliberately touches **only** the SOCKS service ports, never
general fips traffic. So if the backend serves the portal over fips (for
transparent login), the **fips mesh firewall** must be told to allow the portal
port (e.g. `:8080`) inbound — otherwise clients can reach the SOCKS port but not
the portal. This is separate from the nftables gate; configure it in your fips
setup.

## Tests and development

Store integration tests run only when `TEST_DATABASE_URL` is set and require
serial execution:

```sh
TEST_DATABASE_URL=postgres://fips:pw@localhost:5433/fips_test go test -p 1 ./...
```

> **Use a throwaway database.** The integration tests `DROP SCHEMA public
> CASCADE` — pointing `TEST_DATABASE_URL` at a live/validation database will
> wipe it. Spin up a dedicated one:
> `docker run -d --name fips-pg -e POSTGRES_USER=fips -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=fips_test -p 5433:5432 postgres:16-alpine`.
