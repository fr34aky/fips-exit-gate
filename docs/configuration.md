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
| `DATABASE_URL` | — (**required**) | Postgres DSN, e.g. `postgres://fips:pw@db:5432/fips_exit`. |
| `ADMIN_TOKEN` | — (**required**) | Bearer token protecting `/admin`. |
| `LISTEN` | `:8080` | Listen address. `:8080` binds all interfaces; use `[<fips-addr>]:8080` to serve the portal only over fips. |
| `SESSION_SECRET` | random | HMAC key for portal session cookies. Set it, or sessions drop on restart. |
| `CHALLENGE_SECRET` | random | HMAC key for login challenges. Set it in production. |
| `CAPTIVE_TOKEN_SECRET` | — | Verifies captive redirect tokens. **Must equal the exit node's value.** |
| `PORTAL_PUBLIC_URL` | `http://localhost:8080` | Public base URL; BTCPay redirects buyers back here after paying. Over fips, prefer the portal's `<npub>.fips` URL (see [Addressing the portal](#addressing-the-portal-over-fips)). |
| `PORTAL_TRUST_FIPS_SOURCE` | **on** | Transparent fips-source login. On by default (the portal is reached natively over fips). Set `0` **only** when a reverse proxy masks the client source (e.g. a public HTTPS portal) — otherwise everyone would appear as the proxy. |
| `PORTAL_SECURE_COOKIES` | **off** | Off by default so login works over the fips portal (HTTP). Set `1` when the portal is served over HTTPS. |
| `PORTAL_DEV_AUTOSETTLE` | `0` | Dev only: `1` grants purchases immediately without any payment rail. **Never in production.** |
| `USAGE_INTERVAL_S` | `30` | Usage-report interval advertised to agents (seconds). |
| `GRACE_MINUTES` | `240` | Outage grace window advertised to agents (fail-open duration). |
| `BTCPAY_URL` | — | BTCPay base URL (e.g. `http://<onion>.onion`). Empty = payments disabled. |
| `BTCPAY_API_KEY` | — | Store-scoped Greenfield API key (`btcpay.store.cancreateinvoice`). |
| `BTCPAY_STORE_ID` | — | BTCPay store id. |
| `BTCPAY_WEBHOOK_SECRET` | — | Verifies the BTCPay webhook HMAC (`BTCPay-Sig`). |
| `BTCPAY_SOCKS5` | — | SOCKS5 proxy (e.g. `127.0.0.1:9050`) to reach a BTCPay `.onion` over Tor. |
| `METRICS_TOKEN` | — | If set, `GET /metrics` requires this bearer token; else `/metrics` is open (restrict by network). See [Observability](observability.md). |

See the [BTCPay runbook](phase4-btcpay.md) for the required store **Transaction
Speed** setting (≥ 1 confirmation) that governs on-chain finalization.

## Exit node (`deploy/.env`)

Consumed by `docker-compose.yaml` and `up.sh`. Also passed to the Dante and
captive containers.

| Variable | Example | Purpose |
|---|---|---|
| `FIPS_IF` | `fips0` | fips TUN interface; the gate only touches traffic ingressing here. |
| `EXIT_FIPS_ADDR` | `fd..:..` | This node's fips address; services listen on it and the gate matches it. |
| `EXTERNAL_IF` | `eth0` | Public egress interface (IPv4/IPv6) Dante exits from. |
| `CLEARNET_PORT` | `1080` | Dante SOCKS port. |
| `CAPTIVE_PORT` | `1088` | Captive daemon port (redirect target for unauthorized traffic). |
| `TOR_PORT` | `1081` | Tor SOCKS port (only with `--profile tor`). |
| `WORKERS` | `4` | Dante worker processes. |
| `CAPTIVE_PORTAL_URL` | `http://<npub>.fips:8080/captive` | Where the captive `302` sends unauthorized clients. Prefer the portal host's `<npub>.fips` URL (see note below). |
| `CAPTIVE_TOKEN_SECRET` | (secret) | Signs the captive token. **Must equal the backend's value.** |

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

## Exit / Dante container

Read by `exit/entrypoint.sh`. Under compose these come from `deploy/.env`.

| Variable | Default | Purpose |
|---|---|---|
| `FIPS_IF` | — | Interface Dante's `internal:` binds. |
| `EXTERNAL_IF` | — | Interface Dante's `external:` egresses from. |
| `CLEARNET_PORT` | `1080` | SOCKS listen port. |
| `WORKERS` | `4` | `sockd` workers. |
| `CONFIG` | `/etc/sockd.conf` | Dante config path (a symlink to `sockd.conf`). |

`exit/sockd.conf` is the Dante policy: credential-free (`socksmethod: none`),
connect-only, and it **blocks** fd00::/8, RFC1918, loopback, and metadata
destinations. Edit it there; it's bind-mounted so no rebuild is needed.

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

### `deploy/allowlist.txt` — Phase-1 static authorization

Newline-separated fips addresses seeded into the `authorized` set at load time.
**Leave empty when running the agent** (the agent owns the set). Populate it
only for an agent-less static node (`go run ./cmd/fips-derive npub1... >> allowlist.txt`).

### `render-nftables.sh` env

Used by `up.sh` (which sources `deploy/.env`): `FIPS_IF`, `EXIT_FIPS_ADDR`,
`CAPTIVE_PORT`, `SERVICES_FILE` (default `services.conf`), `ALLOWLIST_FILE`
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
decremented by `bytes × rate_ppm / 1e6`. **Packages** (volume bundles + time
passes) are managed via `/admin/packages`; a default catalog is seeded on first
start. See [Maintenance](maintenance.md#admin-quick-reference).

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
