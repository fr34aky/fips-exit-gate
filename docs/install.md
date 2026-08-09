# Installation

This walks through a working deployment: a **backend host** (control plane +
portal + Postgres) and one **exit node** (the SOCKS5 egress + gate + agent).
They can be the same machine for testing, but the design keeps them separate so
you can add more exit nodes against one backend.

For every environment variable mentioned here, see
[Configuration](configuration.md). For payments, choose a rail
(`PAYMENT_RAIL`): [BTCPay](phase4-btcpay.md) (on-chain BTC + Lightning + Monero)
or [phoenixd](phoenixd.md) (direct Lightning, lighter to run). This guide brings
up everything *except* real payments and uses admin credits to grant access.

## Topology

```
Backend host                         Exit node (a fips participant)
┌──────────────────────────┐         ┌────────────────────────────────┐
│ Postgres                 │◀── API ─│ exit-agent                     │
│ backend (API + portal)   │         │ Dante (:1080) + captive (:1088)│
│ [BTCPay + Tor, optional] │         │ unbound · nftables gate        │
└──────────────────────────┘         └────────────────────────────────┘
```

## Prerequisites

**Both hosts**

- Docker + Docker Compose, and Go ≥ 1.25 if you build/run binaries directly.

**Exit node**

- Already **joined to fips**, with the fips TUN interface up (e.g. `fips0`) and
  the **fips mesh firewall enabled** (required — it prevents source-address
  spoofing, which is the whole basis of authentication; see
  [threat model](threat-model.md)).
- `nft` (nftables) on the host, and a kernel that supports it (≥ 5.x; validated
  on 6.8).
- Its own fips address (`EXIT_FIPS_ADDR`) and a public egress interface
  (`EXTERNAL_IF`) with IPv4 and/or IPv6.

**Backend host**

- Reachable by the exit node(s). If it also serves the **portal over fips**
  (for transparent login), it must be a fips participant and its fips port must
  be allowed in the fips firewall (see [Configuration](configuration.md#the-portal-and-the-fips-firewall)).

```sh
git clone https://github.com/fr34aky/fips-exit-gate && cd fips-exit-gate
```

---

## 1. Backend host

The backend serves the agent API, the portal, and admin endpoints, backed by
Postgres. Migrations run and the `clearnet` service + default package catalog
are seeded automatically on first start.

```sh
cd deploy
cp backend.env.example backend.env          # then edit — see below
chmod 600 backend.env
```

Fill in `backend.env`. Example values (generate every secret with
`openssl rand -base64 32` — the `…` below stands for the rest of a real one):

```sh
# --- Postgres ---
PGUSER=fips
PGPASSWORD=8Qk4wPw2qf5aEQH0aay…       # DB password
PGDATABASE=fips_exit

# --- Admin + portal secrets (openssl rand -base64 32 each) ---
ADMIN_TOKEN=cIpqUa4x0ko6bQ…Qk4w=      # protects the /admin API
SESSION_SECRET=Rk9mQ2p…               # portal session cookies (set it, or sessions drop on restart)
CHALLENGE_SECRET=Vb7xLp0…             # login challenges
CAPTIVE_TOKEN_SECRET=Pgbrp/w8o4ub…    # MUST equal the exit node's value, byte-for-byte

# --- Portal reachability + login ---
# Base URL of the portal (buyers return here after paying). Over fips, use the
# exit/portal host's <npub>.fips URL on HTTP; behind a TLS proxy use your https URL.
PORTAL_PUBLIC_URL=http://npub1lx2m36mtzpvae7caw6tphqzhuyufg82y63p8lvd8n6nvkdkw0thq08hdpz.fips:8080
PORTAL_TRUST_FIPS_SOURCE=1   # transparent fips login (default on); 0 only behind a source-masking proxy
PORTAL_SECURE_COOKIES=0      # 0 for the HTTP fips portal (default); 1 when served over HTTPS

# --- Metrics (optional) ---
METRICS_TOKEN=               # empty = /metrics open (restrict by network); set a token to require it

# --- Payments: pick a rail — see "6. Payments" below (empty = admin-credit only) ---
PAYMENT_RAIL=                # btcpay | phoenixd | empty
```

Bring it up:

```sh
set -a; . ./backend.env; set +a
docker compose -f backend-compose.yaml up -d --build     # Postgres + backend on :8080
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/admin/authz
# -> {"addresses":[],"rev":0}
```

`backend-compose.yaml` publishes the API on `127.0.0.1:8080` by default —
**front it with TLS** (a reverse proxy) for real exit nodes to reach it. For
**transparent portal login over fips**, the backend must bind the fips address
and see the client's real source address, so run it with **host networking** (no
bridge NAT) rather than the default published port. See
[Configuration](configuration.md#backend).

## 2. Enroll the exit node

The agent authenticates with a one-time enroll token issued by the backend:

```sh
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
     -XPOST http://localhost:8080/admin/enroll-token -d '{"note":"exit-01"}'
# -> {"enroll_token":"..."}    keep this for step 3
```

## 3. Exit node

On the exit host, from the repo root:

```sh
cd deploy
cp .env.example .env            # then edit
```

Set in `.env` (example values — replace with your own):

```sh
# --- Interfaces / this node's identity ---
FIPS_IF=fips0                                            # fips TUN interface (see: ip -6 addr show fips0)
EXIT_FIPS_ADDR=fd6b:b19b:6700:c923:df48:31a8:698b:bb25   # this node's fips address (services listen here)
EXTERNAL_IF=eth0                                         # public egress interface (with IPv4 and/or IPv6)

# --- Captive redirect (unauthorized clients) ---
# Use the portal host's <npub>.fips URL over fips (HTTP), or your public portal URL.
CAPTIVE_PORTAL_URL=http://npub1lx2m36mtzpvae7caw6tphqzhuyufg82y63p8lvd8n6nvkdkw0thq08hdpz.fips:8080/captive
CAPTIVE_TOKEN_SECRET=Pgbrp/w8o4ub…                       # MUST equal the backend's value, byte-for-byte

# --- Agent → backend ---
FIPS_AGENT_BACKEND_URL=http://127.0.0.1:8080   # plain HTTP if co-located; https://backend.example:8080 behind TLS
FIPS_AGENT_ENROLL_TOKEN=<the token from step 2>   # one-time; only read until the node has enrolled
FIPS_AGENT_NODE_NAME=exit-01

# --- Optional hardening / metrics ---
MAX_CONNS_PER_SRC=0             # per-source connection ceiling (e.g. 256); 0 = off
FIPS_AGENT_METRICS_ADDR=        # e.g. :9101 to expose the agent's /metrics
CAPTIVE_METRICS_ADDR=           # e.g. :9102 to expose the captive daemon's /metrics
```

> `FIPS_AGENT_BACKEND_URL` must be **`http://`** for a plain backend on `:8080` —
> pointing `https://` at a non-TLS backend is a common bring-up failure.

Leave `allowlist.txt` **empty** — in agent mode the agent owns the authorized
set (a static allowlist is the Phase-1 alternative; run one, not both).

Load the nftables gate, then start the stack **with the agent profile**:

```sh
set -a; . ./.env; set +a
sudo -E ./up.sh up                                   # renders + validates + loads nftables, starts exit+captive+unbound
docker compose --profile agent up -d --build agent   # start the agent
docker logs deploy-agent-1 | tail                    # -> "enrolled as node <id>"
```

`up.sh` runs `nft -c -f` before touching the live ruleset, so a malformed gate
fails safely. Point the host resolver at unbound if you want DNS fully
server-side (`echo 'nameserver 127.0.0.1' > /etc/resolv.conf`), or skip unbound
and let Dante use the host resolver.

> Instead of compose, the exit node can run as systemd units — see
> `deploy/systemd/`.

## 4. Grant a client and verify

Grant access without payments by crediting an account directly (admin):

```sh
H="Authorization: Bearer $ADMIN_TOKEN"; URL=http://backend:8080
# Create the account and credit it a package:
curl -s -H "$H" -XPOST $URL/admin/accounts -d '{"npub":"npub1..."}'
curl -s -H "$H" -XPOST $URL/admin/credit   -d '{"npub":"npub1...","kind":"volume","gb":50,"days":90}'
curl -s -H "$H" $URL/admin/authz            # -> the account's fips address appears
```

Within a few seconds the agent mirrors it into the kernel set
(`sudo nft list set inet fips_exit authorized`). Then, **from a separate fips
peer** whose npub you credited (not the exit host itself — see
[Troubleshooting](troubleshooting.md#everything-works-but-the-exit-host-itself-isnt-gated)):

```sh
EXIT=<EXIT_FIPS_ADDR>
curl --socks5-hostname "[$EXIT]:1080" https://ifconfig.co      # -> the exit's public IP
curl --socks5-hostname "[$EXIT]:1080" http://example.com -D -  # unauthorized client -> HTTP 302 to portal
```

You now have a working exit. To let users **buy** access instead of admin
credits, configure a payment rail (**§6** below); to add the **Tor** egress
service, see [the Tor runbook](phase4b-tor.md).

## 5. Portal login

Users manage their account and packages at `PORTAL_PUBLIC_URL`:

- **Nostr signer** (from anywhere): "Sign in with extension" (NIP-07), or paste
  a signed event from any signer (incl. Amber).
- **Transparent fips login** (over fips): **on by default** — when the backend
  listens on the fips interface with no proxy masking the source, the client's
  npub-derived address authenticates it with no signature. Requires the fips
  firewall to allow the portal port — see
  [Configuration](configuration.md#the-portal-and-the-fips-firewall). Set
  `PORTAL_TRUST_FIPS_SOURCE=0` only behind a source-masking reverse proxy, and
  `PORTAL_SECURE_COOKIES=1` when the portal is served over HTTPS.

## 6. Payments (optional)

Without a rail, access is granted only by admin credits (§4). To let users
**buy**, set `PAYMENT_RAIL` in `backend.env` to **one** rail and its variables,
then restart the backend. The buy flow then shows either a hosted checkout
(BTCPay) or a Lightning invoice page (phoenixd), and settlement grants the
package automatically. The backend **refuses to start** if the chosen rail's
webhook secret is empty (an unsigned webhook would be forgeable).

You can exercise either rail with **no real money** using the bundled test
doubles — `cmd/fake-btcpay` and `cmd/fake-phoenixd` (see each runbook).

### Option A — phoenixd (direct Lightning, lighter to run)

Run an [ACINQ phoenixd](phoenixd.md) node (one self-custodial binary). In
`~/.phoenix/phoenix.conf`:

```ini
http-password=s3cret-http-pw
webhook-url=http://127.0.0.1:8080/payments/phoenixd/webhook
webhook-secret=whsec-9f3c1d…
```

Then in `backend.env`:

```sh
PAYMENT_RAIL=phoenixd
PHOENIXD_URL=http://127.0.0.1:9740     # phoenixd's HTTP API
PHOENIXD_PASSWORD=s3cret-http-pw       # = http-password above
PHOENIXD_WEBHOOK_SECRET=whsec-9f3c1d…  # = webhook-secret above (required)
# PHOENIXD_SOCKS5=127.0.0.1:9050       # only if reaching phoenixd over Tor
PHOENIXD_POLL_INTERVAL_S=15            # reconciler poll (settles missed webhooks)
PHOENIXD_INVOICE_TTL_S=3600            # unpaid invoice lifetime before it's voided
```

Lightning is final on receipt — access is granted immediately. Lightning only
(no on-chain BTC / Monero), and ACINQ charges a receiving/liquidity fee, so
**price packages above that floor**. Full details: [docs/phoenixd.md](phoenixd.md).

### Option B — BTCPay (on-chain BTC + Lightning + Monero, heavier)

Stand up [BTCPay Server](phase4-btcpay.md), create a store, a store-scoped API
key, and a webhook. Then in `backend.env`:

```sh
PAYMENT_RAIL=btcpay
BTCPAY_URL=https://btcpay.example      # or http://xxxxxxxx.onion
BTCPAY_API_KEY=3a7f0b2c…               # store key, permission btcpay.store.cancreateinvoice
BTCPAY_STORE_ID=9KkD2r…
BTCPAY_WEBHOOK_SECRET=whsec-2b1a4e…    # = the store's webhook secret (required)
# BTCPAY_SOCKS5=127.0.0.1:9050         # only to reach a BTCPay .onion over Tor
```

Set the store's **Transaction Speed to ≥ 1 confirmation** so on-chain payments
grant only once finalized (Lightning stays instant). Full runbook:
[docs/phase4-btcpay.md](phase4-btcpay.md).

## Uninstall / teardown

```sh
# exit node
cd deploy && docker compose --profile agent --profile tor down -v
sudo nft delete table inet fips_exit
# backend host
docker compose -f backend-compose.yaml down          # add -v to drop the database volume
```
