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

Set at least these in `backend.env` (generate each secret with
`openssl rand -base64 32`):

```sh
PGPASSWORD=...                 # Postgres password
ADMIN_TOKEN=...                # protects /admin
SESSION_SECRET=...             # portal session cookies
CHALLENGE_SECRET=...           # login challenges
CAPTIVE_TOKEN_SECRET=...       # MUST equal the exit node's CAPTIVE_TOKEN_SECRET
PORTAL_PUBLIC_URL=https://portal.example   # where buyers are sent back after paying
```

Bring it up:

```sh
set -a; . ./backend.env; set +a
docker compose -f backend-compose.yaml up -d --build     # Postgres + backend on :8080
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/admin/authz
# -> {"addresses":[],"rev":0}
```

`backend-compose.yaml` publishes the API on `127.0.0.1:8080` by default —
**front it with TLS** (a reverse proxy) for real exit nodes to reach it, or bind
it to a fips address for transparent portal login. See
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

Set in `.env`:

```sh
FIPS_IF=fips0                   # your fips TUN interface
EXIT_FIPS_ADDR=fd..:..          # this node's own fips address (services listen here)
EXTERNAL_IF=eth0                # public egress interface
CAPTIVE_PORTAL_URL=http://[<EXIT_FIPS_ADDR>]:8080/captive   # or your public portal URL
CAPTIVE_TOKEN_SECRET=...        # MUST equal the backend's CAPTIVE_TOKEN_SECRET
# Agent → backend:
FIPS_AGENT_BACKEND_URL=https://backend.example:8080
FIPS_AGENT_ENROLL_TOKEN=<the token from step 2>
FIPS_AGENT_NODE_NAME=exit-01
```

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
credits, add BTCPay ([runbook](phase4-btcpay.md)); to add the **Tor** egress
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

## Uninstall / teardown

```sh
# exit node
cd deploy && docker compose --profile agent --profile tor down -v
sudo nft delete table inet fips_exit
# backend host
docker compose -f backend-compose.yaml down          # add -v to drop the database volume
```
