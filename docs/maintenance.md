# Maintenance & operations

Day-two tasks: managing accounts, adding nodes/services, rotating secrets,
backups, and upgrades. Admin calls use the backend's `/admin` API (bearer
`ADMIN_TOKEN`).

```sh
H="Authorization: Bearer $ADMIN_TOKEN"; URL=https://backend.example:8080
```

## Admin quick reference

```sh
# Accounts & access
curl -H "$H" -XPOST $URL/admin/accounts   -d '{"npub":"npub1..."}'
curl -H "$H" -XPOST $URL/admin/credit     -d '{"npub":"npub1...","kind":"volume","gb":50,"days":90}'
curl -H "$H" -XPOST $URL/admin/credit     -d '{"npub":"npub1...","kind":"time","days":30}'
curl -H "$H" -XPOST $URL/admin/whitelist  -d '{"owner_npub":"npub1...","guest_npub":"npub1...","label":"laptop"}'
curl -H "$H" -XPOST $URL/admin/whitelist  -d '{"owner_npub":"npub1...","guest_npub":"npub1...","enabled":false}'  # disable a guest
curl -H "$H"        $URL/admin/authz       # current authorized set

# Catalog  (price_sats is in sats; add "available_days":N for a time-limited promo)
curl -H "$H"        $URL/admin/packages
curl -H "$H" -XPOST $URL/admin/packages   -d '{"kind":"volume","name":"100 GB / 180d","gb":100,"days":180,"price_sats":70000}'
curl -H "$H" -XPOST $URL/admin/packages   -d '{"kind":"time","name":"1 day pass (special)","days":1,"price_sats":21,"available_days":30}'  # promo, hidden after 30d
curl -H "$H" -XDELETE $URL/admin/packages/<id>   # deactivate a package (leaves the catalog; existing purchases unaffected)
# Replace the whole catalog at once: deploy/apply-catalog.sh  (URL=... ADMIN_TOKEN=... sh deploy/apply-catalog.sh)
curl -H "$H"        $URL/admin/services
curl -H "$H" -XPOST $URL/admin/services   -d '{"key":"tor","name":"Tor","port":1081,"rate_ppm":1500000}'        # Privacy rail (1.5x)
curl -H "$H" -XPOST $URL/admin/services   -d '{"key":"clearnet","name":"Connectivity","port":1080,"rate_ppm":1000000}'  # rename/retune the connectivity service (key stays clearnet)

# Payments
curl -H "$H" -XPOST $URL/admin/settle     -d '{"purchase_id":"..."}'   # manual settle (same seam the webhook uses)

# Nodes
curl -H "$H" -XPOST $URL/admin/enroll-token -d '{"note":"exit-02"}'
```

## Add another exit node

The backend is multi-node; the authorized set is global (any authorized address
may use any node).

1. Issue an enroll token: `POST /admin/enroll-token`.
2. On the new host, follow [Installation §3](install.md#3-exit-node) with that
   token and the node's own `EXIT_FIPS_ADDR` / `EXTERNAL_IF`.
3. It appears after `docker logs deploy-agent-1` shows `enrolled as node <id>`.

## Add an egress service (e.g. a second exit layer)

Adding a service is configuration only — the gate, captive, agent, and billing
are service-agnostic. All three must go together (the gate should list a port
only when an authorized-only endpoint is actually listening there):

1. **Catalog row** (backend, once): `POST /admin/services` with its `key`,
   `port`, and `rate_ppm`.
2. **SOCKS endpoint** (each exit node): run it on that port bound to
   `EXIT_FIPS_ADDR` only. For Tor: `docker compose --profile tor up -d tor`.
3. **Gate + counters** (each exit node): add `<key> <port>` to
   `deploy/services.conf`, then `sudo -E ./up.sh reload`.

See the [Tor egress runbook](phase4b-tor.md) for the worked example. To retire a
service, reverse all three (disable the catalog row with `"enabled":false`).

To reach **more networks over the same port** (e.g. clearnet + `.onion` on
`:1080`) rather than adding a port, that's the connectivity dispatcher — no new
gate/catalog entry, since it's still one port at one rate. See
[Connectivity](connectivity.md).

## Revoke or suspend access

- **Guest:** `POST /admin/whitelist` with `"enabled":false` — removed from the
  authorized set on the next recompute (seconds).
- **Whole account:** it loses access automatically when its entitlements expire
  or run out of volume. Usage that exhausts a package triggers an inline revoke
  within one usage interval (≤ ~60 s).
- **Immediately, everywhere:** cutting a node off is loading an empty set; the
  agent also fails **closed** if `FIPS_AGENT_FAIL_CLOSED_AFTER_GRACE=1` and the
  backend is unreachable past the grace window.

## Rotate secrets

| Secret | How to rotate |
|---|---|
| `ADMIN_TOKEN` | Change it in `backend.env`, restart the backend. Update any admin scripts. |
| `SESSION_SECRET` | Change + restart; invalidates existing portal sessions (users re-login). |
| `CHALLENGE_SECRET` | Change + restart; in-flight login challenges are voided. |
| `CAPTIVE_TOKEN_SECRET` | Change on **both** the backend and **every** exit node's captive daemon, then restart both. In-flight captive tokens are voided. |
| `BTCPAY_WEBHOOK_SECRET` | Update in the BTCPay store webhook **and** `backend.env`, restart the backend. |
| Node identity | Re-enroll the node (new token + wipe `deploy_agent-state`) — see [Troubleshooting](troubleshooting.md#agent-401--unknown-node-after-a-backend-reset). |

## Back up & restore Postgres

All account/entitlement/usage/authz state lives in Postgres. Back it up
regularly:

```sh
# Backup (from the backend host)
docker exec <pg-container> pg_dump -U "$PGUSER" "$PGDATABASE" | gzip > fips-$(date +%F).sql.gz

# Restore into a fresh database
gunzip -c fips-2026-01-01.sql.gz | docker exec -i <pg-container> psql -U "$PGUSER" -d "$PGDATABASE"
```

After a restore, **re-enroll exit nodes** if the `exit_nodes` rows changed
(their durable state won't match) — see Troubleshooting. Migrations are embedded
and apply automatically on backend start, so restoring an older dump and
starting a newer backend upgrades the schema in place.

## Upgrade the stack

```sh
git pull
# Backend host:
docker compose -f deploy/backend-compose.yaml up -d --build   # migrations auto-apply on start
# Each exit node:
cd deploy && sudo -E ./up.sh reload                            # re-render the gate ONLY if services.conf changed
docker compose --profile agent --profile tor up -d --build     # rebuild dispatch/exit/captive/agent (+tor for .onion & the privacy rail)
```

The agent and backend speak a versioned API and the agent tolerates brief
backend downtime (fail-open within the grace window), so a rolling backend
restart doesn't drop clients.

## Update the Dante version

`exit/Dockerfile` pins Dante by version, URL, and SHA-256 as build args — bump
all three together:

```
ARG DANTE_VERSION=1.4.4
ARG DANTE_URL="https://www.inet.no/dante/files/dante-${DANTE_VERSION}.tar.gz"
ARG DANTE_SHA256="<sha256 of the new tarball>"
```

Then rebuild the exit image (`docker compose up -d --build exit-clearnet`).

## Monitoring & log hygiene

- **Node liveness:** `exit_nodes.last_seen` advances on each agent heartbeat;
  alert if it stalls. `GET /admin/authz` should track intended access.
- **Usage:** per-account totals accumulate in `usage_samples`; the dashboard
  shows per-service consumption. The shared balance decrements by
  `bytes × rate_ppm / 1e6`.
- **Privacy:** keep Dante logging minimal in production — retain per-account
  byte totals, **not** destinations. The dispatcher likewise never logs
  destinations. The design never needs destination logs.
- **Agent state:** `FIPS_AGENT_STATE_DIR` (`identity.json` 0600 +
  `runtime.json`) survives restarts without double-counting or losing bytes;
  back it up if you want node identity to survive a host rebuild (otherwise just
  re-enroll).

## Payments upkeep

BTCPay runs against your **external** bitcoind/monerod over Tor. Keep those
nodes synced and reachable, keep the Monero **view-only** wallet on BTCPay in
sync, and verify the store **Transaction Speed** stays at ≥ 1 confirmation so
on-chain access is only granted on finalization. Full runbook:
[phase4-btcpay.md](phase4-btcpay.md).
