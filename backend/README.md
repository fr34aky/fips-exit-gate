# backend (Phase 3)

The fips-exit control plane: the agent-facing API plus admin endpoints, backed
by Postgres. It is the production replacement for `cmd/fake-backend`.

Stack (per the project's settled choices): stdlib `net/http` (Go 1.22 routing),
`pgx` for Postgres, `btcec/schnorr` for nostr signature verification, plain SQL,
server-rendered `html/template`.

## What it does now

- **Agent API** (`docs/api-agent-backend.md`): `POST /v1/nodes/enroll`,
  `GET /v1/nodes/{id}/authz` (long-poll, full+delta), `POST /v1/nodes/{id}/usage`
  (idempotent, rate-weighted consumption, inline revoke on exhaustion),
  `POST /v1/nodes/{id}/heartbeat` (returns the service catalog + config). Node
  requests use a bearer auth token issued at enrollment.
- **Authorization model**: the authorized set is global (any authorized address
  may use any node) and materialized in `authz_current`, with every change
  appended to `authz_revisions` (the revision agents poll). An address is
  authorized iff its account is active and has an active entitlement (a time
  pass, or a volume package with remaining balance).
- **Package catalog**: a seeded catalog of buyable packages (volume bundles +
  time passes). The portal `/packages` page lets a user buy one, creating a
  **pending** purchase; **settling** it grants the entitlement. `SettlePurchase`
  is idempotent (status guard + unique `entitlements.purchase_id`) — it is the
  exact seam the Phase-4 BTCPay webhook will call. In dev,
  `PORTAL_DEV_AUTOSETTLE=1` settles immediately so the flow works without a
  payment rail.
- **Admin API** (static bearer token): issue enroll tokens, create accounts,
  manage whitelist entries, credit entitlements directly, manage the catalog,
  and settle purchases.

## User portal

Server-rendered pages (`backend/templates`) with two login paths, both ending
in a stateless HMAC-signed session cookie keyed to the npub:

- **Nostr signature** — `GET /auth/challenge` issues a stateless challenge; the
  client signs a nostr event carrying it (NIP-07 browser extension via JS, or
  any signer incl. Amber by pasting the signed event); `POST /auth/verify`
  checks the Schnorr signature (`backend/nostr`), the challenge HMAC, and
  freshness.
- **Transparent fips-source** (`POST /auth/fips`, off by default) — when
  `PORTAL_TRUST_FIPS_SOURCE=1` and the request arrives from an fd00::/8 source,
  the npub-derived source address authenticates the identity with no signature.
  A `?npub=` claim is accepted only if it derives to the trusted source address
  (`fipsaddr.CheckDerivation`). Enable only on a fips-bound listener with no
  proxy masking the source.

Pages: `/login`, `/dashboard` (packages, usage, whitelist management),
`/captive` (landing for the exit's redirect; verifies the captive token).

## Run (dev)

```sh
cd deploy
cp backend.env.example backend.env   # set PGPASSWORD, ADMIN_TOKEN
set -a; . ./backend.env; set +a
docker compose -f backend-compose.yaml up -d --build   # postgres + backend on :8080
```

Migrations are embedded and applied on startup; the `clearnet` service is
seeded automatically.

## Point the exit-agent at it

The agent speaks the exact same API `cmd/fake-backend` did, so just change its
backend URL (see `agent/README.md`), get an enroll token, and run it:

```sh
curl -H "Authorization: Bearer $ADMIN_TOKEN" -XPOST http://backend:8080/admin/enroll-token -d '{"note":"exit-01"}'
# -> {"enroll_token":"..."}  then set FIPS_AGENT_ENROLL_TOKEN + FIPS_AGENT_BACKEND_URL
```

## Admin quick reference

```sh
H='-H Authorization:Bearer '"$ADMIN_TOKEN"
curl $H -XPOST $URL/admin/accounts   -d '{"npub":"npub1..."}'
curl $H -XPOST $URL/admin/credit     -d '{"npub":"npub1...","kind":"volume","gb":50,"days":90}'
curl $H -XPOST $URL/admin/credit     -d '{"npub":"npub1...","kind":"time","days":30}'
curl $H -XPOST $URL/admin/whitelist  -d '{"owner_npub":"npub1...","guest_npub":"npub1...","label":"laptop"}'
curl $H -XPOST $URL/admin/whitelist  -d '{"owner_npub":"npub1...","guest_npub":"npub1...","enabled":false}'
curl $H         $URL/admin/authz
curl $H         $URL/admin/packages
curl $H -XPOST $URL/admin/packages   -d '{"kind":"volume","name":"100 GB / 180d","gb":100,"days":180,"price_sats":70000}'
curl $H -XPOST $URL/admin/settle     -d '{"purchase_id":"..."}'   # Phase-4 webhook seam
```

## Tests

`go test ./backend/...` runs pure checks always; the store integration tests
run only when `TEST_DATABASE_URL` is set:

```sh
TEST_DATABASE_URL=postgres://fips:pw@localhost:5433/fips_exit go test ./backend/...
```

They cover enrollment/auth, credit→authz, rate-weighted consumption with
inline revoke on exhaustion, idempotent replay, delta replay, and the
active-address uniqueness conflict.
