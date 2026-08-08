# backend (Phase 3)

The fips-exit control plane: the agent-facing API plus admin endpoints, backed
by Postgres. It is the production replacement for `cmd/fake-backend`.

Stack (per the project's settled choices): stdlib `net/http` (Go 1.22 routing),
`pgx` for Postgres, plain SQL. Nostr login + the user portal are the next slice.

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
- **Admin API** (static bearer token): issue enroll tokens, create accounts,
  manage whitelist entries, and credit entitlements. Crediting is the Phase-4
  payment hook stand-in — until BTCPay lands, an admin grants packages here.

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
