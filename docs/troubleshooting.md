# Troubleshooting

Symptom → cause → fix. Many of these were found during real hardware bring-up.

First, a quick health sweep:

```sh
# Exit node
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'exit|captive|agent'
docker logs deploy-agent-1 | tail                       # "enrolled as node <id>"
sudo nft list set inet fips_exit authorized             # who is authorized in-kernel
# Backend
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" $URL/admin/authz    # who SHOULD be authorized
```

The kernel `authorized` set should mirror `/admin/authz` within a few seconds.
If it doesn't, the problem is the **agent ↔ backend** link; if it does but a
client is still blocked, the problem is **that client's entitlement** or the
**path from the client**.

---

## Everything works, but the exit host itself isn't gated

**Symptom:** testing the proxy *from the exit node itself* gives direct access
(no captive redirect, no auth).
**Cause:** the gate only fires on traffic **ingressing via the fips interface**
(`iifname "fips0"`). Traffic from the exit host to its own fips address goes
over loopback, so `iifname != fips0` and the gate returns early.
**Fix:** always test from a **separate fips peer**, never the exit host.

## Authorized client still gets the captive 302 (or blocked)

**Cause 1 — no active entitlement.** The account exists but has no credit, or
it expired / ran out of volume. Check `/admin/authz`: if the address isn't
there, the backend doesn't consider it authorized.
**Fix:** credit it (`/admin/credit`) or check the entitlement's expiry/volume.

**Cause 2 — agent not syncing.** `/admin/authz` lists the address but
`nft list set … authorized` doesn't.
**Fix:** check `docker logs deploy-agent-1`. If it shows `401`/auth errors, see
*Agent 401 after a backend reset* below. Otherwise confirm
`FIPS_AGENT_BACKEND_URL` is reachable from the node.

**Cause 3 — wrong client address.** The client's fips address must derive from
the npub you credited. Verify: `go run ./cmd/fips-derive <npub>` should equal the
client's fips address.

## Portal (or backend API) unreachable over fips, but SOCKS works

**Symptom:** from a fips peer, `:1080` connects but `:8080` times out; curl with
`-s` prints nothing.
**Cause:** the **fips mesh firewall** blocks the port. The nftables gate only
touches the SOCKS service ports by design — it does not open the portal port.
**Fix:** allow the portal port (e.g. `:8080`) inbound in your fips firewall
config. (Verify with `curl -v` from the peer — `Connection timed out` = firewall
drop.) See [Configuration](configuration.md#the-portal-and-the-fips-firewall).

## Transparent fips login doesn't work

- **Login page doesn't offer "Continue as this identity":** `transparentNpub`
  didn't resolve. Check `PORTAL_TRUST_FIPS_SOURCE=1`, that the request actually
  arrives from an fd00::/8 source (no reverse proxy masking it — the backend
  must see the real source), and that the npub has a known enabled whitelist
  entry.
- **`/auth/fips` returns 500:** check `docker logs` / backend log — the handler
  logs the `CreateAccount` error. (A prior bug where a whitelisted guest
  couldn't create their own account is fixed; if you see the
  `whitelist_active_addr` unique-index error, you're on an old build — rebuild.)
- **`303 → /login`:** the source wasn't recognized (not fips, or npub not
  known). Same checks as the login-page case.

## Captive landing page rejects the token ("bad token")

**Cause:** `CAPTIVE_TOKEN_SECRET` differs between the exit node's captive daemon
and the backend. The daemon signs the redirect token; the portal verifies it
with the same secret.
**Fix:** set an identical `CAPTIVE_TOKEN_SECRET` on both and restart both.

## Agent 401 / "unknown node" after a backend reset

**Cause:** the backend's `exit_nodes` row was removed (DB reset/restore), but the
agent still holds its old node id + token in durable state, so every call 401s.
**Fix:** re-enroll — issue a fresh token, wipe the agent state, recreate it:

```sh
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" -XPOST $URL/admin/enroll-token -d '{}'   # new token
# set FIPS_AGENT_ENROLL_TOKEN=<new> in deploy/.env, then:
docker compose -f deploy/docker-compose.yaml --profile agent rm -sf agent
docker volume rm deploy_agent-state
docker compose -f deploy/docker-compose.yaml --profile agent up -d agent
docker logs deploy-agent-1 | tail       # "enrolled as node <new id>"
```

## Agent (or captive) image fails to build

**Cause:** a stale Go base image older than the module's `go` directive.
**Fix:** the Dockerfiles pin `golang:1.25-bookworm`; rebuild with `--build` and
ensure you're on the current tree. If you build binaries directly, use Go ≥ 1.25
(or `GOTOOLCHAIN=auto`).

## Loading the nftables gate fails

- **`nft -c`/`nft -f` "Operation not permitted":** run as root
  (`sudo -E ./up.sh …`); even a check needs privilege.
- **Ruleset rejected:** `up.sh` validates with `nft -c -f` before touching the
  live firewall, so the live gate is unharmed. Fix the inputs it renders from
  (`FIPS_IF`, `EXIT_FIPS_ADDR`, `services.conf`) and re-run `./up.sh reload`.
- **Table missing after reboot:** the gate isn't persistent by default — re-run
  `sudo -E ./up.sh up` (or install the systemd unit).

## Captive redirect loops in a browser (or "denied by proxy")

An unauthorized client browsing a plain-HTTP site through the proxy should be
302'd to the portal. In a browser it can instead **loop** ("redirects in a way
that never completes") or fail with "denied by proxy". Causes:

- **The browser proxies the portal address too.** The captive 302 points at the
  portal (a fips address); if the browser sends *that* through the SOCKS proxy,
  the exit blocks fd00::/8 → the redirect can't complete (loop, since the request
  re-enters the captive). **Fix:** route `.fips` / fd00::/8 **direct**. Firefox's
  "No proxy for" doesn't honor IPv6, so use a PAC:
  `if (dnsDomainIs(host, ".fips")) return "DIRECT";` and address the portal by its
  `<npub>.fips` name (see [Configuration](configuration.md#addressing-the-portal-over-fips)).
- **The source is actually authorized.** Only *unauthorized* sources are sent to
  the captive; a paid-up client goes straight to the exit (check `/admin/authz`).
- **The site is HTTPS.** The captive can only redirect plain HTTP; `https://` is
  cleanly refused (a connection error, never the portal). This is why the portal
  is reached natively over fips, not via the proxy bounce.

## DNS doesn't resolve through the proxy

**Cause:** the client is resolving locally and sending an IP literal, or the
exit's resolver is down.
**Fix:** clients must use **remote DNS** — `curl --socks5-hostname` (not
`--socks5`), and enable "proxy DNS" in browser/app SOCKS settings. On the exit,
either run unbound and point the host resolver at it, or ensure the host
resolver works (Dante resolves via the host).

## An on-chain purchase doesn't unlock immediately

**This is by design.** Access for on-chain BTC is granted only when the payment
is **finalized** (BTCPay `InvoiceSettled`), i.e. after the store's confirmation
threshold — not at 0-conf. The dashboard shows "confirming…" until then.
- For instant access, pay with **Lightning** (final on receipt).
- If it *never* settles, check the BTCPay store **Transaction Speed** setting
  (should be ≥ 1 confirmation, not `High`/0-conf) — see the
  [BTCPay runbook](phase4-btcpay.md).

## A purchase is stuck at `pending` or `processing`

**Cause:** the settlement webhook isn't reaching the backend.
**Fix:** verify BTCPay's store webhook points at
`${PORTAL_PUBLIC_URL}/payments/btcpay/webhook`, is subscribed to the invoice
events, and its secret equals `BTCPAY_WEBHOOK_SECRET`. Watch the backend log
during a test payment; a signed-but-unknown invoice is acked (200) and logged.
A `401` from the webhook endpoint means the secret doesn't match.

## Whitelisting fails with "address already active on another account"

**Cause:** an fips address may be **active on at most one account** (deterministic
attribution). The guest npub is already an enabled entry elsewhere (often its own
account).
**Fix:** disable it on the other account first, or accept that its traffic is
attributed where it's currently active.

## Backend won't start

- `DATABASE_URL is required` / `ADMIN_TOKEN is required`: set them.
- Can't reach Postgres: check the DSN/host and that Postgres is healthy
  (`backend-compose.yaml` gates the backend on a Postgres healthcheck).

## Tests wiped my database

The store integration tests `DROP SCHEMA public CASCADE`. Never point
`TEST_DATABASE_URL` at a live database — use a throwaway one, and run with
`-p 1`. See [Configuration](configuration.md#tests-and-development).
