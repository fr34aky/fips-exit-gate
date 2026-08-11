# Phase 4b — Second egress service: Tor (modularity proof)

Phase 4b adds **Tor** as a second egress service alongside clearnet. The point
is not Tor itself but the proof that the design is modular: a new egress layer
is added with **configuration only** — a catalog row, a SOCKS endpoint on a new
port, and a re-render of the gate. The captive daemon, exit-agent, billing, and
portal are all service-agnostic and were **not changed** to support it.

```
fips client ──┬─ :1080 SOCKS ─▶ Dante  ─▶ clearnet     rate 1.0x ┐
              └─ :1081 SOCKS ─▶ Tor    ─▶ Tor network  rate 1.5x ┘── one shared balance
                    ▲
              same nft gate (authorized → service, else → captive)
              same acct counters, keyed (addr, port)
              same agent (maps port→service from the heartbeat catalog)
              same backend (weighted consumption: bytes × rate_ppm / 1e6)
```

**M4b:** the same client reaches clearnet via `:1080` and Tor via `:1081`, both
drawing on one balance at different rates; adding the service required only
catalog + compose changes.

## What did *not* change (the proof)

- **`deploy/render-nftables.sh`** already templates the gate + `acct` counters
  over every port in `services.conf`. Adding `tor 1081` yields
  `dport { 1080, 1081 }` in the gate and both acct chains — no edit to the script.
- **captive daemon** gates any port generically (redirect target is per-port via
  the ruleset). Unchanged.
- **exit-agent** builds `port → service key` from the heartbeat catalog
  (`agent.go`) and reads the `(addr, port)` `acct` set. A new service just
  appears as a new port. Unchanged.
- **backend billing** already weights each sample `bytes × rate_ppm / 1e6` and
  draws from the account's single shared balance (`store/usage.go`). Unchanged.

The only additions this phase are **generic operator/portal surfaces** the plan
called for, not Tor-specific logic: an admin `POST /admin/services` to register a
service, and a per-service usage table on the dashboard.

## Enabling Tor on an exit node

All three of the following must go together (the gate must list `:1081` only when
something authorized-only is actually listening there):

1. **Register the catalog row** (backend, once — the agent picks it up on its
   next heartbeat):

   ```sh
   curl -H "Authorization: Bearer $ADMIN_TOKEN" -XPOST $URL/admin/services \
     -d '{"key":"tor","name":"Tor","port":1081,"rate_ppm":1500000}'   # 1.5x
   curl -H "Authorization: Bearer $ADMIN_TOKEN" $URL/admin/services      # verify
   ```

2. **Run the Tor SOCKS endpoint** (exit host). It binds `EXIT_FIPS_ADDR:1081`
   only — never the public interface (that would be an open proxy) — and rejects
   non-fips sources as defence in depth behind the gate:

   ```sh
   cd deploy
   docker compose -f docker-compose.yaml --profile tor up -d tor
   ```

   Tor rejects private/internal destinations by default
   (`ClientRejectInternalAddresses 1`), so clients cannot re-enter fips or reach
   RFC1918/loopback through it — matching Dante's egress policy.

3. **Gate + meter the port** (exit host): uncomment `tor 1081` in
   `deploy/services.conf`, then re-render:

   ```sh
   sudo ./up.sh reload      # re-render nftables from services.conf; nft -c validates
   sudo nft list table inet fips_exit | grep 1081   # confirm the port is gated
   ```

   `up.sh` writes `/etc/nftables.d/` (needs root) and auto-loads `deploy/.env`
   for `FIPS_IF`/`EXIT_FIPS_ADDR`/etc.; if you've already `set -a; . ./.env` in
   your shell, use `sudo -E ./up.sh reload` to carry those through instead.

To disable Tor, reverse all three: comment the `services.conf` line +
`sudo ./up.sh reload`, `docker compose --profile tor down`, and disable the
catalog row (`POST /admin/services {"key":"tor",...,"enabled":false}`).

## Verifying M4b

From an **authorized** fips client (a separate peer, not the exit host):

```sh
# Clearnet via :1080 — exits as the node's public IP.
curl --socks5-hostname $EXIT_FIPS_ADDR:1080 https://ifconfig.co

# Tor via :1081 — exits from a Tor exit node (different IP), remote DNS via Tor.
curl --socks5-hostname $EXIT_FIPS_ADDR:1081 https://check.torproject.org/api/ip
# expect {"IsTor":true,...}
```

Then confirm one balance drained at two rates on the dashboard's **Usage by
service** table (or the DB): with equal bytes on each service, Tor's *billed*
column is 1.5× clearnet's, and both decremented the same package. An
**unauthorized** client hitting `:1081` gets the captive 302 on plain HTTP,
exactly like `:1080`.

## Adding yet another service later

The same three steps with a different key/port/rate (e.g. a second exit layer on
`:1082`). Nothing in the gate, captive, agent, or billing path changes — that
invariance is the deliverable this phase verifies.

For a *different* axis — reaching more networks over the **same** port rather
than adding a port — see [Phase 4c — Connectivity](connectivity.md), which turns
`:1080` into a clearnet + `.onion` dispatcher while `:1081` here stays the
force-all-through-Tor privacy rail.
