# Phase 4c — Connectivity dispatcher (clearnet + .onion on one port)

Phase 4c widens the `:1080` service from clearnet-only to **connectivity**: the
same port now reaches the clear internet **and** `.onion` services, routed
automatically by destination. This gives the node two distinct offerings:

| Port | Service | Reaches | Rate | Intent |
|---|---|---|---|---|
| `:1080` | **Connectivity** | clearnet + `.onion` | 1.0× | reachability — `.onion` "just works" |
| `:1081` | **Privacy** | everything, forced through Tor | 1.5× | anonymity — your traffic joins the Tor crowd |

The two are different features, not duplicates. On **Connectivity**, `.onion`
traffic enters Tor **from the exit's IP** — that is onion *reachability*, not
anonymity. **Privacy** is where anonymity lives (all traffic leaves via a Tor
exit). Keep the product copy clear on this.

```
fips client ──┬─ :1080 ─▶ dispatch ─┬─ *.onion ─▶ Tor (loopback SocksPort) ─▶ Tor network
              │                      └─ else    ─▶ Dante (loopback) ─▶ clearnet
              └─ :1081 ─▶ Tor (force-all) ─▶ Tor network
                    ▲
              same nft gate, acct counters, agent, billing — all unchanged
```

## How the dispatcher works

The dispatcher (`dispatch/`) is a minimal SOCKS5 CONNECT proxy that owns the
connectivity port on the fips address. For each CONNECT it looks **only at the
destination host**:

- a domain ending in `.onion` → forwarded to **Tor's loopback SocksPort**
  (Tor does the rendezvous; the name is never resolved locally);
- anything else — clearnet names and IP literals → forwarded to **Dante over
  loopback**, which resolves DNS server-side and egresses.

It carries **no egress policy of its own**. The clearnet path inherits Dante's
guards (fd00::/8, RFC1918, loopback, cloud-metadata, SMTP, and `bind`/UDP all
blocked); the onion path inherits Tor's (`ClientRejectInternalAddresses`), so
neither can re-enter fips or reach private space. It is connect-only and never
logs destinations, matching the rest of the exit's privacy stance.

## What did *not* change (the invariant, again)

Because it is still **one port at one rate**, everything downstream is untouched:

- **nftables gate + `acct` counters** key on `(src addr, dport=1080)`. The
  dispatcher↔upstream hops are on loopback and are never metered — the counter
  is exactly the client's connectivity bytes.
- **exit-agent** maps `port → service key` from the heartbeat catalog. `:1080`
  is still the `clearnet` service key; only its display name changed.
- **backend billing** weights the single `clearnet` sample at 1.0×. No schema or
  billing change.
- **captive daemon** still gates the port generically (unauthorized → 302).

The service **key stays `clearnet`** (it is the foreign key on every historical
usage row); only the **display name** becomes **Connectivity**.

## Topology / ports

| Component | Binds | Role |
|---|---|---|
| dispatch | `[EXIT_FIPS_ADDR]:1080` | client-facing connectivity SOCKS (gated, metered) |
| Dante (`exit-clearnet`) | `127.0.0.1:1090` | clearnet egress engine + policy + DNS (loopback only) |
| Tor privacy rail | `[EXIT_FIPS_ADDR]:1081` | force-all Tor (gated, metered at 1.5×) |
| Tor dispatch port | `127.0.0.1:9052` | onion routing for the dispatcher (local only) |

Onion routing on `:1080` uses the **same Tor** as the `:1081` privacy rail — it
just adds a loopback SocksPort. So **enabling onion on `:1080` requires the
`tor` compose profile** to be running. If Tor is down, clearnet still works and
`.onion` CONNECTs return a SOCKS host-unreachable error (graceful degradation).

## Enabling it on an exit node

1. **Bring up the stack with the Tor profile** (needed for `.onion`):

   ```sh
   cd deploy
   docker compose -f docker-compose.yaml --profile tor up -d --build
   ```

   This builds/starts `dispatch` on `:1080`, moves Dante to `127.0.0.1:1090`,
   and gives Tor its loopback SocksPort (`127.0.0.1:9052`) alongside `:1081`.
   No nftables change is needed — `:1080` is already the gated service port.

2. **Rename the catalog display name** to "Connectivity" (the key stays
   `clearnet`). On a fresh DB, `SeedDefaults` already does this. On a **live**
   node whose row still says "Clearnet", re-register it:

   ```sh
   curl -H "Authorization: Bearer $ADMIN_TOKEN" -XPOST $URL/admin/services \
     -d '{"key":"clearnet","name":"Connectivity","port":1080,"rate_ppm":1000000,"enabled":true}'
   curl -H "Authorization: Bearer $ADMIN_TOKEN" $URL/admin/services   # verify
   ```

   (Equivalently: `UPDATE services SET name='Connectivity' WHERE key='clearnet';`)

## Verifying

From an **authorized** fips client (a separate peer, not the exit host):

```sh
# Clearnet via connectivity — exits as the node's public IP.
curl --socks5-hostname $EXIT_FIPS_ADDR:1080 https://ifconfig.co

# .onion via connectivity — reachable through the SAME port.
curl --socks5-hostname $EXIT_FIPS_ADDR:1080 http://<some>.onion/

# Privacy rail still forces everything through Tor.
curl --socks5-hostname $EXIT_FIPS_ADDR:1081 https://check.torproject.org/api/ip
# expect {"IsTor":true,...}
```

Both clearnet and onion on `:1080` draw down the **one** connectivity balance at
1.0× (confirm on the dashboard's per-service usage — all `:1080` bytes land on
the `clearnet` service). Remember `--socks5-hostname` (remote DNS): a plain
`--socks5` resolves locally and would never form a `.onion` request.

## Migrating an existing node (e.g. VM1867)

```sh
cd ~/fips-exit-gate && git pull
cd deploy
# Rebuild + restart the exit stack with Tor (for onion). Dante moves to loopback,
# dispatch takes :1080. Your .env's CLEARNET_PORT is now Dante's loopback port —
# leaving it at 1080 is harmless (loopback), or bump it to 1090 for clarity.
docker compose -f docker-compose.yaml --profile tor up -d --build
# Rename the live catalog display name (step 2 above).
```

The nftables gate is unchanged (still `:1080` + `:1081`), so no `up.sh reload`
is required — which also means the authorized set is **not** reset.

## Adding `.i2p` later

The design already accommodates it: run an i2pd router with a loopback SOCKS
proxy and add one branch to the dispatcher (`*.i2p → i2pd`). It is deferred for
now — Tor is already running so `.onion` is nearly free, whereas i2pd is a real
new daemon (router bootstrap, RAM/disk, slow first-connect) for niche demand.
Ship onion-first; add i2p behind a profile if users ask.

See also [Phase 4b — Tor](phase4b-tor.md) (the privacy rail) and the earlier
comparison with destination-routing proxies like hedproxy.
