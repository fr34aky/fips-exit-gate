# HTTP forward proxy — a non-SOCKS egress service

The exit's egress services have so far all been SOCKS endpoints (clearnet via the
dispatcher on `:1080`, Tor on `:1081`). This adds an **HTTP forward proxy** on
`:8080` for clients and operating systems that can point at an HTTP proxy but not
a SOCKS one (system proxy settings, many corporate/managed clients, some CLI
tools). Functionally it egresses the same clearnet path as `:1080`; it exists for
**client compatibility**, not new reach.

```
fips client ──┬─ :1080 SOCKS ─▶ dispatch ─▶ Dante ─▶ clearnet   rate 1.0x ┐
              ├─ :1081 SOCKS ─▶ Tor              ─▶ Tor network  rate 1.5x ┤─ one balance
              └─ :8080 HTTP  ─▶ httpproxy ─▶ Dante ─▶ clearnet   rate 1.0x ┘
                    ▲              (forwards every request over loopback SOCKS)
              same nft gate (authorized → service, else → captive)
              same acct counters, keyed (addr, port)
              same agent (maps port→service from the heartbeat catalog)
              same backend (weighted consumption: bytes × rate_ppm / 1e6)
```

## No egress policy of its own

`httpproxy` carries **no egress policy**. It forwards every request — plaintext
(absolute-form `GET http://…`) and `CONNECT` (HTTPS tunnels) — to **Dante over
loopback** (`127.0.0.1:1090`, `CLEARNET_PORT`) via a SOCKS upstream. So it
inherits Dante's policy verbatim: fd00::/8, RFC1918, metadata, SMTP and `bind`
all blocked, and **DNS resolved server-side** (the hostname is forwarded to
Dante, not resolved on the proxy). Onion routing is *not* offered on the HTTP
port — use the SOCKS connectivity port (`:1080`) for `.onion`.

It binds `EXIT_FIPS_ADDR:8080` only, never the public interface — an HTTP proxy
open to the internet would be abused instantly. The nft gate is the primary
control (only authorized fips sources reach the port); the fips-only bind is
defence in depth.

## What stayed the same, and the one thing that didn't

Unlike Tor (Phase 4b), which was **configuration-only** because Tor is itself a
SOCKS endpoint, the HTTP proxy is the **first non-SOCKS service** — so it touched
exactly one shared component:

- **`deploy/render-nftables.sh`** — unchanged. It templates the gate + `acct`
  counters over every port in `services.conf`; `http 8080` just adds `8080` to
  `dport { … }` and both acct chains. The byte counters are protocol-agnostic.
- **exit-agent** — unchanged. It maps `port → service key` from the heartbeat
  catalog and reads the `(addr, port)` `acct` set; a new port is a new service.
- **backend billing / catalog / portal** — unchanged. The `services` table is
  dynamic (`key/name/port/rate_ppm`); usage is weighted `bytes × rate_ppm / 1e6`
  from one shared balance; the dashboard's per-service table is generic.
- **captive daemon** — **changed** (the one seam). The gate redirects every
  unauthorized service port to the single captive listener, which assumed a SOCKS
  handshake. Captive now **peeks the first byte**: `0x05` → the existing SOCKS
  path; otherwise → an HTTP-proxy path that answers a plain request with the same
  `302 → portal` and refuses `CONNECT`/non-HTTP (the same "can't capture a TLS
  tunnel" limitation as TLS-over-SOCKS). See `captive/httpproxy.go`.

## Enabling the HTTP proxy on an exit node

All three go together (the gate must list `:8080` only when something
authorized-only is actually listening there):

1. **Register the catalog row** (backend, once — the agent picks it up on its
   next heartbeat). Rate `1000000` = 1.0×, same as clearnet:

   ```sh
   curl -H "Authorization: Bearer $ADMIN_TOKEN" -XPOST $URL/admin/services \
     -d '{"key":"http","name":"HTTP proxy","port":8080,"rate_ppm":1000000}'
   curl -H "Authorization: Bearer $ADMIN_TOKEN" $URL/admin/services   # verify
   ```

2. **Run the HTTP proxy** (exit host). It binds `EXIT_FIPS_ADDR:8080` only and
   forwards to Dante over loopback:

   ```sh
   cd deploy
   docker compose -f docker-compose.yaml --profile http up -d httpproxy
   ```

3. **Gate + meter the port** (exit host): uncomment `http 8080` in
   `deploy/services.conf`, then re-render:

   ```sh
   sudo ./up.sh reload      # re-render nftables from services.conf; nft -c validates
   sudo nft list table inet fips_exit | grep 8080   # confirm the port is gated
   ```

To disable, reverse all three: comment the `services.conf` line +
`sudo ./up.sh reload`, `docker compose --profile http down`, and disable the
catalog row (`POST /admin/services {"key":"http",…,"enabled":false}`).

## Verifying

Point a client at the HTTP proxy (note: an **authorized** fips client, run from a
separate peer, not the exit host):

```sh
# HTTPS via CONNECT — exits as the node's public IP, DNS resolved server-side.
curl -x http://$EXIT_FIPS_ADDR:8080 https://ifconfig.co

# Plaintext via absolute-form GET.
curl -x http://$EXIT_FIPS_ADDR:8080 http://ifconfig.co

# An UNAUTHORIZED client gets the captive 302 on plain HTTP, and a clean refusal
# on HTTPS (CONNECT) — exactly the captive behaviour of the SOCKS ports.
curl -x http://$EXIT_FIPS_ADDR:8080 http://example.com   # -> 302 to the portal
```

Then confirm the balance drained under the `http` service on the dashboard's
**Usage by service** table (or the DB), decrementing the same package as the
SOCKS ports.
