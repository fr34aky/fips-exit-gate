# Deploying a fips-exit node (Phase 1 MVP)

Phase 1 is a single exit node with a **static** authorized set (a file), the
clearnet Dante service, the captive daemon, and unbound. No backend/agent yet
(that's Phase 2).

## Prerequisites

- A host already joined to fips, with the fips TUN interface up (e.g. `fips0`)
  and the fips **mesh firewall enabled** (required — see `docs/threat-model.md`).
- Docker + compose, and `nft` on the host.
- The node's own fips address (`EXIT_FIPS_ADDR`) and public egress interface.

## Bring-up

```sh
cd deploy
cp .env.example .env && edit .env         # set FIPS_IF, EXIT_FIPS_ADDR, etc.
set -a; . ./.env; set +a

# Authorize a client: derive its address from its npub and add it.
go run ../cmd/fips-derive npub1... >> allowlist.txt

sudo -E ./up.sh up                        # renders+validates+loads nftables, starts stack
```

`up.sh` runs `nft -c -f` before loading, so a malformed ruleset fails safely
without touching the live firewall. To change the allowlist or service list
later, edit the file(s) and `sudo -E ./up.sh reload`.

> **Note:** the nftables ruleset is rendered from `services.conf` — this is the
> modularity seam. Adding the Tor service (Phase 4b) is one line in
> `services.conf` plus a compose service; the gate, captive redirect, and
> counters are generated for every listed port automatically.

## Verifying milestone M1

From an **authorized** fips client (its address is in `allowlist.txt`):

```sh
# Clearnet egress, server-side DNS (--socks5-hostname = resolve on the proxy):
curl --socks5-hostname [EXIT_FIPS_ADDR]:1080 https://ifconfig.co        # -> exit's public IP
curl --socks5-hostname [EXIT_FIPS_ADDR]:1080 -6 https://ifconfig.co     # AAAA target works too
# fips must NOT be reachable through the proxy:
curl --socks5-hostname [EXIT_FIPS_ADDR]:1080 http://something.fips      # -> fails (blocked)
```

From an **unauthorized** fips client (address not in the list):

```sh
curl -sD- --socks5-hostname [EXIT_FIPS_ADDR]:1080 http://example.com    # -> HTTP 302 to the portal
curl --socks5-hostname [EXIT_FIPS_ADDR]:1080 https://example.com        # -> clean failure (no redirect)
```

The 302 `Location` carries `?t=<signed-token>&dest=<host>`; the portal verifies
the token (same secret) to greet the visitor with their status.

Native fips traffic (`.fips`, other fd00::/8 peers) must be **unaffected**
throughout — the gate only touches traffic to `EXIT_FIPS_ADDR` on service ports.

## Known limitation / validation caveat

The rendered nftables ruleset is syntax-checked with `nft -c` at load time on
the host. It could not be kernel-validated in the development sandbox (no
CAP_NET_ADMIN), so the **first** `up.sh up` on a real host is also the first
true validation — watch for `nft` errors there.
