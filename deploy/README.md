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

## Phase 2: dynamic authorization (exit-agent)

Instead of the static `allowlist.txt`, run the exit-agent (`--profile agent` in
compose, or the systemd unit in `systemd/`). It owns the `authorized` set from
the backend and reports per-service usage read from the `acct` counters. Run
one or the other, not both. See `../agent/README.md` for M2 verification against
the bundled `cmd/fake-backend`.

## Validation status

M1 was validated end-to-end on two real fips nodes (2026-08-08): ruleset loads
on a live 6.8 kernel; unauthorized clients get the captive `302` (HTTP) / clean
failure (HTTPS); authorized clients egress with server-side DNS and the exit's
public IP; fips (`fd00::/8`) destinations are refused through the proxy even
for authorized clients (SOCKS error 2); and per-`(client, service)` `acct`
counters increment on real traffic.

`up.sh` still runs `nft -c -f` before loading, so a malformed ruleset fails
safely.

> Gotcha learned during bring-up: the gate only fires on traffic ingressing via
> `fips0`. Testing from the exit host itself reaches the exit's own fips address
> over loopback (`iifname != fips0`), bypassing the gate — always test from a
> separate fips peer.
