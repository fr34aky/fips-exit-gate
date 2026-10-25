# Hardening

Production hardening for an internet-facing exit: egress abuse controls,
per-account ceilings, and logging/privacy. Pair this with
[Observability](observability.md) (metrics + alerts) and the
[Maintenance](maintenance.md) runbooks.

## Egress abuse policy (Dante)

The exit is **connect-only** and **internet-egress-only**, enforced in
`exit/sockd.conf`:

- **Command policy:** `bind` and `udpassociate` are blocked — only `CONNECT`.
- **Destination policy:** loopback (`127.0.0.0/8`, `::1/128`), RFC1918
  (`10/8`, `172.16/12`, `192.168/16`), link-local + cloud metadata
  (`169.254.0.0/16`, `fe80::/10`), and **all of fips** (`fd00::/8`) are blocked.
  This guarantees the proxy can't be turned back on the mesh or on cloud
  metadata endpoints, and that every metered byte is genuine internet traffic.
- **Abuse ports:** outbound mail is blocked by default (**SMTP 25**, **SMTPS/
  submission 465, 587**) so the exit can't be used as a spam relay — the top
  abuse and IP-blocklisting risk for an open exit.

Adjust in `exit/sockd.conf` (bind-mounted, no rebuild needed). To block more
ports (e.g. IRC), add a rule of the same shape and validate before deploying:

```conf
socks block { from: 0/0 to: 0/0 port = 6667 log: error }
```

```sh
# Validate the config against the real Dante binary before reloading:
FIPS_IF=lo EXTERNAL_IF=lo CLEARNET_PORT=1080 envsubst < exit/sockd.conf > /tmp/s.conf
docker run --rm --entrypoint sockd -v /tmp/s.conf:/tmp/s.conf:ro fips-exit/clearnet:dev -V -f /tmp/s.conf
```

Rules are first-match, top-to-bottom; keep the blocks above the final
`socks pass … command: connect`.

### Cloud metadata

`sockd.conf` blocks `169.254.0.0/16` (covering `169.254.169.254`) and all of
`fd00::/8` (covering the IPv6 IMDS `fd00:ec2::254`), and Dante refuses
IPv4-mapped IPv6 so `::ffff:169.254.169.254` can't slip past. If the exit runs
on a cloud VM, add a **host-level** egress block as defence-in-depth so nothing
on the box (not just the proxy) can reach the metadata endpoint:

```sh
nft add rule inet filter output ip daddr 169.254.169.254 drop
```

## Per-account ceilings

### Concurrent connections (nftables)

Set `MAX_CONNS_PER_SRC` (default `0` = off) to cap the number of **simultaneous
connections per source address** (per npub/device) on the service ports. The
render script emits a filter chain that drops over-limit new connections from
authorized sources (`ct count`), so one client can't exhaust the exit's sockets:

```sh
# deploy/.env
MAX_CONNS_PER_SRC=256      # generous; stops abuse without breaking browsers
./up.sh reload             # nft -c validates before loading
```

This is per **source address**, not per account — each of an account's
whitelisted npubs gets its own ceiling (nftables has no notion of account
membership). It counts connections, not bandwidth.

### Bandwidth (tc)

Byte-rate caps are a node-level traffic-control concern, applied with `tc` on the
fips interface — outside the rendered ruleset because they depend on the node's
link and desired policy. A per-source HTB example, egress toward clients:

```sh
IF=fips0
tc qdisc add dev $IF root handle 1: htb default 10
tc class add dev $IF parent 1: classid 1:1 htb rate 100mbit
tc class add dev $IF parent 1:1 classid 1:10 htb rate 20mbit ceil 50mbit   # per-client default
# Add u32/flower filters to map each authorized fips /128 to its own class.
```

Volume (not rate) is already metered and enforced by the quota system: usage
draws down the package balance and exhaustion revokes the address within a usage
interval (see [maintenance](maintenance.md#revoke-or-suspend-access)).

### Revocation cuts live connections

The gate is enforced twice: a NAT rule decides once per connection whether a
new flow reaches the service or the captive daemon, and filter rules
(`svc_in`/`svc_out` in the rendered ruleset) re-check `authorized` membership on
**every packet** and reset a flow whose source is no longer in the set. So when
a package runs out or a guest is disabled, the client's open tunnels die on
their next packet; they cannot keep using a connection opened while they were
still authorized. A revoked tunnel that stays silent is cleaned up too: the
dispatcher's listener sends TCP keepalives (Go's 15 s default), the keepalive
toward a de-authorized address is reset by `svc_out`, and the dispatcher sees
`ECONNRESET` and closes both sides within about 30 s. On top of that the
dispatcher bounds every tunnel by `DISPATCH_IDLE_TIMEOUT_S` (default 2 h, so
long-idle but legitimate sessions such as IMAP IDLE or SSH survive) and,
opt-in, `DISPATCH_MAX_LIFETIME_S`.

The same `svc_in` chain resets service-port traffic that did not arrive on the
fips interface, which is why testing the proxy from the exit host itself gets
"connection refused" (see [Troubleshooting](troubleshooting.md)). Ports a
compose service may bind that are missing from `services.conf` are refused
from fips as well (`GUARD_PORTS` in `up.sh`).

`deploy/test/run-nft-gate-test.sh` exercises all of this against a real kernel
in a throwaway container (redirect, accept, loopback drop, live reset, acct).

## Logging & privacy

The design records **what** was used, not **where** it went.

- **No destination logging.** Dante logs errors only (`log: error` on every
  rule, `logoutput: stderr`), so successful connections and their destinations
  are never written. Policy violations (blocked ports/destinations, failures)
  are logged without payload. Don't switch to `log: connect`/`disconnect` in
  production.
- **Accounting is byte totals.** The usage ledger stores per-`(account, service,
  source address)` byte counts — never destination hosts. Quota is enforced on
  those totals.
- **Bounded retention.** The exit/captive/agent containers cap their logs
  (`json-file`, 10 MB × 3 via the `x-logging` anchor in
  `deploy/docker-compose.yaml`); adjust to taste. Don't ship Dante logs to
  long-term storage.
- **Backend logs** contain operational data (npubs — which are public keys —
  invoice ids, errors), not browsing activity. Keep them access-controlled and
  rotate them.

For the full trust/retention model see [threat-model.md](threat-model.md).
