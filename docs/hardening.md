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
