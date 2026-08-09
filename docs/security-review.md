# Security review (Phase 5e)

An adversarial audit of the auth surfaces, payment lifecycle, SOCKS gate/egress
policy, and SQL layer, ahead of public launch. This records the findings and how
each was resolved. Overall the crypto hygiene held up: admin/metrics bearer
checks are constant-time, every HMAC path (`session`, `challenge`, captive
token, BTCPay) uses `hmac.Equal`, all SQL is pgx-parameterized, payment
settlement is idempotent, transparent-fips login can only ever assert the
caller's own derived identity (no `X-Forwarded-For` trust), and the `fipsaddr`
derivation/bech32 handling is correct.

## Fixed

| # | Sev | Issue | Fix |
|---|-----|-------|-----|
| H1 | high | With payments enabled, an empty `BTCPAY_WEBHOOK_SECRET` would make webhooks forgeable → free access. | Backend refuses to start payments without the secret; `VerifyWebhook` returns false for an empty secret. Test added. |
| H2b | high | Dante's `internal:` bound the whole fips interface; a second global address on it would be reachable **ungated**. | Pin `internal:` to the exact `EXIT_FIPS_ADDR` (the address the gate protects). |
| M1 | med | SSRF: missing egress ranges; IPv4-mapped IPv6 concern. | Added blocks for `0.0.0.0/8`, `100.64.0.0/10` (CGNAT), `198.18.0.0/15`, `fc00::/8` (other ULA half). Dante **refuses** IPv4-mapped IPv6, normalizing to plain IPv4 — so mapped literals are covered by the IPv4 rules, not a bypass. |
| M2 | med | Login accepted any event kind and fell back to event **content** for the challenge → an ordinary signed note could authenticate (cross-app signing). | Require the auth event kind (`27235`) and take the challenge only from a `["challenge", …]` tag — no content fallback. Tests added. |
| L1 | low | `AuthNode` compared token hashes with `!=`. | Use `subtle.ConstantTimeCompare`. |
| L2 | low | A hostile/buggy node's usage report could overflow the `uint64→int64` conversion / weighted-bytes multiply. | Clamp per-sample bytes (`1<<40`) and compute weighted consumption divide-first (overflow-safe). Test added. |
| M3 | med | `/metrics` open when `METRICS_TOKEN` unset (exposes node names/counts). | Startup warning when unset; documented to gate by token or bind to a private interface. |

## Accepted / documented residuals

- **Source-address authenticity (H2, the linchpin).** The whole access boundary
  assumes the fips mesh prevents a node from emitting packets with another
  node's fd00::/8 source on the exit's ingress interface. This is external to
  this repo and is the **top item to validate before launch** — see
  [threat-model.md §1](threat-model.md). The nftables gate + credential-free
  Dante are safe only under it.
- **Challenge replay within its 120 s window (M2).** Challenges are stateless
  HMACs, so a captured `(challenge, signed-event)` pair is replayable until it
  expires. Capturing it requires MITM/client compromise, and the kind+tag
  binding closes the practical social-engineering path. A single-use server-side
  nonce cache would remove the residual — future work.
- **Semi-trusted exit nodes (L2).** An enrolled node can misreport usage for any
  authorized address (billing drain/DoS). Exit nodes are operator-run
  infrastructure; the byte clamp bounds the blast radius. Cross-node attribution
  limits would need node↔address binding — future work.
- **Cloud metadata defense-in-depth (M1).** Dante blocks `169.254.0.0/16`
  already; if the exit ever runs on a cloud VM, also add a **host-level** egress
  block to the metadata IP (`169.254.169.254`, and `fd00:ec2::254` is inside the
  blocked `fd00::/8`) — see [hardening.md](hardening.md#cloud-metadata).

Every Dante/nftables change here was validated against the real binaries
(`sockd -V`, `nft -c`), and each code fix has a regression test.
