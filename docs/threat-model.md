# Threat model

## 1. Source-address authenticity (the core assumption)

Authorization trusts the client's fips source IPv6, which is derived from the
npub. This holds only as far as fips itself prevents source spoofing inside
the mesh.

- fips ships a mesh firewall (`docs/how-to/enable-mesh-firewall.md` in the
  fips repo) — **required on the exit node's fips daemon**.
- Residual risk: an on-path or malicious mesh node emitting packets with a
  victim's source address. For TCP (all SOCKS traffic is TCP) the attacker
  must also receive the return path, which mesh routing sends toward the
  victim's real node — so blind spoofing cannot complete a handshake, but an
  attacker who *controls routing* toward the victim could steal quota.
- Mitigations: per-account usage anomaly alerts (sudden multi-node
  consumption); optional future hardening: periodic in-band re-auth
  (signed nostr challenge) for high-volume sessions.
- The exit binds SOCKS strictly to the fips TUN interface; packets from any
  other interface never reach the proxy or the authorized set.

## 2. Exit abuse (outbound)

- Egress policy: block SMTP (25), and destinations in loopback, RFC 1918,
  link-local, cloud metadata (169.254.169.254 / fd00:ec2::254), and fd00::/8
  (no re-entry into fips; also keeps metering internet-only).
- `bind`/`udpassociate` disabled; connect-only proxy.
- Per-address connection-rate and bandwidth ceilings (nftables limits / tc)
  to keep one user from degrading the node or triggering upstream abuse
  reports.
- Operational: abuse-contact address, log policy that can demonstrate *which
  npub* (not which destination) used the node at a given time — see §6.

## 3. Captive daemon (pre-auth attack surface)

Unauthenticated peers speak first bytes to it by design.

- Memory-safe Go, no external deps; hard limits: max header bytes, 10 s idle
  timeout, connection cap, per-source rate limit in nftables.
- It never proxies: it only parses a SOCKS5 CONNECT + sniffs for HTTP, then
  answers a static 302 (with a signed, short-lived context token identifying
  the source address) or closes. No payload logging.

## 4. Payments

- Webhook forgery: verify BTCPay HMAC **and** re-fetch invoice state via the
  Greenfield API before crediting.
- Double-credit: crediting transaction is idempotent on `btcpay_invoice_id`
  (unique constraint), webhook replays are no-ops.
- Partial/late payments: only `settled` credits; late settlement after
  invoice expiry goes to manual review, not auto-credit.
- Price manipulation: package price is fixed server-side at invoice creation;
  the client never supplies amounts.

## 5. Portal authentication

- Transparent fips login is **on by default**; it authenticates a client only
  when the request arrives directly from an fd00::/8 source (the same
  source-address trust the exit gate already relies on) and the client's npub
  derives to that source. It never trusts `X-Forwarded-For`, so it can't be
  spoofed at the app layer — its strength reduces to the mesh's L3 source
  integrity (§1). Disable it (`PORTAL_TRUST_FIPS_SOURCE=0`) only behind a
  reverse proxy that masks the source, where every client would otherwise
  appear as the proxy.
- Nostr challenge login: server-generated nonce, single-use, short expiry;
  signature verified against the claimed npub (NIP-07/NIP-55/NIP-46).
- Sessions: 256-bit random IDs, HttpOnly/SameSite cookies, CSRF tokens on
  state-changing requests (whitelist edits, purchases).
- Whitelist abuse: adding an npub requires no consent from that npub (it only
  *grants* paid access), but the unique-active-address constraint prevents
  hijacking an npub already active on another account.

## 6. Privacy & logging

- No destination logging in production: Dante logs errors only; usage ledger
  stores per-account byte totals per time window, never destinations or DNS
  names.
- unbound: no query logging; cache only in memory.
- Retention: usage samples aggregated after 90 days, raw reports dropped;
  captive daemon logs counters only.
- Data held per user: npub(s), derived addresses, package/payment references
  (BTCPay invoice IDs — no fiat identity), byte totals.

## 7. Agent ↔ backend channel

- Bearer token stored hashed server-side; TLS required; tokens are per-node
  so one compromised node can't affect others' sets.
- A compromised exit node can: see the authorized set (npub-derived
  addresses of paying users) and fabricate usage (drain quotas). Mitigations:
  usage plausibility checks against node bandwidth, alerting on outliers;
  nodes are operator-owned in Phase 1 (federation is out of scope).

## 8. Availability

- Backend outage: agents keep last-known set (bounded grace), captive path
  is fully local → paying users unaffected short-term, unknown users still
  get the portal redirect (portal availability permitting).
- Captive/proxy floods: nftables per-source new-connection rate limits on
  port 1080; Dante worker cap; monitoring alerts on connection-table growth.
