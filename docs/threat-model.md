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
- Service ports are reachable **only via the fips TUN interface**: the rendered
  ruleset (`svc_in`) resets service-port traffic that arrives from loopback or
  any other interface, so neither the exit host itself nor anything routed to
  it can reach the gated ports around the gate (the SOCKS listeners bind the
  fips address, not the interface, so the firewall is what enforces this). The
  dispatcher's loopback upstreams (Dante `127.0.0.1:1090`, Tor's loopback
  SocksPort) stay reachable to local processes by design; a local process is
  the operator's own.
- A port a compose service may bind on the fips address (`CONNECTIVITY_PORT`,
  `TOR_PORT`) that is **missing from `services.conf`** is refused from fips by
  the ruleset, so a service started before its catalog line is unreachable,
  never open-but-unmetered.
- Authorization is re-checked on **every packet**, not only when a connection
  opens. The captive redirect is a NAT decision (once per flow), but
  `svc_in`/`svc_out` reset any service-port flow whose source has left the
  `authorized` set, so revocation and quota exhaustion cut live tunnels
  immediately instead of only blocking new ones. The dispatcher additionally
  bounds every tunnel (`DISPATCH_IDLE_TIMEOUT_S`, `DISPATCH_MAX_LIFETIME_S`).

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
  timeout, connection cap; optionally a per-source concurrent-connection
  ceiling in nftables (`MAX_CONNS_PER_SRC`).
- It never proxies: it only parses a SOCKS5 CONNECT + sniffs for HTTP, then
  answers a static 302 (with a signed, short-lived context token identifying
  the source address) or closes. No payload logging.

## 4. Payments

- Webhook forgery: verify the BTCPay HMAC **and** re-read the invoice via the
  Greenfield API before crediting (`InvoiceSettled` grants only if the API
  also says `Settled`; a provider error makes BTCPay retry).
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
- Nostr challenge login: server-generated HMAC nonce with a 120 s expiry,
  **single-use** (an in-memory used-challenge cache refuses a replayed signed
  event), signature verified against the claimed npub (NIP-07/NIP-55/NIP-46),
  and audience-bound: when the event carries a `u` tag (the login page always
  adds one) it must name this portal, so a signature obtained by a phishing
  page cannot be relayed here.
- Sessions: stateless HMAC-signed cookies (7-day), HttpOnly, SameSite=Lax.
  State-changing requests are protected against cross-site requests by the
  `Sec-Fetch-Site`/`Origin` checks of Go's `CrossOriginProtection` (every
  browser since 2023 sends them) rather than per-form tokens; the Cashu
  NUT-18 receiver is exempt by design (wallets POST cross-origin).
- Purchases: `POST /buy` is rate-limited per source address (5/min) and an
  account may hold at most 3 unpaid invoices at once; `GET /packages` never
  creates rows.
- Admin API and metrics live on a separate loopback listener
  (`LISTEN_ADMIN`), never on the fips-facing port.
- Whitelist abuse: a guest entry is an **invitation** and does nothing until
  the invited npub accepts it from its own dashboard (or the inviter is
  demonstrably browsing from that very address). Before this, anyone could
  attach any npub to their account; the one-active-row-per-address rule then
  parked the victim's own owner row, so a package the victim paid for never
  authorized them. Invitations require an active package, are capped per
  account (`MAX_GUESTS_PER_ACCOUNT`) and rate-limited per inviter. Buying a
  package on one's own account always re-activates one's own owner row.

## 6. Privacy & logging

- No destination logging in production: Dante logs errors only; usage ledger
  stores per-account byte totals per time window, never destinations or DNS
  names.
- unbound: no query logging; cache only in memory.
- Retention: raw usage samples (one per client, service and 30 s window) are
  rolled up into per-day, per-account totals after `RETENTION_DAYS` (90) and
  deleted with their reports; the authz revision log is compacted after
  `REVISION_RETENTION_DAYS` (30). Captive daemon logs counters only.
- Data held per user: npub(s), derived addresses, package/payment references
  (BTCPay invoice IDs — no fiat identity), byte totals.

## 7. Agent ↔ backend channel

- Bearer token stored hashed server-side; the agent refuses plain `http://`
  to anything but loopback, a fips address or a `.fips` name (the mesh
  encrypts and authenticates end to end), so the token never crosses the
  Internet unencrypted unless `FIPS_AGENT_ALLOW_INSECURE=1` is set
  deliberately; tokens are per-node so one compromised node can't affect
  others' sets.
- A compromised exit node can: see the authorized set (npub-derived
  addresses of paying users) and fabricate usage (drain quotas). Mitigations:
  usage plausibility checks against node bandwidth, alerting on outliers;
  nodes are operator-owned in Phase 1 (federation is out of scope).

## 8. Availability

- Backend outage: agents keep last-known set (bounded grace), captive path
  is fully local → paying users unaffected short-term, unknown users still
  get the portal redirect (portal availability permitting).
- Captive/proxy floods: optional per-source concurrent-connection ceiling
  (`MAX_CONNS_PER_SRC`), dispatcher and captive connection caps, Dante worker
  cap; monitoring alerts on connection-table growth. Portal: purchase rate
  limit and open-invoice cap per account.
