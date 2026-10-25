# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
One version covers every component (agent, backend, captive, dispatch, exit
image, deploy). Each release's notes end with **Upgrade notes** when a
migration, an `up.sh reload` or an agent restart is involved.

Changes before this file existed are in the git history (Phase 0 through the
authz drift self-heal, August–October 2026).

## [Unreleased]

### Added

- **WireGuard whole-device exit service** (#14): a `wg` service in the catalog
  turns an exit into a WireGuard endpoint on its fips address, gated by the
  same `@authorized` set and metered through the same counters. Clients import
  one config from the portal (QR or file) and get a true default route for
  IPv4, IPv6 and UDP with no proxy settings; mesh traffic (`fd00::/8`) stays
  native. Server-side keygen, several devices per identity
  (`WG_MAX_PEERS_PER_ADDR`), inner pools `WG_POOL4`/`WG_POOL6`, host-side
  `wg-quick@wg0` with the agent mirroring the backend's peer table
  (`FIPS_AGENT_WG_IF`, `FIPS_AGENT_WG_ENDPOINT`). See `docs/wireguard.md`.
- **Whole-device client tunnel** (#12): `deploy/client/` ships a systemd
  service that routes an entire Linux client through the exit's SOCKS port
  with tun2socks, failing closed when the tunnel dies, with DNS-over-TLS via
  systemd-resolved. Nothing changes on the exit. See `docs/client-tunnel.md`.
- **Guest invitations need consent** (#11): adding an npub to an account
  creates a pending invitation that the invited identity accepts or declines
  from its own dashboard (auto-accepted when the inviter is browsing from that
  very address). Invitations require an active package and are capped
  (`MAX_GUESTS_PER_ACCOUNT`, default 5). `GET /admin/accounts/{npub}` answers
  "why can't this user get out?" in one call.
- **Health and readiness** (#16): `GET /healthz` (process up) and
  `GET /readyz` (database reachable, migrations applied) on the public
  listener; structured logging with `LOG_FORMAT=json|text` and `LOG_LEVEL`;
  agent metrics for the last counter collection, bytes collected and
  collection errors.
- **Control-plane knobs** (#10): `EXPIRY_SWEEP_S` recomputes the authorized set
  on a timer so lapsed time passes are revoked while an account is idle;
  `AUTHZ_ALLOW_MASS_REVOKE` overrides the agent's mass-revoke guard; agent
  pacing via `FIPS_AGENT_FULL_SYNC_S`, `FIPS_AGENT_HEARTBEAT_S`,
  `FIPS_AGENT_LONGPOLL_S`, `FIPS_AGENT_MASS_REVOKE_MIN`.
- **Retention** (#15): raw usage samples older than `RETENTION_DAYS` (90) are
  rolled up into `usage_daily` and deleted; the authz revision log is compacted
  after `REVISION_RETENTION_DAYS` (30). Dashboard totals are unchanged.
- Container integration tests that run against a real kernel:
  `deploy/test/run-nft-gate-test.sh` (gate, per-packet reject, accounting, UDP
  and WireGuard policy) and `deploy/client/test/run-tunnel-test.sh`.
- `CONTRIBUTING.md` (workflow, required checks, security-boundary rules,
  releasing and versioning), `PR-REVIEW.md` (the 13-criteria review checklist
  every PR goes through) and this changelog.
- CI on every pull request (`.github/workflows/ci.yml`: gofmt, vet, tests with
  a Postgres service, shell syntax, and the container integration tests when
  present) and tag-driven releases (`.github/workflows/release.yml`).
- `pkg/version`: the build's version from the git tag (`-ldflags -X`, or the
  Dockerfiles' `VERSION` build argument), falling back to the VCS revision Go
  embeds. The backend logs it at start. `VERSION` at the repo root is
  substituted by `git archive`.

### Changed

- **Authorization is enforced on every packet** (#9). New `svc_in`/`svc_out`
  filter chains reset TCP flows whose source left `@authorized`, so revoking an
  address ends its open connections at once instead of only blocking new ones.
  Ports not listed in `services.conf` are refused outright (`GUARD_PORTS`), and
  the service ports are no longer reachable from other interfaces.
- `up.sh reload` carries the live `authorized` set across the reload instead
  of emptying it until the agent's next full sync.
- The dispatcher closes relays idle for `DISPATCH_IDLE_TIMEOUT_S` (default
  7200, measured on real inactivity) and optionally after
  `DISPATCH_MAX_LIFETIME_S` (default 0 = unlimited). It no longer needs
  `NET_ADMIN`.
- The admin API and `/metrics` moved to a separate loopback listener,
  `LISTEN_ADMIN` (default `127.0.0.1:8081`); the public port serves only the
  portal, the agent API and payment webhooks. The monitoring stack scrapes
  `backend:8081`.
- Agent full reconciles default to every 300 s (`FIPS_AGENT_FULL_SYNC_S`, `0`
  disables, floor 30 s) and are no longer the only thing hiding delta-log gaps:
  recomputes are serialized, so the delta log is gap-free, and agents are
  woken by Postgres `NOTIFY` instead of a 200 ms poll.
- Drift detection compares a hash of the kernel set with `authz_current`
  (`set_hash` in the heartbeat), not just its size.
- The agent refuses a full reconcile that would revoke more than
  `FIPS_AGENT_MASS_REVOKE_MIN` addresses and more than half of its live set
  unless the backend marks the response `force` (see
  `AUTHZ_ALLOW_MASS_REVOKE`).
- The agent accepts `https://` backend URLs, or plain `http://` only to
  loopback, a fips address or a `.fips` name (`FIPS_AGENT_ALLOW_INSECURE=1`
  lifts this).
- Backend start requires `CAPTIVE_TOKEN_SECRET` (an empty secret let anyone
  forge captive tokens).
- `GET /packages` no longer creates accounts; creation happens on purchase.
- The systemd agent unit runs as the `fips-agent` user (sysusers file
  included) with `AmbientCapabilities=CAP_NET_ADMIN` and the usual sandboxing.
- Documentation was trued up: the threat model and hardening guide describe
  only controls that exist, and `backend/README.md` states the real
  transparent-login default.

### Fixed

- A revoked address could keep an open tunnel indefinitely and, because the
  counters matched `@authorized`, do so unmetered.
- Concurrent `RecomputeAuthz` calls could commit revisions out of order, so an
  agent's cursor permanently skipped a revision until the next full sync.
- A delete for an address already removed inline failed the whole nft batch
  and stalled the agent's cursor.
- Time-based entitlements only expired when some other write happened.
- Anyone could attach any npub as a guest; the unique-active-address rule then
  parked the victim's own owner row, so a package they paid for never
  authorized them. Buying a package now always re-activates one's own row.
- Usage reports that arrived after an address was revoked (buffered through an
  outage) were recorded without an account; they are now billed to the last
  holder.
- A corrupt `runtime.json` was fatal, and the fail-closed timer did not
  survive restarts; the agent now recovers, primes its counter baselines and
  persists the last successful sync.
- The `FipsExitUsageStalled` alert fired whenever customers were merely idle;
  it now watches the age of the last counter collection.
- A long-poll wake-up race in the backend and a revision cursor that could
  move backwards after a backend restore.

### Security

- Login challenges are single-use and audience-bound: a replayed signed event
  is refused, and the event's `u` tag must name this portal.
- State-changing portal requests are protected against cross-site requests by
  Go's `CrossOriginProtection` (`Sec-Fetch-Site`/`Origin`); the Cashu NUT-18
  receiver is exempt by design.
- `POST /buy` is rate-limited per identity and an account may hold at most 3
  unpaid invoices.
- BTCPay settlement webhooks are re-checked against the Greenfield API before
  crediting when the provider supports it.
- Captive-token verification is one shared package (`pkg/captivetoken`) used
  by the backend and the captive daemon.

### Upgrade notes

- **Migrations** `0005_usage_daily`, `0005_whitelist_consent`,
  `0006_authz_revisions_addr_index` and `0007_wireguard` apply automatically
  when the backend starts. Existing guest rows stay active (`pending`
  defaults to false).
- **Backend env:** set `CAPTIVE_TOKEN_SECRET` (start fails without it). If you
  reached `/admin` or `/metrics` on the public port, point your tooling at
  `LISTEN_ADMIN` (`127.0.0.1:8081` by default, or set it equal to `LISTEN` for
  the old single-port behaviour). New optional knobs are listed in
  `docs/configuration.md`.
- **Exit nodes:** run `up.sh reload` to load the new filter chains; the live
  set is preserved. `services.conf` keeps its two-column format (`proto`
  is optional and defaults to `tcp`). Agents must be restarted for the new
  heartbeat fields and knobs; an agent configured with a plain `http://`
  backend URL on a non-fips host needs `FIPS_AGENT_ALLOW_INSECURE=1` or, better,
  TLS. The agent container image now includes `wireguard-tools`.
- **Monitoring:** update Prometheus to scrape the backend on port 8081 and
  reload the alert rules (`deploy/monitoring/alerts.yml`).
- **WireGuard** is opt-in: add the `wg` service row and `services.conf` line,
  bring up `wg-quick@wg0`, set the agent's `FIPS_AGENT_WG_*` variables and
  allow UDP `WG_PORT` in the fips firewall. See `docs/wireguard.md`.

[Unreleased]: https://github.com/fr34aky/fips-exit-gate/commits/master
