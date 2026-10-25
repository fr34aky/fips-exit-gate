# Agent ↔ Backend API contract (v1)

The exit-agent (one per exit node) is the only consumer of this API. It keeps
the node's nftables `@authorized` set in sync with the backend and reports
usage counters. Transport: HTTPS, JSON. The portal/user API is separate and
out of scope here.

## Authentication

- Each node has an Ed25519 keypair generated at install time.
- **Enrollment:** an admin creates a one-time enroll token in the backend.
  `POST /v1/nodes/enroll { enroll_token, node_pubkey, name }` →
  `{ node_id, auth_token }`. The backend stores only a hash of `auth_token`;
  the node pubkey is retained for future request-signing if needed.
- All subsequent requests: `Authorization: Bearer <auth_token>` over TLS.
  Token rotation = re-enroll with a fresh admin token.

## Endpoints

### `GET /v1/nodes/{node_id}/authz?rev={n}&wait={seconds}[&full=1]`

Long-poll sync of the authorized-address set.

- `rev=0` (or missing): immediate **full** response:
  `{ "rev": 412, "full": true, "addresses": [ { "addr": "fd10:...", "account": "a_01H..." } ], "force": false }`
- `full=1`: the full set **right now**, even when the backend's revision is
  still 0 (where plain `rev=0` would long-poll to a `204`). The agent sends it
  on every forced reconcile so stale kernel entries are cleared on a fresh
  backend too.
- `rev=n` with `wait`: blocks up to `wait` (max 55 s); returns `204` if
  unchanged, otherwise a **delta**:
  `{ "rev": 413, "add": [ { "addr": "...", "account": "..." } ], "del": [ "fd54:..." ] }`
  The backend wakes parked long-polls on Postgres `NOTIFY` from the recompute
  (with a slow poll as backstop), so a grant reaches nodes within milliseconds.
- If the backend cannot produce a delta from `n` (compaction), it replies
  with a full set (`"full": true`). Agent applies atomically per response.
- Revisions are **monotonic in commit order** (the recompute holds a
  transaction-scoped advisory lock), so a cursor that only ever asks for
  `rev > n` never skips a change.
- `force` (full responses): the agent refuses a full set that would revoke
  more than `FIPS_AGENT_MASS_REVOKE_MIN` (50) addresses *and* more than half of
  its live set, as a guard against an empty/truncated backend set (DB restore,
  wrong backend URL) cutting every paying user off at once. `force: true`
  (backend `AUTHZ_ALLOW_MASS_REVOKE=1`) or agent `FIPS_AGENT_ALLOW_MASS_REVOKE=1`
  overrides. A refused startup reconcile falls back to delta syncing from the
  persisted cursor, which still carries genuine revocations.
- The agent additionally forces a full refresh periodically
  (`FIPS_AGENT_FULL_SYNC_S`, default 5 min) as a safety net, and on demand when
  a heartbeat reports set drift (see below), so an out-of-band kernel-set flush
  self-heals without a revision change.
- Deletes are filtered against the live kernel set before being sent to nft:
  an address removed by an inline usage-ack revoke legitimately reappears as a
  `del` in the next delta, and nft would otherwise reject the whole batch.
- The set is service-agnostic: an authorized address may use every egress
  service on the node (shared balance); only metering is per-service.

### `POST /v1/nodes/{node_id}/usage`

Batched byte-counter deltas, default every 30 s.

```json
{
  "report_id": "01J9...",          // ULID, idempotency key
  "counter_epoch": "boot-7f3a",    // changes when counters reset (reboot/flush)
  "window_end": "2026-08-08T12:00:30Z",
  "samples": [ { "service": "clearnet", "addr": "fd10:...", "bytes": 778777 } ]
}
```

Samples are keyed by (service, addr); `bytes` is the metered total for that
client on that service in the window (both directions — the nftables `acct`
element sums them). The backend weights it with the service's `rate_ppm` when
decrementing the shared balance. Direction (rx/tx) split is a possible later
refinement and is not needed for billing.

Response: `{ "ack": "01J9...", "revoke": [ "fd10:..." ] }` — `revoke` lists
addresses to remove from the set *immediately* (quota just exhausted),
without waiting for the next authz delta. Duplicate `report_id` → `200` with
same ack, no double-counting. Samples are deltas since the last acked report;
on `counter_epoch` change the backend treats counters as reset.

### `POST /v1/nodes/{node_id}/heartbeat` (every `FIPS_AGENT_HEARTBEAT_S`, default 60 s)

`{ "version": "...", "authz_rev": 413, "set_size": 1234, "set_hash": "9f2c…" }` →

```json
{
  "config": {
    "usage_interval_s": 30,
    "grace_minutes": 240,
    "services": [
      { "key": "clearnet", "port": 1080 },
      { "key": "tor", "port": 1081 }
    ]
  },
  "resync": false
}
```

`set_hash` is the `pkg/authzhash` fingerprint of the live kernel set (sorted
members, SHA-256, 128 bits hex). `resync` is `true` when the node reports
`authz_rev` equal to the backend's current revision yet a `set_hash` that
differs from the fingerprint of `authz_current` — i.e. the node's kernel set
drifted out-of-band (an `nft` flush / table reload) and its revision cursor
can't detect it, including the same-size-different-members case a count would
miss. Agents that send no hash are compared by `set_size`; `set_size: -1`
means the agent could not read its set and is never treated as drift. The
agent responds by forcing a full reconcile. As a backstop, the agent also
forces a periodic full reconcile on its own, so drift self-heals even if a
heartbeat is missed.

The `services` list is the node's egress catalog, used by the agent to label
per-port counters with service keys in usage reports (the nftables gate itself
is rendered on the node from `deploy/services.conf`; keep the two in sync).
The heartbeat also lets the backend tune agent behavior (`usage_interval_s`,
`grace_minutes`) without redeploys and detect stuck nodes.

The backend additionally recomputes the authorized set on a timer
(`EXPIRY_SWEEP_S`, default 60 s), so a time pass that lapses while its account
is idle is revoked without waiting for an unrelated event.

## Failure semantics

- **Backend unreachable:** agent keeps the last-known authorized set
  (fail-open for already-paying users, still fail-closed for unknowns) for at
  most `grace_minutes` (default 240); after that it freezes new grants and
  keeps buffered usage reports on disk for later delivery (bounded, oldest
  dropped first). Captive daemon needs no backend and keeps working.
- **Revocation latency target:** ≤ 60 s from quota exhaustion
  (30 s usage interval + inline `revoke` in the ack).
- **Versioning:** path-versioned (`/v1`); only additive JSON changes within
  a version.

## Error format

`{ "error": { "code": "invalid_token", "message": "..." } }` with proper
HTTP status. Agent backoff: exponential from 1 s with ±20 % jitter, cap 60 s.
