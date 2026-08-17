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

### `GET /v1/nodes/{node_id}/authz?rev={n}&wait={seconds}`

Long-poll sync of the authorized-address set.

- `rev=0` (or missing): immediate **full** response:
  `{ "rev": 412, "full": true, "addresses": [ { "addr": "fd10:...", "account": "a_01H..." } ] }`
- `rev=n` with `wait`: blocks up to `wait` (max 55 s); returns `204` if
  unchanged, otherwise a **delta**:
  `{ "rev": 413, "add": [ { "addr": "...", "account": "..." } ], "del": [ "fd54:..." ] }`
- If the backend cannot produce a delta from `n` (compaction), it replies
  with a full set (`"full": true`). Agent applies atomically per response.
- The agent additionally forces a full refresh periodically (default 5 min) as
  a safety net, and on demand when a heartbeat reports set drift (see below), so
  an out-of-band kernel-set flush self-heals without a revision change.
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

### `POST /v1/nodes/{node_id}/heartbeat` (every 60 s)

`{ "version": "...", "authz_rev": 413, "set_size": 1234 }` →

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

`resync` is `true` when the node reports `authz_rev` equal to the backend's
current revision yet a `set_size` that disagrees with `authz_current` — i.e. the
node's kernel set drifted out-of-band (an `nft` flush / table reload) and its
revision cursor can't detect it. The agent responds by forcing a full reconcile.
As a backstop, the agent also forces a periodic full reconcile on its own, so
drift self-heals even if a heartbeat is missed.

The `services` list is the node's egress catalog: the agent renders the
nftables gate (authz check, captive redirect, per-service counters) from it,
so registering a new egress service requires no agent changes. This also
lets the backend tune agent behavior without redeploys and detect stuck
nodes.

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
HTTP status. Agent backoff: exponential with jitter, cap 60 s.
