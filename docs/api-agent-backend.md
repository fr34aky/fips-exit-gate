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
- The agent additionally does a full refresh every 15 min as safety net.

### `POST /v1/nodes/{node_id}/usage`

Batched byte-counter deltas, default every 30 s.

```json
{
  "report_id": "01J9...",          // ULID, idempotency key
  "counter_epoch": "boot-7f3a",    // changes when counters reset (reboot/flush)
  "window_end": "2026-08-08T12:00:30Z",
  "samples": [ { "addr": "fd10:...", "rx": 123456, "tx": 654321 } ]
}
```

Response: `{ "ack": "01J9...", "revoke": [ "fd10:..." ] }` — `revoke` lists
addresses to remove from the set *immediately* (quota just exhausted),
without waiting for the next authz delta. Duplicate `report_id` → `200` with
same ack, no double-counting. Samples are deltas since the last acked report;
on `counter_epoch` change the backend treats counters as reset.

### `POST /v1/nodes/{node_id}/heartbeat` (every 60 s)

`{ "version": "...", "authz_rev": 413, "set_size": 1234 }` →
`{ "config": { "usage_interval_s": 30, "grace_minutes": 240 } }` — lets the
backend tune agent behavior without redeploys and detect stuck nodes.

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
