# exit-agent (Phase 2)

The agent turns a Phase 1 exit node from a **static** allowlist into one driven
by the backend. It:

- reconciles the nftables `authorized` set with the backend (long-poll delta
  sync + periodic full refresh);
- reads the per-`(addr, service)` `acct` counters, computes deltas since the
  last baseline, and reports **rate-weightable** per-service usage;
- applies inline `revoke` from a usage ack immediately, so quota cutoff lands
  within one usage interval (target ≤ 60 s);
- survives backend outages: keeps the last-known set (fail-open) for a bounded
  grace window, buffering usage to disk; optionally fails closed after grace.

It shells out to `nft` (present on Ubuntu and OpenWrt) and is otherwise
stdlib-only. Config is via env (see `deploy/systemd/agent.env.example`).

## Phase 1 static vs Phase 2 agent

Both manage the same `authorized` set — **run one, not both**. In agent mode
leave `allowlist.txt` empty; the agent takes over the set. Load the nftables
ruleset with `up.sh` first either way (the agent fills the set, it doesn't
create the table).

## State

`FIPS_AGENT_STATE_DIR` (default `/var/lib/fips-exit-agent`) holds
`identity.json` (node id, auth token, Ed25519 seed — mode 0600) and
`runtime.json` (last authz rev, counter baselines, buffered usage). Baselines
advance every tick and usage is buffered durably, so a crash neither
double-counts nor loses bytes.

## Verifying milestone M2 (with the fake backend)

The real backend is Phase 3; `cmd/fake-backend` stands in so the mechanics can
be demonstrated on a host that has `nft` and a loaded ruleset.

```sh
# 1. Load the ruleset (creates the table + empty authorized set).
cd deploy && sudo -E ./up.sh up

# 2. Run the fake backend.
go run ./cmd/fake-backend :8080 &

# 3. Run the agent against it (host binary; needs CAP_NET_ADMIN for nft).
sudo FIPS_AGENT_BACKEND_URL=http://localhost:8080 \
     FIPS_AGENT_ENROLL_TOKEN=dev \
     FIPS_AGENT_TABLE="inet fips_exit" \
     go run ./agent

# 4. Grant a client and watch it appear in the kernel set within seconds:
curl -XPOST localhost:8080/admin/grant -d fd10:93b2:8586:6046:e42d:c089:3228:ccff
sudo nft list set inet fips_exit authorized      # -> address present

# 5. Generate traffic through the proxy, then read accounting:
curl localhost:8080/admin/usage                  # -> per-service bytes for the client

# 6. Revoke and confirm prompt cutoff (inline on the next usage ack, plus the
#    authz delta):
curl -XPOST localhost:8080/admin/revoke -d fd10:93b2:8586:6046:e42d:c089:3228:ccff
sudo nft list set inet fips_exit authorized      # -> address gone
```

M2 is met when granting/revoking in the backend flips kernel access within
seconds and the client's traffic shows up in the usage dump.

## Tests

`go test ./agent/...` covers the delta math (including counter resets), authz
full/delta reconciliation, inline revocation + acct GC, the outage/grace
fail-closed path, durable buffering across delivery failure, the HTTP client
round-trips, and parsing real `nft -j` JSON for both sets.
