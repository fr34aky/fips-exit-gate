# Data model (Postgres)

Conventions: ULID primary keys (`text`), `timestamptz` everywhere, npubs
stored in canonical bech32 lowercase, fips addresses as `inet` (always the
canonical derived address; derivation via `pkg/fipsaddr` at write time).

## Identity & access

```
accounts
  id            pk
  npub          text unique not null      -- the owner identity
  fips_addr     inet unique not null      -- derived from npub
  created_at, status (active|suspended)

whitelist_entries        -- npubs allowed to consume the account's packages
  id            pk
  account_id    fk -> accounts
  npub          text not null
  fips_addr     inet not null             -- derived
  role          owner|guest               -- owner row auto-created with account
  enabled       bool default true
  label         text                      -- user-facing note ("laptop", "alice")
  created_at
  unique (account_id, npub)
  unique (fips_addr) where enabled        -- an address may be active on at
                                          -- most ONE account at a time; this
                                          -- is what makes source-address →
                                          -- account resolution deterministic
```

If npub X is whitelisted by two accounts, only one entry may be enabled; the
portal surfaces the conflict and lets the second account enable it only after
the first disables it.

## Catalog & entitlements

```
package_types            -- the catalog (admin-managed)
  id            pk
  kind          volume|time
  name          text                      -- "50 GB / 90 days", "1 month pass"
  volume_bytes  bigint null               -- volume kind
  validity_days int not null              -- volume: expiry window; time: pass length
  price_eur_cents int not null            -- reference price; BTCPay converts
                                          -- to BTC/LN/XMR at invoice time
  active        bool

purchases                -- one per BTCPay invoice
  id            pk
  account_id    fk
  package_type_id fk
  btcpay_invoice_id text unique not null  -- idempotency anchor for crediting
  status        pending|settled|expired|invalid
  created_at, settled_at

entitlements             -- what actually authorizes traffic
  id            pk
  account_id    fk
  purchase_id   fk unique                 -- exactly one entitlement per purchase
  kind          volume|time
  volume_bytes  bigint null               -- total, for volume kind
  volume_used   bigint not null default 0
  starts_at, expires_at
  -- account is authorized iff EXISTS an entitlement with
  --   now() within [starts_at, expires_at] AND
  --   (kind = time OR volume_used < volume_bytes)
  -- consumption order: earliest expires_at first
```

## Egress services

```
services                 -- modular egress catalog (clearnet, tor, ...)
  id            pk
  key           text unique               -- "clearnet", "tor"
  name          text                      -- display name
  port          int unique not null       -- one port per service on every node
  rate_ppm      bigint not null           -- consumption rate, parts-per-million:
                                          -- 1_000_000 = 1.0x, 1_500_000 = 1.5x;
                                          -- balance -= bytes * rate_ppm / 1e6
  backend       text                      -- "dante" | "tor-socks" | ... (informational)
  enabled       bool
```

Adding an egress layer = one `services` row + running its SOCKS endpoint on
that port on the exit nodes. Authorization is account-level and shared across
services (one `@authorized` set); only metering and rates are per-service.

## Accounting & nodes

```
exit_nodes
  id            pk
  name          text
  node_pubkey   text                      -- Ed25519, from enrollment
  auth_token_hash text
  enrolled_at, last_seen, version

usage_reports            -- idempotency ledger, one row per agent report
  id            pk                        -- = report_id from the agent (ULID)
  node_id       fk
  counter_epoch text
  window_end    timestamptz
  received_at

usage_samples            -- per-address, per-service deltas, partitioned by month
  report_id     fk -> usage_reports
  service_id    fk -> services
  fips_addr     inet
  account_id    fk null                   -- resolved at ingest; null if unknown
  bytes         bigint                    -- metered total (both directions);
                                          -- weighted consumption =
                                          -- bytes * services.rate_ppm / 1e6

authz_revisions          -- append-only log driving the agent delta sync
  rev           bigserial pk
  op            add|del
  fips_addr     inet
  account_id    fk
  created_at
  -- compacted periodically; full set = view over accounts/whitelist/entitlements
```

## Portal sessions

```
sessions
  id            pk (random 256-bit)
  npub          text not null             -- acting identity
  account_id    fk null                   -- resolved account (owner or via whitelist)
  method        fips|nip07|nip55|nip46|manual
  created_at, expires_at
```

## Invariants worth enforcing in code

- Crediting is a single transaction keyed on `btcpay_invoice_id`
  (insert-or-ignore purchase settle + entitlement creation).
- `volume_used` accumulates **rate-weighted** bytes (`bytes *
  services.rate_ppm / 1e6`); updates and exhaustion checks happen in one
  statement at usage ingest; crossing the limit emits `del` to
  `authz_revisions` and the inline `revoke` in the usage ack.
- Whitelist changes and entitlement expiry both write `authz_revisions`;
  a periodic sweep expires time-based entitlements between traffic events.
