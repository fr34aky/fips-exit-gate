-- fips-exit backend schema (see docs/data-model.md).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Modular egress services (clearnet, tor, ...).
CREATE TABLE services (
    id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key      text    NOT NULL UNIQUE,
    name     text    NOT NULL,
    port     integer NOT NULL UNIQUE,
    rate_ppm bigint  NOT NULL DEFAULT 1000000,   -- 1e6 = 1.0x; balance -= bytes*rate_ppm/1e6
    enabled  boolean NOT NULL DEFAULT true
);

CREATE TABLE exit_nodes (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    node_pubkey     text NOT NULL,
    auth_token_hash text NOT NULL,
    enrolled_at     timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz,
    version         text
);

-- One-time enrollment tokens (admin-issued).
CREATE TABLE enroll_tokens (
    token_hash text PRIMARY KEY,
    note       text,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz,
    node_id    uuid REFERENCES exit_nodes(id)
);

-- An account is a nostr identity (the owner).
CREATE TABLE accounts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    npub       text NOT NULL UNIQUE,
    fips_addr  inet NOT NULL UNIQUE,          -- derived from npub
    status     text NOT NULL DEFAULT 'active',-- active | suspended
    created_at timestamptz NOT NULL DEFAULT now()
);

-- npubs allowed to consume an account's packages (owner + whitelisted guests).
CREATE TABLE whitelist_entries (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    npub       text NOT NULL,
    fips_addr  inet NOT NULL,                 -- derived
    role       text NOT NULL DEFAULT 'guest', -- owner | guest
    enabled    boolean NOT NULL DEFAULT true,
    label      text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, npub)
);
-- An address is active on at most one account => deterministic source->account.
CREATE UNIQUE INDEX whitelist_active_addr ON whitelist_entries (fips_addr) WHERE enabled;

-- Catalog (admin-managed). Payments (Phase 4) create purchases -> entitlements;
-- for M3 the admin credits entitlements directly.
CREATE TABLE package_types (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          text    NOT NULL,           -- volume | time
    name          text    NOT NULL,
    volume_bytes  bigint,                      -- volume kind only
    validity_days integer NOT NULL,
    price_msat    bigint  NOT NULL DEFAULT 0,  -- reference price (Lightning msat)
    active        boolean NOT NULL DEFAULT true
);

CREATE TABLE purchases (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id        uuid NOT NULL REFERENCES accounts(id),
    package_type_id   uuid NOT NULL REFERENCES package_types(id),
    btcpay_invoice_id text UNIQUE,             -- idempotency anchor for crediting
    status            text NOT NULL DEFAULT 'pending', -- pending|settled|expired|invalid
    created_at        timestamptz NOT NULL DEFAULT now(),
    settled_at        timestamptz
);

-- What actually authorizes traffic.
CREATE TABLE entitlements (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    purchase_id  uuid UNIQUE REFERENCES purchases(id),
    kind         text NOT NULL,               -- volume | time
    volume_bytes bigint,                       -- total, volume kind
    volume_used  bigint NOT NULL DEFAULT 0,    -- rate-weighted bytes consumed
    starts_at    timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX entitlements_account ON entitlements (account_id);

-- Idempotency ledger: one row per agent usage report.
CREATE TABLE usage_reports (
    id            text PRIMARY KEY,            -- report_id (ULID) from the agent
    node_id       uuid NOT NULL REFERENCES exit_nodes(id),
    counter_epoch text,
    window_end    timestamptz,
    received_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE usage_samples (
    id         bigserial PRIMARY KEY,
    report_id  text NOT NULL REFERENCES usage_reports(id) ON DELETE CASCADE,
    service_id uuid REFERENCES services(id),
    fips_addr  inet NOT NULL,
    account_id uuid REFERENCES accounts(id),   -- resolved at ingest; null if unknown
    bytes      bigint NOT NULL                 -- metered total; weighted = bytes*rate_ppm/1e6
);

-- Materialized global authorized set + append-only revision log driving deltas.
CREATE TABLE authz_current (
    fips_addr  inet PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE authz_revisions (
    rev        bigserial PRIMARY KEY,
    op         text NOT NULL,                  -- add | del
    fips_addr  inet NOT NULL,
    account_id uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
