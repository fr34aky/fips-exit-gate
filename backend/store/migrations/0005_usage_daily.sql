-- Retention: raw usage_samples (one row per client, service and 30 s window)
-- are an activity timeline per npub. After RETENTION_DAYS they are rolled up
-- into per-day totals here (what the dashboard and billing views need) and the
-- raw rows plus their reports are deleted. Samples that never resolved to an
-- account, or named a service key not in the catalog, are dropped at that
-- point (they are unbillable and not shown per service).
CREATE TABLE usage_daily (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    service_id uuid NOT NULL REFERENCES services(id),
    day        date NOT NULL,
    bytes      bigint NOT NULL,
    PRIMARY KEY (account_id, day, service_id)
);
