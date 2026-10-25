-- Usage attribution falls back to "the account that last held this address"
-- (ORDER BY rev DESC per address). authz_revisions is append-only and was only
-- indexed by rev; a burst of buffered reports after an outage would scan the
-- whole log once per sample.
CREATE INDEX IF NOT EXISTS authz_revisions_addr_rev ON authz_revisions (fips_addr, rev DESC);
