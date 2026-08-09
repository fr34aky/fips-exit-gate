-- Optional availability window for time-limited catalog entries (e.g. promos).
-- NULL = always available. The customer catalog hides entries past this instant;
-- existing purchases/entitlements are unaffected.
ALTER TABLE package_types ADD COLUMN available_until timestamptz;
