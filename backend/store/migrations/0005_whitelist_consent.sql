-- Guest whitelist entries need the guest's consent before they take effect.
--
-- Before: anyone could add any npub as a guest, and the partial unique index
-- (one ENABLED row per address) then made that address "taken": when the real
-- owner created their own account their owner row was created disabled, and a
-- package they paid for never authorized them. Now a guest row starts
-- `pending` and only counts (for authorization, source->account resolution and
-- the one-active-account-per-address rule) once the invited npub accepts it.
ALTER TABLE whitelist_entries ADD COLUMN pending boolean NOT NULL DEFAULT false;

DROP INDEX IF EXISTS whitelist_active_addr;
CREATE UNIQUE INDEX whitelist_active_addr ON whitelist_entries (fips_addr) WHERE enabled AND NOT pending;
