-- WireGuard whole-device service ("wg"): a UDP endpoint on each exit, gated
-- and metered by fips source address like the SOCKS ports. Each client device
-- is a WireGuard peer issued to a whitelist npub; the agent configures peers on
-- the node from wg_peers, and nodes announce their own public key via the
-- heartbeat.
ALTER TABLE exit_nodes
    ADD COLUMN wg_pubkey  text,
    ADD COLUMN wg_endpoint text,          -- "<npub>.fips:51820" as clients should dial it
    ADD COLUMN wg_seen_at  timestamptz;

CREATE TABLE wg_peers (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    npub        text NOT NULL,            -- the device identity (whitelist npub) the peer is issued to
    fips_addr   inet NOT NULL,            -- derived: the OUTER source that must be authorized
    pubkey      text NOT NULL UNIQUE,     -- client X25519 public key, base64
    idx         integer NOT NULL UNIQUE,  -- allocation slot: ip4 = pool4 + idx, ip6 = pool6::idx
    label       text,
    created_by  text,                     -- session npub (audit)
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX wg_peers_addr ON wg_peers (fips_addr);
-- Round-robin allocation cursor so freed slots are not reused immediately.
CREATE SEQUENCE wg_peer_alloc;
