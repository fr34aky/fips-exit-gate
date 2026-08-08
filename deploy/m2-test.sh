#!/bin/sh
# M2 validation: prove the exit-agent reconciles the nftables `authorized` set
# from the backend and reports per-service usage read from the `acct` counters.
#
# Run on the exit host as root (drives nftables):  sudo sh deploy/m2-test.sh
# Prereqs: the gate table `inet fips_exit` is loaded (M1), and the prebuilt
# binaries /tmp/fips-agent and /tmp/fake-backend exist.
set -eu

NFT=/usr/sbin/nft
TABLE="inet fips_exit"
CLIENT=fd91:8fb5:5778:f352:7ee2:1fdb:d6ab:868f
AGENT=/tmp/fips-agent
BACKEND=/tmp/fake-backend

hr() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
    hr "cleanup"
    kill "${AG:-}" "${FB:-}" 2>/dev/null || true
    echo "agent + backend stopped. authorized set left as-is (see below)."
    echo "To restore the M1 static authorization: sudo nft -f /tmp/fips-exit-gate.nft"
}
trap cleanup EXIT INT TERM

# Fresh start.
pkill -f "$BACKEND" 2>/dev/null || true
pkill -f "$AGENT" 2>/dev/null || true
rm -rf /tmp/fips-agent-state
$NFT list table "$TABLE" >/dev/null 2>&1 || { echo "table $TABLE not loaded; run M1 first"; exit 1; }

hr "0. start clean: flush authorized set (so we can watch the agent fill it)"
$NFT flush set "$TABLE" authorized
$NFT list set "$TABLE" authorized

hr "1. start fake-backend, pre-grant the client"
"$BACKEND" :8080 >/tmp/fake-backend.log 2>&1 &
FB=$!
sleep 1
curl -s -XPOST localhost:8080/admin/grant -d "$CLIENT"

hr "2. start agent (enrolls, then owns the authorized set)"
FIPS_AGENT_BACKEND_URL=http://localhost:8080 \
FIPS_AGENT_ENROLL_TOKEN=dev \
FIPS_AGENT_TABLE="$TABLE" \
FIPS_AGENT_NFT="$NFT" \
FIPS_AGENT_STATE_DIR=/tmp/fips-agent-state \
"$AGENT" >/tmp/agent.log 2>&1 &
AG=$!
sleep 5
echo "--- agent log ---"; cat /tmp/agent.log

hr "3. authorized set after sync — expect the agent ADDED $CLIENT"
$NFT list set "$TABLE" authorized

hr "4. wait one usage cycle, then read usage the agent reported"
echo "(uses the residual acct counter from M1 — no new traffic needed)"
sleep 7
echo "--- acct set (source of truth) ---"; $NFT list set "$TABLE" acct
echo "--- /admin/usage (what the agent reported to the backend) ---"
curl -s localhost:8080/admin/usage; echo

hr "5. revoke via backend admin — expect the agent REMOVES $CLIENT"
curl -s -XPOST localhost:8080/admin/revoke -d "$CLIENT"
sleep 5
$NFT list set "$TABLE" authorized
echo "--- agent log tail ---"; tail -n 8 /tmp/agent.log
