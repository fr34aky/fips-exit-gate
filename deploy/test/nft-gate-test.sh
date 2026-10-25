#!/bin/sh
# Integration test for the rendered nftables gate. Runs as root inside a
# throwaway network namespace owner (see run-nft-gate-test.sh for the Docker
# wrapper) and proves, against a real kernel:
#
#   1. an unauthorized fips source on a service port is redirected to captive;
#   2. an authorized source reaches the service;
#   3. service ports are NOT reachable from loopback/other interfaces;
#   4. removing a source from `authorized` resets its LIVE connection on the
#      next packet (per-packet enforcement, not just new-connection gating);
#   5. `acct` counts the authorized client's bytes on (addr, port);
#   6. the ruleset renders and validates with MAX_CONNS_PER_SRC set;
#   7. svc_out resets the SERVICE side when it keeps sending to a revoked client;
#   8. a guarded port missing from services.conf is refused from fips.
#
# Topology: veth pair; this namespace plays the exit (fips0 = fd00::1, the
# listeners), namespace "client" plays two fips peers on the far end
# (fd00::2 authorized, fd00::3 unauthorized).
set -u

here="$(cd "$(dirname "$0")" && pwd)"
RENDER="${RENDER:-$here/../render-nftables.sh}"
work="$(mktemp -d)"
fail=0
pass() { echo "PASS: $*"; }
failed() { echo "FAIL: $*"; fail=1; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 2; }; }
need nft; need ip; need socat

cleanup() {
    kill $(jobs -p) 2>/dev/null
    nft delete table inet fips_exit 2>/dev/null
    ip netns del client 2>/dev/null
    ip link del fips0 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# --- topology -----------------------------------------------------------------
ip netns add client
ip link add fips0 type veth peer name cl0
ip link set cl0 netns client
ip addr add fd00::1/64 dev fips0 nodad
ip link set fips0 up
ip -n client link set lo up
ip -n client addr add fd00::2/64 dev cl0 nodad
ip -n client addr add fd00::3/64 dev cl0 nodad
ip -n client link set cl0 up

# --- ruleset -------------------------------------------------------------------
printf 'clearnet 1080\ntor 1081\n' > "$work/services.conf"
: > "$work/allowlist.txt"
render() {
    FIPS_IF=fips0 EXIT_FIPS_ADDR=fd00::1 CAPTIVE_PORT=1088 \
    SERVICES_FILE="$work/services.conf" ALLOWLIST_FILE="$work/allowlist.txt" \
    MAX_CONNS_PER_SRC="${1:-0}" GUARD_PORTS="1080 1081 3128" sh "$RENDER"
}
# packets counter of the svc_in / svc_out rule whose text matches $2.
rule_packets() {
    nft list chain inet fips_exit "$1" | grep -F -- "$2" | sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -1
}
render > "$work/gate.nft" || { echo "render failed" >&2; exit 2; }
nft -c -f "$work/gate.nft" || { echo "nft -c rejected the ruleset" >&2; cat "$work/gate.nft" >&2; exit 2; }
nft -f "$work/gate.nft"

# --- listeners (the "services") ------------------------------------------------
# service on the exit's fips address: banner + echo; captive on [::]: banner only.
socat TCP6-LISTEN:1080,bind=[fd00::1],fork,reuseaddr SYSTEM:'echo SERVICE; cat' &
socat TCP6-LISTEN:1088,fork,reuseaddr SYSTEM:'echo CAPTIVE' &
# :1081 "ticker": a service that keeps SENDING (for the svc_out test).
socat TCP6-LISTEN:1081,bind=[fd00::1],fork,reuseaddr SYSTEM:'echo TICKER; while sleep 0.2; do echo tick || exit; done' 2>/dev/null &
# :3128 bound but NOT in services.conf (guarded port).
socat TCP6-LISTEN:3128,bind=[fd00::1],fork,reuseaddr SYSTEM:'echo UNGATED' &
sleep 0.5

# cl SRC PORT: connect from the client namespace with the given source, print
# whatever the far end says within a short window.
cl() {
    ip netns exec client timeout 5 socat -T2 -t1 - "TCP6:[fd00::1]:$2,bind=[$1]" </dev/null 2>/dev/null
}

# 1. unauthorized -> captive, on every service port (1081 has no listener; the
#    redirect alone must land it on the captive daemon).
out="$(cl fd00::3 1080)"; [ "$out" = "CAPTIVE" ] && pass "unauthorized :1080 -> captive" || failed "unauthorized :1080 got '$out'"
out="$(cl fd00::3 1081)"; [ "$out" = "CAPTIVE" ] && pass "unauthorized :1081 -> captive" || failed "unauthorized :1081 got '$out'"

# 2. authorized -> service.
nft add element inet fips_exit authorized '{ fd00::2 }'
out="$(cl fd00::2 1080)"; [ "$out" = "SERVICE" ] && pass "authorized :1080 -> service" || failed "authorized :1080 got '$out'"

# 3. host-local (loopback) access to the service port is refused, even though
#    the listener is right there: no banner AND the loopback rule fired.
before="$(rule_packets svc_in 'iifname != "fips0"')"
out="$(timeout 4 socat -T2 -t1 - 'TCP6:[fd00::1]:1080' </dev/null 2>/dev/null)"
after="$(rule_packets svc_in 'iifname != "fips0"')"
if [ -z "$out" ] && [ "${after:-0}" -gt "${before:-0}" ]; then pass "loopback access to :1080 refused (rule fired)"; else failed "loopback access: out='$out' counter $before->$after"; fi

# 4. live revocation: hold a connection open, remove the source, next packet
#    must be reset and never reach the service.
mkfifo "$work/in"
ip netns exec client socat -T20 - "TCP6:[fd00::1]:1080,bind=[fd00::2]" < "$work/in" > "$work/out" 2>"$work/err" &
longpid=$!
exec 3>"$work/in"
echo hello >&3; sleep 0.5
grep -q '^hello$' "$work/out" && pass "live tunnel echoes before revocation" || failed "no echo before revocation: $(cat "$work/out")"
nft delete element inet fips_exit authorized '{ fd00::2 }'
echo after-revoke >&3; sleep 1
if kill -0 "$longpid" 2>/dev/null; then
    failed "connection survived revocation"
    kill "$longpid" 2>/dev/null
else
    pass "live tunnel reset on first packet after revocation"
fi
grep -q 'after-revoke' "$work/out" && failed "post-revocation data was echoed" || pass "post-revocation data never reached the service"
exec 3>&-
resets="$(rule_packets svc_in '!= @authorized')"
[ "${resets:-0}" -ge 1 ] && pass "svc_in per-packet reject rule fired ($resets)" || failed "svc_in per-packet reject rule did not fire"

# 5. accounting on (addr, port) for the authorized client.
bytes="$(nft -j list set inet fips_exit acct | tr '{}' '\n\n' | grep -A3 'fd00::2' | grep -o '"bytes": *[0-9]*' | sed 's/[^0-9]//g' | head -1)"
[ "${bytes:-0}" -gt 0 ] && pass "acct counted $bytes bytes for fd00::2 . 1080" || failed "acct has no bytes for fd00::2 . 1080: $(nft list set inet fips_exit acct)"

# 7. svc_out: the service keeps sending to a client that gets revoked; the
#    OUTPUT-hook reset must fire and the service must stop getting through.
nft add element inet fips_exit authorized '{ fd00::2 }'
ip netns exec client socat -T20 - "TCP6:[fd00::1]:1081,bind=[fd00::2]" </dev/null > "$work/ticks" 2>/dev/null &
tickpid=$!
sleep 0.8
grep -q '^tick$' "$work/ticks" && pass "ticker service streams to the authorized client" || failed "no ticks received: $(cat "$work/ticks")"
nft delete element inet fips_exit authorized '{ fd00::2 }'
sleep 0.5
n1="$(wc -l < "$work/ticks")"; sleep 0.8; n2="$(wc -l < "$work/ticks")"
[ "$n1" = "$n2" ] && pass "no further ticks reach the revoked client" || failed "ticks kept arriving after revocation ($n1 -> $n2)"
outresets="$(rule_packets svc_out '!= @authorized')"
[ "${outresets:-0}" -ge 1 ] && pass "svc_out reset rule fired on service->client traffic ($outresets)" || failed "svc_out rule did not fire"
kill "$tickpid" 2>/dev/null

# 8. a guarded port that is not in services.conf is refused from fips, even
#    for an authorized source.
nft add element inet fips_exit authorized '{ fd00::2 }'
out="$(cl fd00::2 3128)"
guard="$(rule_packets svc_in 'not in services.conf')"
if [ -z "$out" ] && [ "${guard:-0}" -ge 1 ]; then pass "uncatalogued :3128 refused from fips (rule fired)"; else failed "uncatalogued port: out='$out' counter=$guard"; fi
nft delete element inet fips_exit authorized '{ fd00::2 }'

# 6. render variant with the connection ceiling validates.
render 4 > "$work/gate-limit.nft" && nft -c -f "$work/gate-limit.nft" && pass "ruleset with MAX_CONNS_PER_SRC validates" || failed "ruleset with MAX_CONNS_PER_SRC rejected"

[ "$fail" -eq 0 ] && echo "ALL PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
