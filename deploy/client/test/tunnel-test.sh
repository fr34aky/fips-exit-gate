#!/bin/sh
# End-to-end test of fips-exit-tunnel.sh against a real SOCKS server, inside a
# throwaway container (see run-tunnel-test.sh): a local Dante plays the exit's
# connectivity port, tun2socks + policy routing send the container's Internet
# traffic into it, and we prove (1) the route really goes via the TUN, (2) an
# HTTP request reaches the Internet THROUGH Dante, (3) killing tun2socks fails
# closed (no leak via the normal default route), (4) teardown restores routing.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${SCRIPT:-$here/../fips-exit-tunnel.sh}"
T2S_VERSION="${T2S_VERSION:-v2.7.0}"
fail=0
pass() { echo "PASS: $*"; }
failed() { echo "FAIL: $*"; fail=1; }

# --- tun2socks binary ------------------------------------------------------
arch="$(uname -m)"
case "$arch" in
    x86_64) t2s_arch=amd64 ;;
    aarch64) t2s_arch=arm64 ;;
    *) echo "unsupported arch $arch" >&2; exit 2 ;;
esac
cd /tmp
if ! command -v tun2socks >/dev/null 2>&1; then
    curl -fsSL -o t2s.zip "https://github.com/xjasonlyu/tun2socks/releases/download/${T2S_VERSION}/tun2socks-linux-${t2s_arch}.zip" || { echo "download failed" >&2; exit 2; }
    unzip -oq t2s.zip && install -m755 "tun2socks-linux-${t2s_arch}" /usr/local/bin/tun2socks
fi

# --- a local "exit": Dante on 127.0.0.1:1080, connect-only, logging connects ---
ext_if="$(ip -4 route show default | awk '{print $5; exit}')"
cat > /tmp/sockd.conf <<CONF
logoutput: /tmp/sockd.log
internal: 127.0.0.1 port = 1080
external: $ext_if
clientmethod: none
socksmethod: none
user.notprivileged: nobody
client pass {
    from: 0/0 to: 0/0
    log: connect
}
socks block {
    from: 0/0 to: 0/0
    command: bind udpassociate
    log: error
}
socks pass {
    from: 0/0 to: 0/0
    command: connect
    log: connect
}
CONF
sockd -f /tmp/sockd.conf -D || { echo "sockd failed to start" >&2; exit 2; }
sleep 0.5

# --- bring the tunnel up --------------------------------------------------------
# Dante's outbound connections run as `nobody`; on a real client the same role
# (traffic that must bypass the tunnel) is the fips daemon's, hence FIPS_UID.
export EXIT_SOCKS=socks5://127.0.0.1:1080 FIPS_IF=lo TUN_IF=fipsexit0 DNS_MODE=skip STATE_DIR=/run/fips-exit-tunnel
export FIPS_UID="$(id -u nobody)"
sh "$SCRIPT" up > /tmp/tunnel.log 2>&1 &
tunpid=$!
i=0
until grep -q "fips-exit-tunnel: up" /tmp/tunnel.log 2>/dev/null; do
    i=$((i + 1)); [ "$i" -lt 100 ] || { echo "tunnel never came up:"; cat /tmp/tunnel.log; exit 2; }
    sleep 0.1
done
pass "tunnel came up"

# 1. Routing: Internet via the TUN, loopback/LAN direct.
if ip route get 1.1.1.1 | grep -q "dev fipsexit0"; then pass "1.1.1.1 routes via fipsexit0"; else failed "1.1.1.1 route: $(ip route get 1.1.1.1)"; fi
lan="$(ip -4 route show proto kernel | awk '$1 ~ /\// {print $1; exit}' | cut -d/ -f1)"
if [ -n "$lan" ] && ip route get "$lan" | grep -qv fipsexit0; then pass "connected prefix ($lan) stays direct"; else failed "LAN route via tunnel: $(ip route get "$lan" 2>&1)"; fi
if ip route show table 5180 | grep -q "^unreachable default"; then pass "unreachable fallback present"; else failed "no unreachable fallback: $(ip route show table 5180)"; fi

# 2. An HTTP request reaches the Internet, and Dante saw it.
code="$(curl -4 -s -o /dev/null -m 20 -w '%{http_code}' http://1.1.1.1/ 2>/dev/null || true)"
if [ -n "$code" ] && [ "$code" != "000" ]; then pass "HTTP through the tunnel (status $code)"; else failed "HTTP through the tunnel failed (code '$code'); tunnel log: $(tail -5 /tmp/tunnel.log)"; fi
sleep 0.3
if grep -q "connect" /tmp/sockd.log && grep -q "1.1.1.1" /tmp/sockd.log; then pass "Dante logged the proxied connection"; else failed "Dante saw no connection: $(tail -5 /tmp/sockd.log)"; fi

# 3. Fail closed: kill tun2socks; the script exits, device/route/rules stay,
#    Internet traffic black-holes (no leak), and the uid exception still works
#    (this is what keeps fips itself alive on a real client after a crash).
kill "$(cat /run/fips-exit-tunnel/tun2socks.pid)"
wait "$tunpid" 2>/dev/null && failed "script exited 0 after tun2socks died" || pass "script exited non-zero after tun2socks died"
if ip route get 1.1.1.1 2>&1 | grep -q "dev fipsexit0"; then pass "fail-closed: 1.1.1.1 still routed into the (dead) TUN"; else failed "leak: $(ip route get 1.1.1.1 2>&1)"; fi
code="$(curl -4 -s -o /dev/null -m 5 -w '%{http_code}' http://1.1.1.1/ 2>/dev/null || true)"
[ "$code" = "000" ] && pass "HTTP times out while the tunnel is down" || failed "HTTP succeeded while the tunnel was down (status $code)"
if ip rule show | grep -q "lookup 5180"; then pass "policy rules persist across the crash"; else failed "rules vanished on crash (would leak on restart gap)"; fi
code="$(su-exec nobody curl -4 -s -o /dev/null -m 10 -w '%{http_code}' http://1.1.1.1/ 2>/dev/null || true)"
[ -n "$code" ] && [ "$code" != "000" ] && pass "excluded uid still reaches the Internet directly (status $code)" || failed "excluded uid blocked (code '$code')"

# 3b. A restart (as systemd would do) comes back up into the existing rules.
sh "$SCRIPT" up > /tmp/tunnel2.log 2>&1 &
tunpid=$!
i=0
until grep -q "fips-exit-tunnel: up" /tmp/tunnel2.log 2>/dev/null; do
    i=$((i + 1)); [ "$i" -lt 100 ] || { failed "restart never came up: $(cat /tmp/tunnel2.log)"; break; }
    sleep 0.1
done
code="$(curl -4 -s -o /dev/null -m 20 -w '%{http_code}' http://1.1.1.1/ 2>/dev/null || true)"
[ -n "$code" ] && [ "$code" != "000" ] && pass "HTTP works again after restart (status $code)" || failed "HTTP after restart failed (code '$code'): $(tail -3 /tmp/tunnel2.log)"
n="$(ip -4 rule show pref 5180 | grep -c "lookup 5180")"
[ "$n" = "1" ] && pass "catch-all rule not duplicated on restart" || failed "catch-all rule count after restart: $n"

# 4. Explicit teardown (what systemctl stop does) restores normal routing.
kill -TERM "$tunpid"; wait "$tunpid" 2>/dev/null || true
sh "$SCRIPT" down >/dev/null 2>&1 || true
if ip rule show | grep -q "lookup 5180"; then failed "policy rules left behind: $(ip rule show)"; else pass "policy rules removed"; fi
if ip link show fipsexit0 >/dev/null 2>&1; then failed "persistent TUN left behind after down"; else pass "persistent TUN removed by down"; fi
if ip route get 1.1.1.1 | grep -q "dev $ext_if"; then pass "default route restored via $ext_if"; else failed "route after teardown: $(ip route get 1.1.1.1 2>&1)"; fi

[ "$fail" -eq 0 ] && echo "ALL PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
