#!/bin/sh
# fips-exit-tunnel — route this whole device through a fips exit node with NO
# per-application proxy settings.
#
# How it works: tun2socks creates a TUN interface and turns every TCP flow that
# enters it into a SOCKS5 CONNECT to the exit's connectivity port over fips.
# Policy routing sends all Internet traffic into that TUN while fips itself
# (fd00::/8), your LAN, and the fips daemon's own uplink keep using the normal
# routing table.
#
# Fail-closed: the TUN is a PERSISTENT device created here, which tun2socks
# attaches to. If tun2socks dies the device, its route and the policy rules all
# stay: Internet traffic goes into a TUN nobody reads (black hole, connections
# time out) instead of leaking around the exit, while fips/LAN/bypassed traffic
# keeps working — which matters, because the reverse-path filter would drop
# replies to bypassed traffic if the tunnel table held no interface route at
# all. systemd restarts the service into the same device. Only an explicit
# `down` (what `systemctl stop` runs) removes the device and restores routing.
#
# DNS: the exit's SOCKS server is connect-only (no UDP), and tun2socks hands it
# IP addresses, so names must be resolved on the client THROUGH the tunnel.
# This script configures systemd-resolved to use DNS-over-TLS (TCP/853) on the
# TUN for everything except .fips, which stays with fips' own resolver.
#
# Requirements: Linux, root, iproute2, tun2socks (github.com/xjasonlyu/tun2socks,
# a single static binary), and systemd-resolved for the DNS step (or set
# DNS_MODE=skip and point your resolver at a DoT/DoH server yourself).
#
#   fips-exit-tunnel up      # bring the tunnel up (stays in the foreground)
#   fips-exit-tunnel down    # tear it down
#   DRY_RUN=1 fips-exit-tunnel up   # print what would be done
#
# Config comes from the environment (see fips-exit-tunnel.env.example).
set -eu

: "${EXIT_SOCKS:?EXIT_SOCKS is required, e.g. socks5://[fd00:...]:1080}"
: "${FIPS_IF:=fips0}"
: "${TUN_IF:=fipsexit0}"
: "${TUN_MTU:=1500}"
: "${TUN2SOCKS:=tun2socks}"
: "${TUN_ADDR4:=198.18.0.1/15}"          # benchmark range: never routed on the Internet
: "${TUN_ADDR6:=fc00:f1b5:ea17::2/64}"   # ULA outside fips' fd00::/8
: "${TABLE:=5180}"
: "${PRIO:=5180}"
: "${UPLINK_EXCLUDE:=}"    # space-separated IPs/CIDRs that must bypass the tunnel (fips peers' public endpoints)
: "${FIPS_UID:=}"          # if the fips daemon runs under its own uid, its traffic bypasses the tunnel
: "${DNS_MODE:=resolved}"  # resolved | skip
: "${DNS_SERVERS:=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net}"
: "${STATE_DIR:=/run/fips-exit-tunnel}"

run() {
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "+ $*"
    else
        "$@"
    fi
}

# Connected (on-link) prefixes of every interface except the TUN: LAN, docker
# bridges, VPNs you already have. They keep going direct. Kernel-installed
# connected routes are `proto kernel` in both families (IPv6 ones carry no
# "scope link" tag); host routes without a prefix length are skipped.
local_prefixes() {
    fam="$1"
    ip "-$fam" route show proto kernel 2>/dev/null \
        | awk -v tun="$TUN_IF" '$0 !~ ("dev " tun " ") && $1 ~ /\// && $1 != "default" {print $1}' | sort -u
}

rules_add() {
    # Idempotent: a restart after a crash finds our rules still in place (that
    # is the fail-closed guarantee). Refresh the exceptions, keep the catch-all.
    rules_del_exceptions
    # Exceptions first (lower pref wins).
    run ip -6 rule add pref $((PRIO - 3)) to fd00::/8 lookup main
    for fam in 4 6; do
        for p in $(local_prefixes "$fam"); do
            run ip "-$fam" rule add pref $((PRIO - 3)) to "$p" lookup main
        done
    done
    for x in $UPLINK_EXCLUDE; do
        case "$x" in *:*) fam=6 ;; *) fam=4 ;; esac
        run ip "-$fam" rule add pref $((PRIO - 2)) to "$x" lookup main
    done
    if [ -n "$FIPS_UID" ]; then
        run ip -4 rule add pref $((PRIO - 1)) uidrange "$FIPS_UID-$FIPS_UID" lookup main
        run ip -6 rule add pref $((PRIO - 1)) uidrange "$FIPS_UID-$FIPS_UID" lookup main
    fi
    # Everything else: the tunnel table (added once; survives tun2socks dying).
    for fam in 4 6; do
        if ! ip "-$fam" rule show pref "$PRIO" 2>/dev/null | grep -q "lookup $TABLE"; then
            run ip "-$fam" rule add pref "$PRIO" lookup "$TABLE"
        fi
    done
}

del_pref() {
    fam="$1"; pref="$2"
    # Delete repeatedly: several rules may share a pref.
    while ip "-$fam" rule show pref "$pref" 2>/dev/null | grep -q .; do
        run ip "-$fam" rule del pref "$pref" || break
        if [ "${DRY_RUN:-0}" = "1" ]; then
            break
        fi
    done
    return 0
}

rules_del_exceptions() {
    for fam in 4 6; do
        for pref in $((PRIO - 3)) $((PRIO - 2)) $((PRIO - 1)); do
            del_pref "$fam" "$pref"
        done
    done
}

rules_del() {
    rules_del_exceptions
    for fam in 4 6; do
        del_pref "$fam" "$PRIO"
        run ip "-$fam" route flush table "$TABLE" 2>/dev/null || true
    done
}

# Reverse-path filtering must be LOOSE while the policy rules are in place.
# Strict rp_filter validates an incoming reply by looking up a route back to
# its source without any socket uid, so for traffic that bypasses the tunnel
# (the fips daemon via FIPS_UID, UPLINK_EXCLUDE peers) the reverse lookup lands
# in the tunnel table, the interface doesn't match, and the kernel silently
# drops the reply. Loose mode (2) accepts a source reachable via any interface.
# The previous value is saved and restored by `down`.
rpfilter_loose() {
    f=/proc/sys/net/ipv4/conf/all/rp_filter
    [ -r "$f" ] || return 0
    cur="$(cat "$f")"
    [ -f "$STATE_DIR/rp_filter.prev" ] || echo "$cur" > "$STATE_DIR/rp_filter.prev"
    if [ "$cur" != "2" ] && [ "$cur" != "0" ]; then
        run sysctl -q -w net.ipv4.conf.all.rp_filter=2 || \
            echo "fips-exit-tunnel: WARNING: could not set rp_filter=2 (read-only sysctl?); replies to traffic that bypasses the tunnel (FIPS_UID/UPLINK_EXCLUDE) may be dropped" >&2
    fi
}

rpfilter_restore() {
    [ -f "$STATE_DIR/rp_filter.prev" ] || return 0
    run sysctl -q -w "net.ipv4.conf.all.rp_filter=$(cat "$STATE_DIR/rp_filter.prev")" || true
    rm -f "$STATE_DIR/rp_filter.prev"
}

dns_up() {
    [ "$DNS_MODE" = "resolved" ] || return 0
    if ! command -v resolvectl >/dev/null 2>&1; then
        echo "fips-exit-tunnel: resolvectl not found; DNS not configured. Use a DNS-over-TLS/HTTPS resolver" >&2
        echo "fips-exit-tunnel: (plain UDP DNS cannot cross the exit) or set DNS_MODE=skip to silence this." >&2
        return 0
    fi
    # shellcheck disable=SC2086
    run resolvectl dns "$TUN_IF" $DNS_SERVERS
    run resolvectl dnsovertls "$TUN_IF" yes
    run resolvectl domain "$TUN_IF" '~.'          # default route for all names...
    run resolvectl default-route "$TUN_IF" yes    # ...except more specific ones (~fips on fips0)
}

cleanup() {
    trap - INT TERM EXIT
    echo "fips-exit-tunnel: tearing down (routing restored)"
    rules_del
    rpfilter_restore
    if [ -f "$STATE_DIR/tun2socks.pid" ]; then
        run kill "$(cat "$STATE_DIR/tun2socks.pid")" 2>/dev/null || true
        rm -f "$STATE_DIR/tun2socks.pid"
    fi
    run ip link del "$TUN_IF" 2>/dev/null || true
}

up() {
    command -v "$TUN2SOCKS" >/dev/null 2>&1 || [ "${DRY_RUN:-0}" = "1" ] || {
        echo "fips-exit-tunnel: $TUN2SOCKS not found (install github.com/xjasonlyu/tun2socks)" >&2; exit 1; }
    mkdir -p "$STATE_DIR"
    # During setup any failure tears down; once up, only INT/TERM (an explicit
    # stop) does — see the fail-closed note at the top.
    trap cleanup INT TERM EXIT

    # 1. A persistent TUN (survives tun2socks), then tun2socks attached to it,
    #    talking to the exit over the fips interface.
    if ! ip link show "$TUN_IF" >/dev/null 2>&1; then
        run ip tuntap add dev "$TUN_IF" mode tun
    fi
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "+ $TUN2SOCKS --device tun://$TUN_IF --proxy $EXIT_SOCKS --interface $FIPS_IF --mtu $TUN_MTU --loglevel warn &"
    else
        "$TUN2SOCKS" --device "tun://$TUN_IF" --proxy "$EXIT_SOCKS" --interface "$FIPS_IF" --mtu "$TUN_MTU" --loglevel warn &
        echo $! > "$STATE_DIR/tun2socks.pid"
        i=0
        while ! ip link show "$TUN_IF" >/dev/null 2>&1; do
            i=$((i + 1)); [ "$i" -lt 50 ] || { echo "fips-exit-tunnel: $TUN_IF never appeared" >&2; exit 1; }
            sleep 0.1
        done
    fi
    run ip addr replace "$TUN_ADDR4" dev "$TUN_IF"
    run ip -6 addr replace "$TUN_ADDR6" dev "$TUN_IF"
    run ip link set "$TUN_IF" up mtu "$TUN_MTU"

    # 2. Tunnel table: default via the (persistent) TUN, plus an unreachable
    #    fallback for the case where the device itself is gone.
    run ip -4 route replace default dev "$TUN_IF" table "$TABLE"
    run ip -6 route replace default dev "$TUN_IF" table "$TABLE"
    run ip -4 route replace unreachable default metric 4096 table "$TABLE"
    run ip -6 route replace unreachable default metric 4096 table "$TABLE"

    # 3. Policy: exceptions, then everything else into the tunnel table.
    rpfilter_loose
    rules_add

    # 4. DNS through the tunnel (TCP), .fips stays native.
    dns_up

    echo "fips-exit-tunnel: up — Internet via $EXIT_SOCKS over $FIPS_IF, fips/LAN direct"
    trap - EXIT
    if [ "${DRY_RUN:-0}" = "1" ]; then
        trap - INT TERM
        return 0
    fi
    # Stay in the foreground (systemd Type=simple). If tun2socks dies we exit
    # non-zero WITHOUT touching device, routes or rules: Internet traffic
    # black-holes in the persistent TUN rather than leaking, bypassed traffic
    # keeps flowing, and systemd's restart re-attaches. `down` restores routing.
    wait "$(cat "$STATE_DIR/tun2socks.pid")" || true
    rm -f "$STATE_DIR/tun2socks.pid"
    echo "fips-exit-tunnel: tun2socks exited; leaving routing FAIL-CLOSED (run 'fips-exit-tunnel down' to restore)" >&2
    exit 1
}

case "${1:-}" in
    up)   up ;;
    down) cleanup ;;
    *) echo "usage: $0 {up|down}" >&2; exit 2 ;;
esac
