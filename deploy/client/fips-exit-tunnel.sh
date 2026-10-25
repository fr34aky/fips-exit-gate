#!/bin/sh
# fips-exit-tunnel — route this whole device through a fips exit node with NO
# per-application proxy settings.
#
# How it works: tun2socks attaches to a TUN interface and turns every TCP flow
# that enters it into a SOCKS5 CONNECT to the exit's connectivity port over
# fips. Policy routing sends all Internet traffic into that TUN while fips
# itself (fd00::/8), your LAN, and the fips daemon's own uplink keep using the
# normal routing table.
#
# Fail-closed: the TUN is a PERSISTENT device created here, which tun2socks
# attaches to. If tun2socks dies the device, its route and the policy rules all
# stay: Internet traffic goes into a TUN nobody reads (black hole, connections
# time out) instead of leaking around the exit, while fips/LAN/bypassed traffic
# keeps working — which matters, because the reverse-path filter would drop
# replies to bypassed traffic if the tunnel table held no interface route at
# all. systemd restarts the service into the same device, and a setup failure
# during such a re-attach keeps the existing routing rather than tearing it
# down. Only an explicit stop (`systemctl stop`, or `down` outside systemd)
# removes the device and restores routing.
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
#   fips-exit-tunnel down    # tear it down (hands over to systemctl if the unit is active)
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

# --- policy rules ---------------------------------------------------------------
# Lowest pref first:
#   PRIO-3  lookup main, suppress_prefixlength 0
#           Every route in the main table EXCEPT a default route is honoured:
#           connected LAN prefixes (now and whenever they appear later: a new
#           WiFi, a docker bridge), fd00::/8 via the fips interface, static host
#           routes. Only traffic that would have taken the default route goes on
#           to the tunnel table. No snapshot of prefixes, nothing to go stale.
#   PRIO-2  UPLINK_EXCLUDE destinations -> main (peers reached via the default)
#   PRIO-1  FIPS_UID traffic -> main (the fips daemon's own transport)
#   PRIO    everything else -> the tunnel table
rules_add() {
    # Idempotent: a restart after a crash finds our rules still in place (that
    # is the fail-closed guarantee). Refresh the exceptions, keep the catch-all.
    rules_del_exceptions
    for fam in 4 6; do
        run ip "-$fam" rule add pref $((PRIO - 3)) lookup main suppress_prefixlength 0
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

# catchall_present: are we re-attaching into an existing fail-closed state?
catchall_present() {
    ip -4 rule show pref "$PRIO" 2>/dev/null | grep -q "lookup $TABLE"
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

# --- reverse-path filter ----------------------------------------------------------
# Must be LOOSE while the policy rules are in place. Strict rp_filter validates
# an incoming reply by looking up a route back to its source without any socket
# uid, so for traffic that bypasses the tunnel (the fips daemon via FIPS_UID,
# UPLINK_EXCLUDE peers) the reverse lookup lands in the tunnel table, the
# interface doesn't match, and the kernel silently drops the reply. Loose mode
# (2) accepts a source reachable via any interface. The previous value is saved
# and restored on stop. Note: 0 for "all" does NOT mean off — the kernel
# applies max(all, iface), so a per-interface 1 is still strict; only an
# explicit 2 is good enough.
rpfilter_loose() {
    f=/proc/sys/net/ipv4/conf/all/rp_filter
    [ -r "$f" ] || return 0
    cur="$(cat "$f")"
    [ -f "$STATE_DIR/rp_filter.prev" ] || echo "$cur" > "$STATE_DIR/rp_filter.prev"
    if [ "$cur" != "2" ]; then
        run sysctl -q -w net.ipv4.conf.all.rp_filter=2 || \
            echo "fips-exit-tunnel: WARNING: could not set rp_filter=2 (read-only sysctl?); replies to traffic that bypasses the tunnel (FIPS_UID/UPLINK_EXCLUDE) may be dropped" >&2
    fi
}

rpfilter_restore() {
    [ -f "$STATE_DIR/rp_filter.prev" ] || return 0
    run sysctl -q -w "net.ipv4.conf.all.rp_filter=$(cat "$STATE_DIR/rp_filter.prev")" || true
    rm -f "$STATE_DIR/rp_filter.prev"
}

# --- DNS --------------------------------------------------------------------------
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

# --- teardown paths -----------------------------------------------------------------
stop_tun2socks() {
    if [ -f "$STATE_DIR/tun2socks.pid" ]; then
        run kill "$(cat "$STATE_DIR/tun2socks.pid")" 2>/dev/null || true
        rm -f "$STATE_DIR/tun2socks.pid"
    fi
}

cleanup() {
    trap - INT TERM EXIT
    echo "fips-exit-tunnel: tearing down (routing restored)"
    rules_del
    rpfilter_restore
    stop_tun2socks
    run ip link del "$TUN_IF" 2>/dev/null || true
}

# on_stop: SIGTERM/SIGINT = an explicit stop (systemctl stop): tear down and
# exit cleanly so the unit ends in "inactive", not "failed".
on_stop() {
    cleanup
    exit 0
}

# on_setup_failure: a setup step failed. On a FIRST start nothing was protected
# yet, so tear everything down. On a re-attach (our catch-all rule already
# existed, i.e. the device was fail-closed from a previous run) leave routing
# exactly as it was — a persistent setup error in a restart loop must never
# turn fail-closed into an open default route.
on_setup_failure() {
    rc=$?
    trap - INT TERM EXIT
    if [ "${REATTACH:-0}" = "1" ]; then
        echo "fips-exit-tunnel: setup failed (exit $rc); keeping the existing FAIL-CLOSED routing" >&2
        stop_tun2socks
    else
        echo "fips-exit-tunnel: setup failed (exit $rc); nothing was protected yet, tearing down" >&2
        cleanup
    fi
    exit "$rc"
}

# down: restore normal routing. Under systemd the unit must be stopped (a
# plain down would kill tun2socks, make the unit exit 1, and Restart= would
# bring the tunnel straight back), so hand over to systemctl in that case.
down() {
    if [ -z "${INVOCATION_ID:-}" ] && command -v systemctl >/dev/null 2>&1 \
       && systemctl is-active --quiet fips-exit-tunnel 2>/dev/null; then
        echo "fips-exit-tunnel: managed by systemd; stopping the unit instead"
        exec systemctl stop fips-exit-tunnel
    fi
    cleanup
}

# --- up -----------------------------------------------------------------------------
up() {
    command -v "$TUN2SOCKS" >/dev/null 2>&1 || [ "${DRY_RUN:-0}" = "1" ] || {
        echo "fips-exit-tunnel: $TUN2SOCKS not found (install github.com/xjasonlyu/tun2socks)" >&2; exit 1; }
    mkdir -p "$STATE_DIR"
    if catchall_present; then
        REATTACH=1
        echo "fips-exit-tunnel: re-attaching into existing fail-closed routing"
    else
        REATTACH=0
    fi
    if [ -z "$FIPS_UID" ] && [ -z "$UPLINK_EXCLUDE" ]; then
        echo "fips-exit-tunnel: WARNING: neither FIPS_UID nor UPLINK_EXCLUDE is set. If this node reaches fips" >&2
        echo "fips-exit-tunnel: WARNING: over UDP/TCP (not raw Ethernet/WiFi/Bluetooth), its peer traffic will be" >&2
        echo "fips-exit-tunnel: WARNING: routed into the tunnel and BOTH fips and Internet will stop working." >&2
    fi
    # During setup a failure runs on_setup_failure (teardown only on a first
    # start); once up, only INT/TERM (an explicit stop) tears down.
    trap on_stop INT TERM
    trap on_setup_failure EXIT

    # 1. A persistent TUN (survives tun2socks), then tun2socks attached to it,
    #    talking to the exit over the fips interface.
    if ! ip link show "$TUN_IF" >/dev/null 2>&1; then
        run ip tuntap add dev "$TUN_IF" mode tun
    fi
    t2s=""
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "+ $TUN2SOCKS --device tun://$TUN_IF --proxy $EXIT_SOCKS --interface $FIPS_IF --mtu $TUN_MTU --loglevel warn &"
    else
        "$TUN2SOCKS" --device "tun://$TUN_IF" --proxy "$EXIT_SOCKS" --interface "$FIPS_IF" --mtu "$TUN_MTU" --loglevel warn &
        t2s=$!
        echo "$t2s" > "$STATE_DIR/tun2socks.pid"
        # The device is persistent, so "it appeared" proves nothing; check that
        # tun2socks itself survived its argument parsing and device attach.
        sleep 0.5
        if ! kill -0 "$t2s" 2>/dev/null; then
            rc=0; wait "$t2s" 2>/dev/null || rc=$?
            rm -f "$STATE_DIR/tun2socks.pid"
            echo "fips-exit-tunnel: tun2socks exited immediately (exit $rc); check EXIT_SOCKS/FIPS_IF and its output above" >&2
            exit 1
        fi
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
    # keeps flowing, and systemd's restart re-attaches. An explicit stop
    # restores routing.
    wait "$t2s" || true
    rm -f "$STATE_DIR/tun2socks.pid"
    echo "fips-exit-tunnel: tun2socks exited; leaving routing FAIL-CLOSED (systemd will retry; 'systemctl stop fips-exit-tunnel' restores routing)" >&2
    exit 1
}

case "${1:-}" in
    up)   up ;;
    down) down ;;
    *) echo "usage: $0 {up|down}" >&2; exit 2 ;;
esac
