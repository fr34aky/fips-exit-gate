#!/bin/sh
# Render the fips-exit nftables ruleset from the service catalog + env.
#
# The ruleset gates ONLY the service ports: unauthorized fips sources hitting a
# service port are redirected to the captive daemon; authorized sources reach
# the service. General fd00::/8 traffic is never touched (no drop policy), so
# the host keeps working as a normal fips node.
#
# Two layers enforce authorization:
#   1. `gate` (nat prerouting) decides ONCE per connection whether a new flow
#      goes to the service or is redirected to the captive daemon.
#   2. `svc_in` / `svc_out` (filter input/output) re-check set membership on
#      EVERY packet of a service-port flow and reset the connection as soon as
#      the source is no longer authorized. Without this a revoked client would
#      keep an already-open tunnel for as long as it liked, because a NAT
#      decision is never re-evaluated. `svc_in` also drops service-port traffic
#      that did not arrive on the fips interface (loopback/other interfaces),
#      so nothing on the exit host or beyond it gets ungated proxy access.
#
# In Phase 1 the authorized set is seeded from a static allowlist file; in
# Phase 2 the exit-agent owns the set and the acct counters live-drive billing.
#
# Services are "<key> <port> [proto]" lines (proto tcp by default; "udp" for
# the WireGuard service). TCP services get the captive redirect; UDP services
# are simply gated (an unauthorized WireGuard handshake is dropped).
#
# Env:
#   FIPS_IF         fips TUN interface        (e.g. fips0)
#   EXIT_FIPS_ADDR  this node's fips address  (services listen here)
#   CAPTIVE_PORT    local port of the captive daemon
#   SERVICES_FILE   path to services.conf     (default: ./services.conf)
#   ALLOWLIST_FILE  newline-separated fips addresses (default: ./allowlist.txt)
#   MAX_CONNS_PER_SRC  per-source concurrent-connection ceiling (0 = disabled)
#   GUARD_PORTS     space-separated ports a compose service may bind on
#                   EXIT_FIPS_ADDR (CONNECTIVITY_PORT, TOR_PORT, WG_PORT). Any
#                   of them NOT listed in services.conf is rendered unreachable
#                   from fips, so a service started without its catalog line is
#                   refused instead of being open, ungated and unmetered.
#   WG_IF           WireGuard interface; when set, the forward/NAT policy for
#                   tunnel clients is rendered too (needs EXTERNAL_IF, WG_POOL4,
#                   WG_POOL6, WG_GW4, WG_GW6; WG_MSS default 1140;
#                   WG_IPV6_EGRESS=1 to masquerade inner IPv6, 0 to refuse it)
set -eu

FIPS_IF="${FIPS_IF:?FIPS_IF is required}"
EXIT_FIPS_ADDR="${EXIT_FIPS_ADDR:?EXIT_FIPS_ADDR is required}"
CAPTIVE_PORT="${CAPTIVE_PORT:?CAPTIVE_PORT is required}"
SERVICES_FILE="${SERVICES_FILE:-$(dirname "$0")/services.conf}"
ALLOWLIST_FILE="${ALLOWLIST_FILE:-$(dirname "$0")/allowlist.txt}"
MAX_CONNS_PER_SRC="${MAX_CONNS_PER_SRC:-0}"
GUARD_PORTS="${GUARD_PORTS:-}"
WG_IF="${WG_IF:-}"

# Collect enabled service ports per protocol.
ports=""      # TCP (captive-redirected) services
udp_ports=""  # UDP services (WireGuard)
while read -r key port proto _rest; do
    case "$key" in
        ''|\#*) continue ;;
    esac
    case "$port" in
        ''|*[!0-9]*) echo "bad port for service '$key' in $SERVICES_FILE: '$port'" >&2; exit 1 ;;
    esac
    case "${proto:-tcp}" in
        tcp) ports="${ports:+$ports, }$port" ;;
        udp) udp_ports="${udp_ports:+$udp_ports, }$port" ;;
        *) echo "bad proto for service '$key' in $SERVICES_FILE: '$proto' (tcp|udp)" >&2; exit 1 ;;
    esac
done < "$SERVICES_FILE"
[ -n "$ports" ] || { echo "no TCP services enabled in $SERVICES_FILE" >&2; exit 1; }

# UDP service rules (empty when no UDP service is enabled: nft rejects `{ }`).
udp_in="" udp_out="" udp_local="" udp_acct_in="" udp_acct_out=""
if [ -n "$udp_ports" ]; then
    udp_local="        iifname != \"$FIPS_IF\" ip6 daddr $EXIT_FIPS_ADDR udp dport { $udp_ports } counter drop"
    udp_in="        iifname \"$FIPS_IF\" ip6 daddr $EXIT_FIPS_ADDR udp dport { $udp_ports } ip6 saddr != @authorized counter drop"
    udp_out="        oifname \"$FIPS_IF\" ip6 saddr $EXIT_FIPS_ADDR udp sport { $udp_ports } ip6 daddr != @authorized counter drop"
    udp_acct_in="        iifname \"$FIPS_IF\" ip6 saddr @authorized udp dport { $udp_ports } update @acct { ip6 saddr . udp dport }"
    udp_acct_out="        oifname \"$FIPS_IF\" ip6 daddr @authorized udp sport { $udp_ports } update @acct { ip6 daddr . udp sport }"
fi

# WireGuard tunnel policy (only when WG_IF is set): tunnel clients may reach
# the Internet via EXTERNAL_IF (masqueraded), the exit's own resolver on the
# gateway addresses, and nothing else — mirroring Dante's egress policy for
# the SOCKS services (exit/sockd.conf).
wg_input="" wg_chains=""
if [ -n "$WG_IF" ]; then
    EXTERNAL_IF="${EXTERNAL_IF:?EXTERNAL_IF is required with WG_IF}"
    WG_POOL4="${WG_POOL4:?WG_POOL4 is required with WG_IF}"
    WG_POOL6="${WG_POOL6:?WG_POOL6 is required with WG_IF}"
    WG_GW4="${WG_GW4:?WG_GW4 is required with WG_IF}"
    WG_GW6="${WG_GW6:?WG_GW6 is required with WG_IF}"
    WG_MSS="${WG_MSS:-1140}"
    WG_IPV6_EGRESS="${WG_IPV6_EGRESS:-1}"
    if [ "$WG_IPV6_EGRESS" = "1" ]; then
        wg_v6_egress="        oifname \"$EXTERNAL_IF\" ip6 saddr $WG_POOL6 masquerade"
        wg_v6_refuse=""
    else
        wg_v6_egress=""
        wg_v6_refuse="        meta nfproto ipv6 counter reject with icmpv6 type addr-unreachable"
    fi
    wg_input="        iifname \"$WG_IF\" jump from_wg"
    wg_chains="
    # Forwarding: only tunnel <-> Internet. fips never routes to/from the
    # Internet through this host (SOCKS and WireGuard are the only paths).
    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname \"$FIPS_IF\" oifname \"$EXTERNAL_IF\" counter drop
        iifname \"$EXTERNAL_IF\" oifname \"$FIPS_IF\" counter drop
        iifname \"$WG_IF\" jump wg_egress
        oifname \"$WG_IF\" jump wg_ingress
    }
    # Tunnel client -> Internet: client isolation, no private/mesh/metadata
    # destinations, no outbound mail, only via the external interface, MSS
    # clamped so TCP never needs outer fragmentation over fips (MTU 1280).
    chain wg_egress {
        oifname \"$WG_IF\" counter drop
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 } counter reject with icmp type admin-prohibited
        ip6 daddr { ::/128, ::1/128, ::ffff:0:0/96, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32 } counter reject with icmpv6 type admin-prohibited
        meta l4proto tcp th dport { 25, 465, 587 } counter reject with tcp reset
$wg_v6_refuse
        oifname != \"$EXTERNAL_IF\" counter drop
        tcp flags syn tcp option maxseg size set $WG_MSS
        accept
    }
    # Internet -> tunnel client: replies only.
    chain wg_ingress {
        tcp flags syn tcp option maxseg size set $WG_MSS
        ct state established,related accept
        counter drop
    }
    # Tunnel client -> this host: the resolver on the gateway addresses and
    # ICMP; everything else (backend, metrics, SSH) is closed from the tunnel.
    chain from_wg {
        ip daddr $WG_GW4 meta l4proto { tcp, udp } th dport 53 accept
        ip6 daddr $WG_GW6 meta l4proto { tcp, udp } th dport 53 accept
        icmp type echo-request accept
        icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert } accept
        counter drop
    }
    chain wg_nat {
        type nat hook postrouting priority srcnat; policy accept;
        oifname \"$EXTERNAL_IF\" ip saddr $WG_POOL4 masquerade
$wg_v6_egress
    }
"
fi

# Ports that may be bound on the fips address but are not catalogued: refused.
ungated=""
for gp in $GUARD_PORTS; do
    case ", $ports, $udp_ports," in
        *", $gp,"*) ;;
        *) case ", $ungated," in *", $gp,"*) ;; *) ungated="${ungated:+$ungated, }$gp" ;; esac ;;
    esac
done
ungated_rule=""
if [ -n "$ungated" ]; then
    ungated_rule="        iifname \"$FIPS_IF\" ip6 daddr $EXIT_FIPS_ADDR tcp dport { $ungated } tcp flags & rst == 0 counter reject with tcp reset comment \"not in services.conf: refused rather than ungated\"
        iifname \"$FIPS_IF\" ip6 daddr $EXIT_FIPS_ADDR udp dport { $ungated } counter drop comment \"not in services.conf: refused rather than ungated\""
fi

# Seed elements for the authorized set from the allowlist (may be empty).
elements=""
if [ -f "$ALLOWLIST_FILE" ]; then
    while read -r addr; do
        case "$addr" in
            ''|\#*) continue ;;
        esac
        elements="${elements:+$elements, }$addr"
    done < "$ALLOWLIST_FILE"
fi

# Optional per-source concurrent-connection ceiling. A filter chain (where
# ct count belongs) that drops over-limit NEW connections from authorized
# sources on service ports — so one npub/device can't exhaust the exit. Runs
# before the nat gate (lower priority number). 0 = disabled.
conn_limit_chain=""
if [ "$MAX_CONNS_PER_SRC" -gt 0 ] 2>/dev/null; then
    conn_limit_chain="
    chain conn_limit {
        type filter hook prerouting priority -160; policy accept;
        iifname \"$FIPS_IF\" ip6 daddr $EXIT_FIPS_ADDR tcp dport { $ports } ip6 saddr @authorized ct state new meter fips_connlimit { ip6 saddr ct count over $MAX_CONNS_PER_SRC } drop
    }
"
fi

cat <<EOT
#!/usr/sbin/nft -f
# Generated by render-nftables.sh — do not edit by hand.
table inet fips_exit {
    # Authorized fips source addresses (owners + whitelisted npubs, derived).
    set authorized {
        type ipv6_addr
        flags interval
$( [ -n "$elements" ] && printf '        elements = { %s }\n' "$elements" )
    }

    # Per-source byte accounting on service traffic. The exit-agent reads this
    # in Phase 2; policy accept means it only counts, never blocks.
    set acct {
        type ipv6_addr . inet_service
        size 131072
        flags dynamic
        counter
    }

    # Gate: redirect unauthorized service-port traffic to the captive daemon.
    # authorized sources are accepted here (in nat = stop, packet proceeds to
    # the local service listening on that port). NAT is evaluated once per
    # connection; per-packet enforcement lives in svc_in/svc_out below.
    chain gate {
        type nat hook prerouting priority dstnat; policy accept;
        iifname != "$FIPS_IF" return
        ip6 daddr $EXIT_FIPS_ADDR tcp dport { $ports } ip6 saddr @authorized accept
        ip6 daddr $EXIT_FIPS_ADDR tcp dport { $ports } redirect to :$CAPTIVE_PORT
    }

    # Per-packet enforcement (filter hooks run after NAT, so a flow that was
    # redirected to the captive daemon now carries dport $CAPTIVE_PORT and is
    # not matched here; only flows that reached a real service port are).
    #   - service ports are reachable ONLY via the fips interface: traffic from
    #     loopback or any other interface is refused (reset, so a misdirected
    #     local client fails fast instead of hanging), so the exit host itself
    #     (and anything routed to it) can't bypass the gate on those ports;
    #   - a port a compose service may bind (GUARD_PORTS) that is missing from
    #     services.conf is refused from fips: never open-but-ungated;
    #   - a flow whose source has left the authorized set is reset on its next
    #     packet in either direction, so revocation/quota exhaustion cuts live
    #     tunnels instead of only blocking new ones.
    # RST segments are exempt everywhere: the resets these rules generate must
    # be able to leave (svc_out) and reach the local socket (svc_in), and a
    # peer's own RST only ever closes a connection.
    chain svc_in {
        type filter hook input priority filter; policy accept;
$wg_input
        iifname != "$FIPS_IF" ip6 daddr $EXIT_FIPS_ADDR tcp dport { $ports } tcp flags & rst == 0 counter reject with tcp reset
        iifname "$FIPS_IF" ip6 daddr $EXIT_FIPS_ADDR tcp dport { $ports } tcp flags & rst == 0 ip6 saddr != @authorized counter reject with tcp reset
$ungated_rule
$udp_local
$udp_in
    }
    chain svc_out {
        type filter hook output priority filter; policy accept;
        oifname "$FIPS_IF" ip6 saddr $EXIT_FIPS_ADDR tcp sport { $ports } tcp flags & rst == 0 ip6 daddr != @authorized counter reject with tcp reset
$udp_out
    }

    # Accounting (counts only; never drops). Keyed on (client address, service
    # port) so usage is per-service — both directions land on the same element:
    #   inbound  client->service: (saddr, dport=service port)
    #   outbound service->client: (daddr, sport=service port)
    # so the element's byte counter is the client's total for that service.
    # Only authorized sources are counted: captive-redirect traffic from unknown
    # addresses would otherwise fill the set and produce unattributable samples.
    # Membership is checked per packet here too, consistent with svc_in/svc_out,
    # so at most the packets already in flight at revocation go uncounted.
    chain acct_in {
        type filter hook prerouting priority -150; policy accept;
        iifname "$FIPS_IF" ip6 saddr @authorized tcp dport { $ports } update @acct { ip6 saddr . tcp dport }
$udp_acct_in
    }
    chain acct_out {
        type filter hook postrouting priority -150; policy accept;
        oifname "$FIPS_IF" ip6 daddr @authorized tcp sport { $ports } update @acct { ip6 daddr . tcp sport }
$udp_acct_out
    }
$conn_limit_chain
$wg_chains
}
EOT
