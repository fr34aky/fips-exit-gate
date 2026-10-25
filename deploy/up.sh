#!/bin/sh
# Bring up (or reload) a Phase 1 fips-exit node on this host.
#
#   ./up.sh up      render+load nftables, then start the compose stack
#   ./up.sh reload  re-render nftables from services.conf + allowlist.txt only
#   ./up.sh down    stop the stack (nftables table left in place; use flush)
#   ./up.sh flush   delete the nftables table
#
# Required env (see .env.example):
#   FIPS_IF EXTERNAL_IF EXIT_FIPS_ADDR CAPTIVE_PORT
#   CAPTIVE_PORTAL_URL CAPTIVE_TOKEN_SECRET
set -eu

here="$(dirname "$0")"
# Load config from this script's .env when it isn't already in the environment,
# so `sudo ./up.sh …` works without -E (root can read the 0600 file). Vars the
# caller already exported take precedence.
if [ -z "${FIPS_IF:-}" ] && [ -f "$here/.env" ]; then
    set -a
    . "$here/.env"
    set +a
fi
: "${CAPTIVE_PORT:=1088}"
export CAPTIVE_PORT
NFT_FILE="${NFT_FILE:-/etc/nftables.d/fips-exit.nft}"

# Ports that compose services bind on the fips address. Any of them missing
# from services.conf is rendered unreachable from fips (see render-nftables.sh
# GUARD_PORTS), so e.g. starting the tor profile before adding `tor 1081` yields
# a refused port, never an open, ungated, unmetered one.
guard_ports() {
    echo "${CONNECTIVITY_PORT:-1080} ${TOR_PORT:-1081}"
}

# The live members of the authorized set, as an nft element list ("a, b, c"),
# empty if the table/set doesn't exist. Used to carry grants across a reload.
authorized_elements() {
    nft list set inet fips_exit authorized 2>/dev/null \
        | sed -n '/elements = {/,/}/p' | tr -d '\n\t' | sed 's/.*elements = {//; s/}.*//; s/^ *//; s/ *$//'
}

render_nft() {
    mkdir -p "$(dirname "$NFT_FILE")"
    FIPS_IF="${FIPS_IF:?}" EXIT_FIPS_ADDR="${EXIT_FIPS_ADDR:?}" \
    CAPTIVE_PORT="$CAPTIVE_PORT" \
    MAX_CONNS_PER_SRC="${MAX_CONNS_PER_SRC:-0}" GUARD_PORTS="$(guard_ports)" \
    SERVICES_FILE="$here/services.conf" ALLOWLIST_FILE="$here/allowlist.txt" \
        sh "$here/render-nftables.sh" > "$NFT_FILE"
    # Validate before touching the running ruleset.
    nft -c -f "$NFT_FILE"
}

case "${1:-up}" in
    up)
        render_nft
        nft -f "$NFT_FILE"
        echo "nftables loaded from $NFT_FILE"
        echo "NOTE: point the host resolver at unbound, e.g.:"
        echo "  echo 'nameserver 127.0.0.1' > /etc/resolv.conf"
        docker compose -f "$here/docker-compose.yaml" up -d --build
        ;;
    reload)
        render_nft
        # Replace only our table, leaving the rest of the host firewall intact.
        # The rendered file seeds `authorized` from allowlist.txt (empty in agent
        # mode), so carry the LIVE members across: with per-packet enforcement an
        # empty set would reset every open tunnel of every client until the
        # agent's next reconcile, not merely block new connections.
        live="$(authorized_elements)"
        nft delete table inet fips_exit 2>/dev/null || true
        nft -f "$NFT_FILE"
        if [ -n "$live" ]; then
            nft add element inet fips_exit authorized "{ $live }" \
                && echo "nftables reloaded from $NFT_FILE; $(printf '%s' "$live" | tr ',' '\n' | wc -l) live grant(s) carried over" \
                || echo "WARNING: could not re-add live grants; the agent's next reconcile restores them" >&2
        else
            echo "nftables reloaded from $NFT_FILE"
        fi
        ;;
    down)
        docker compose -f "$here/docker-compose.yaml" down
        ;;
    flush)
        nft delete table inet fips_exit 2>/dev/null || true
        echo "nftables table inet fips_exit removed"
        ;;
    *)
        echo "usage: $0 {up|reload|down|flush}" >&2
        exit 2
        ;;
esac
