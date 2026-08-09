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
: "${CAPTIVE_PORT:=1088}"
export CAPTIVE_PORT
NFT_FILE="${NFT_FILE:-/etc/nftables.d/fips-exit.nft}"

render_nft() {
    mkdir -p "$(dirname "$NFT_FILE")"
    FIPS_IF="${FIPS_IF:?}" EXIT_FIPS_ADDR="${EXIT_FIPS_ADDR:?}" \
    CAPTIVE_PORT="$CAPTIVE_PORT" \
    MAX_CONNS_PER_SRC="${MAX_CONNS_PER_SRC:-0}" \
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
        nft delete table inet fips_exit 2>/dev/null || true
        nft -f "$NFT_FILE"
        echo "nftables reloaded (authorized set + services re-applied)"
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
