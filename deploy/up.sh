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

# Refuse to leave a running Tor SocksPort ungated. Tor binds EXIT_FIPS_ADDR:TOR_PORT
# for every fips address; only the rendered gate restricts it to paying clients.
# If the tor container is running (or is about to be, via COMPOSE_PROFILES) its
# port must be in services.conf, otherwise the whole mesh gets free, unmetered Tor.
check_tor_gated() {
    tor_port="${TOR_PORT:-1081}"
    tor_up=0
    case ",${COMPOSE_PROFILES:-}," in *,tor,*) tor_up=1 ;; esac
    if [ "$tor_up" -eq 0 ] && command -v docker >/dev/null 2>&1 && \
       [ -n "$(docker ps -q --filter label=com.docker.compose.project=fips-exit \
                              --filter label=com.docker.compose.service=tor 2>/dev/null)" ]; then
        tor_up=1
    fi
    [ "$tor_up" -eq 1 ] || return 0
    if ! grep -Eq "^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]+${tor_port}([[:space:]]|\$)" "$here/services.conf"; then
        echo "ERROR: Tor is running (or starting) on :$tor_port but services.conf does not list that port." >&2
        echo "       Every fips address would get ungated, unmetered Tor. Either add 'tor $tor_port' to" >&2
        echo "       services.conf (plus the /admin/services row) or stop it: docker compose --profile tor down." >&2
        echo "       ALLOW_UNGATED_TOR=1 overrides this check." >&2
        [ "${ALLOW_UNGATED_TOR:-0}" = "1" ] || exit 1
    fi
}

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
        check_tor_gated
        render_nft
        nft -f "$NFT_FILE"
        echo "nftables loaded from $NFT_FILE"
        echo "NOTE: point the host resolver at unbound, e.g.:"
        echo "  echo 'nameserver 127.0.0.1' > /etc/resolv.conf"
        docker compose -f "$here/docker-compose.yaml" up -d --build
        ;;
    reload)
        check_tor_gated
        render_nft
        # Replace only our table, leaving the rest of the host firewall intact.
        # This recreates the `authorized` set from allowlist.txt (empty in agent
        # mode), so live grants are dropped until the agent re-syncs.
        nft delete table inet fips_exit 2>/dev/null || true
        nft -f "$NFT_FILE"
        echo "nftables reloaded from $NFT_FILE"
        echo "NOTE: the 'authorized' set was reset. In agent mode, restart the agent"
        echo "      (docker restart <agent>) or wait for its next full sync to restore grants."
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
