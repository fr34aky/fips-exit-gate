#!/bin/sh
# Render the Dante config from environment and exec sockd.
# POSIX sh (mirrors the upstream project's constraint).
set -eu

: "${FIPS_IF:?FIPS_IF is required}"
: "${EXIT_FIPS_ADDR:?EXIT_FIPS_ADDR is required}"
: "${EXTERNAL_IF:?EXTERNAL_IF is required}"
: "${CLEARNET_PORT:?CLEARNET_PORT is required}"
# Dante now listens on loopback (the dispatcher forwards clearnet here), so the
# bind address is configurable and defaults to IPv4 loopback.
CLEARNET_BIND="${CLEARNET_BIND:-127.0.0.1}"
export CLEARNET_BIND
WORKERS="${WORKERS:-4}"

# Substitute an explicit variable list (so unrelated $tokens in the config are
# left alone). Keep this list in sync with the placeholders used in sockd.conf.
envsubst '$FIPS_IF $EXIT_FIPS_ADDR $EXTERNAL_IF $CLEARNET_BIND $CLEARNET_PORT' \
    < /srv/sockd.conf > /etc/sockd.conf

exec sockd -N "$WORKERS" -f /etc/sockd.conf
