#!/bin/sh
# Render the Dante config from environment and exec sockd.
# POSIX sh (mirrors the upstream project's constraint).
set -eu

: "${FIPS_IF:?FIPS_IF is required}"
: "${EXTERNAL_IF:?EXTERNAL_IF is required}"
: "${CLEARNET_PORT:?CLEARNET_PORT is required}"
WORKERS="${WORKERS:-4}"

envsubst '$FIPS_IF $EXTERNAL_IF $CLEARNET_PORT' \
    < /srv/sockd.conf > /etc/sockd.conf

exec sockd -N "$WORKERS" -f /etc/sockd.conf
