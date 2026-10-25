#!/bin/sh
# Run the whole-device tunnel test in a throwaway container: needs Docker, a
# TUN device, NET_ADMIN, and Internet access (to fetch tun2socks and make one
# HTTP request). Nothing touches the host's routing.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${IMAGE:-alpine:3.20}"
# /proc/sys is read-only in a container, so the loose reverse-path filter the
# script would set itself is passed in at container start instead.
exec docker run --rm --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.conf.all.rp_filter=2 \
    -v "$here/../..:/deploy:ro" "$IMAGE" \
    sh -c 'apk add -q dante-server iproute2 curl unzip ca-certificates su-exec >/dev/null && sh /deploy/client/test/tunnel-test.sh'
