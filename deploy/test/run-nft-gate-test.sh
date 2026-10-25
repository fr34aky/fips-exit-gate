#!/bin/sh
# Run the nftables gate integration test in a throwaway container. Needs a
# Docker daemon; the container gets NET_ADMIN (to load nft rules in its own
# network namespace) and SYS_ADMIN (for `ip netns`). Nothing touches the host's
# firewall.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${IMAGE:-alpine:3.20}"
# apparmor=unconfined: Docker's default profile denies the mount(2) that
# `ip netns add` needs (bind-mounting /var/run/netns) on Ubuntu/Debian hosts.
# The forwarding sysctls are read-only inside the container, so they are set
# at container start (the WireGuard forward/NAT tests need them).
exec docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
    -v "$here/..:/deploy:ro" "$IMAGE" \
    sh -c 'apk add -q nftables iproute2 socat >/dev/null && sh /deploy/test/nft-gate-test.sh'
