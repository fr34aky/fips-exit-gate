# Whole-device mode: use the exit without proxy settings

The PAC file ([Client browser setup](install.md#client-browser-setup-pac))
covers browsers. For *everything* on a device — command-line tools, package
managers, apps that ignore proxy settings — route the whole machine into the
exit instead. No exit-side change is needed: the client turns its own traffic
into SOCKS connections to the same gated, metered port, so authorization,
captive handling and billing are exactly as for a browser.

```
 app ──▶ TUN (fipsexit0) ──▶ tun2socks ──▶ SOCKS5 [exit]:1080 over fips0 ──▶ exit ──▶ Internet
 .fips / fd00::/8 / LAN ──▶ normal routing (direct)
```

Why not just a default route via fips? fips is a TUN overlay that only
carries fd00::/8 and has no exit/default-route feature; a packet for an
Internet address dropped on `fips0` has nowhere to go. The exit therefore
offers a SOCKS port (today) and, planned, a WireGuard endpoint over fips for a
true default route (IPv4+IPv6+UDP, every platform). Until then, whole-device
mode is a client-side tunnel into the SOCKS port.

## Linux (`deploy/client/`)

What you need: root, iproute2, `tun2socks`
([xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks), one static
binary; put it in `PATH`), and systemd-resolved for the DNS step (or your own
DNS-over-TLS/HTTPS resolver, see below).

```sh
cd deploy/client
sudo install -Dm755 fips-exit-tunnel.sh /usr/local/bin/fips-exit-tunnel
sudo install -Dm600 fips-exit-tunnel.env.example /etc/fips-exit/tunnel.env
sudo $EDITOR /etc/fips-exit/tunnel.env        # EXIT_SOCKS, FIPS_IF, FIPS_UID or UPLINK_EXCLUDE
sudo install -Dm644 fips-exit-tunnel.service /etc/systemd/system/
sudo systemctl enable --now fips-exit-tunnel
```

What the script does (`DRY_RUN=1 fips-exit-tunnel up` prints it):

1. Creates a **persistent** TUN `fipsexit0` and starts `tun2socks` attached
   to it, pointed at `EXIT_SOCKS` and bound to `FIPS_IF`, so its own SOCKS
   connections always leave over fips.
2. Creates a routing table whose default route is the TUN (plus an
   `unreachable` fallback for the case where the device is gone). If
   tun2socks dies, the device, its route and the policy rules all stay:
   Internet traffic goes into a TUN nobody reads and times out instead of
   leaking out the normal default route, while fips, the LAN and the fips
   daemon's uplink keep working. systemd restarts the service into the same
   device. Only an explicit stop (`systemctl stop fips-exit-tunnel`; a bare
   `fips-exit-tunnel down` hands over to systemctl when the unit is active,
   because otherwise `Restart=` would bring the tunnel straight back) removes
   the device and restores normal routing. A setup failure during a restart
   likewise keeps the existing fail-closed routing rather than tearing it
   down. So a broken tunnel means *no Internet*, never *unprotected Internet*.
3. Adds policy rules: a `lookup main suppress_prefixlength 0` rule first, so
   every route in the main table *except* a default route keeps winning
   (connected LAN prefixes, including ones that appear later when you change
   WiFi or start a container bridge; fd00::/8 via `fips0`; host routes), then
   anything in `UPLINK_EXCLUDE` and (if set) all traffic of `FIPS_UID`;
   everything that would have taken the default route uses the tunnel table.
4. Sets `net.ipv4.conf.all.rp_filter=2` (loose) while up, restoring the old
   value on stop. With strict reverse-path filtering the kernel would drop
   replies to the traffic that bypasses the tunnel (the fips daemon's own
   uplink), because the reverse lookup has no socket uid and resolves into the
   tunnel table. (`all=0` is not "off": the effective value is the maximum of
   `all` and the interface's own, so only an explicit 2 is good enough.)
5. Points systemd-resolved at DNS-over-TLS servers **on the TUN** with the
   routing domain `~.`, so every name except `.fips` (which fips' own resolver
   keeps, via its more specific `~fips` domain) resolves through the tunnel
   over TCP/853.

### Keep the fips daemon out of its own tunnel

fips reaches its peers over your real uplink (UDP/TCP transports). If those
packets were routed into the TUN you would have a loop and no fips at all.
The script warns loudly if neither exclusion is configured. Two ways to
exclude them, in order of preference:

- Run the fips daemon under its own user and set `FIPS_UID`: the policy rule
  `uidrange` exempts all of its traffic, whatever peers it discovers.
- Or list your peers' public endpoints in `UPLINK_EXCLUDE` (space separated
  IPs/CIDRs). Brittle if peers change; fine for a fixed set of bootstrap peers.

Raw Ethernet/WiFi/Bluetooth transports need neither.

### DNS: why DNS-over-TLS

The exit's SOCKS server is **connect-only** (no UDP relay, by design: every
metered byte is TCP on the gated port). tun2socks hands the exit IP addresses,
not names, so names must be resolved on the client — and plain UDP DNS cannot
cross the tunnel. DNS-over-TLS (TCP/853) and DNS-over-HTTPS (TCP/443) do, and
they exit at the exit's location, so geolocation stays consistent with your
traffic. `DNS_SERVERS` takes `ip#name` pairs for certificate validation.

Without systemd-resolved, set `DNS_MODE=skip` and configure a DoT/DoH stub
resolver yourself (`stubby`, `dnscrypt-proxy`, `cloudflared proxy-dns`, …)
listening on localhost, and point `/etc/resolv.conf` at it.

### What does not work in whole-device mode

- **UDP to the Internet** (games, VoIP, QUIC). Browsers fall back from QUIC to
  TCP automatically; other UDP applications fail. This is the SOCKS port's
  limitation and the reason for the planned WireGuard service.
- **ICMP** (`ping` to Internet hosts). `curl`, `ssh`, `git`, `apt` all work.
- `.onion` destinations: they need the name to reach the exit (`*.onion` is
  routed to Tor by hostname). In whole-device mode use the browser PAC or a
  per-app SOCKS setting for onion sites; or route only clearnet this way.

### Verifying

```sh
curl -4 https://ifconfig.co        # the exit's public IPv4
curl -6 https://ifconfig.co        # the exit's public IPv6
resolvectl query example.com       # answered via fipsexit0 (DoT)
curl http://npub1….fips:8080/      # portal still loads natively over fips
sudo kill $(cat /run/fips-exit-tunnel/tun2socks.pid); curl -m5 https://ifconfig.co   # must time out (fail-closed); fips still works; systemd restarts the tunnel
```

Unauthorized or out of credit? Plain-HTTP requests still get the captive
redirect to the portal (the client sees a 302 like a browser would); HTTPS
connections are refused. Open the portal over fips, buy a package, and the
tunnel works again without restarting anything.

## Android

Apps built on `hev-socks5-tunnel` / `tun2socks` (for example *SocksDroid*,
*Tun2Socks* from F-Droid) do the same thing as a VPN profile: set the server
to the exit's fips address and port 1080, no authentication, **UDP off**, and
a DNS-over-TLS resolver as the device's private DNS. The fips Android app must
be excluded from the VPN (per-app VPN settings) for the same loop reason as
`FIPS_UID` above.

## Windows / macOS

`tun2socks` runs on both; the routing and DNS steps differ per OS and are not
scripted here. The WireGuard service (planned) is the intended path for those
platforms: one imported config, no scripting.
