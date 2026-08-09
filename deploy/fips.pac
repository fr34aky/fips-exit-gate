// fips.pac — browser proxy auto-config for browsing the Internet through a
// fips exit node.
//
//   Internet traffic         -> the exit's SOCKS5 proxy (DNS resolved server-side)
//   .fips names & the mesh    -> DIRECT (reached natively over fips, never tunnelled
//   localhost / fd00::/8         through the exit — this is how the portal loads)
//
// Usage:
//   1. Set EXIT below to your exit node's fips address and clearnet SOCKS port
//      (the EXIT_FIPS_ADDR and CLEARNET_PORT from its deploy/.env).
//   2. Point the browser at this file as its automatic proxy configuration URL
//      (file:///path/to/fips.pac, or an http/.fips URL you host it at).
// See docs/install.md ("Client browser setup").

function FindProxyForURL(url, host) {
  // Exit node:  [fips-address]:clearnet-port
  var EXIT = "[fd6b:b19b:6700:c923:df48:31a8:698b:bb25]:1080";

  // fips mesh (the portal and every .fips service) — reached natively, not via
  // the exit. Without this the portal itself would try to load through SOCKS.
  if (dnsDomainIs(host, ".fips") || host == "fips") return "DIRECT";

  // Localhost and fips ULA (fd00::/8) literals stay local too.
  if (host == "localhost" || host == "::1" ||
      shExpandMatch(host, "127.*") || shExpandMatch(host, "fd*:*"))
    return "DIRECT";

  // Everything else is the Internet: send it through the exit. No DIRECT
  // fallback, so if the exit is down traffic fails closed instead of leaking.
  return "SOCKS5 " + EXIT;
}
