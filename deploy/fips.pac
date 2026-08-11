// fips.pac — browser proxy auto-config for browsing the Internet through a
// fips exit node.
//
//   Internet traffic        -> the exit's SOCKS5 proxy (DNS resolved server-side)
//   .onion addresses         -> same SOCKS5 proxy; the :1080 connectivity service
//                               reaches Tor .onion too (the exit routes *.onion to
//                               Tor), so no special PAC rule is needed for them
//   .fips names & fd00::/8   -> DIRECT (reached natively over fips; this is how
//   localhost                   the portal and .fips services load)
//
// Set EXIT to your exit node's <npub>.fips name and connectivity SOCKS port
// (:1080 — clearnet + .onion).
// Address the exit by its <npub>.fips NAME, not a raw [fd..] IPv6 literal:
// Firefox will not use a bracketed IPv6 literal as a SOCKS proxy target. The
// name also resolves mesh-wide and survives an address change.
//
// Load it as the browser's automatic proxy configuration URL (a file:///path, or
// an http/.fips URL you host it at). See docs/install.md ("Client browser setup").

function FindProxyForURL(url, host) {
  host = host.toLowerCase();

  // Exit node: <npub>.fips : connectivity-port (:1080 — clearnet + .onion)
  var EXIT = "npub1lx2m36mtzpvae7caw6tphqzhuyufg82y63p8lvd8n6nvkdkw0thq08hdpz.fips:1080";

  // fips mesh (the portal and every .fips service) — reached natively, not via
  // the exit. Without this the portal itself would try to load through SOCKS.
  if (dnsDomainIs(host, ".fips")) return "DIRECT";

  // fips ULA (fd00::/8) address literals.
  if (host.indexOf(":") !== -1 && host.substr(0, 2) === "fd") return "DIRECT";

  // Localhost stays local.
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") return "DIRECT";

  // Everything else is the Internet: send it through the exit. No DIRECT
  // fallback, so if the exit is down traffic fails closed instead of leaking.
  return "SOCKS5 " + EXIT;
}
