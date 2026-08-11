package main

import "strings"

// pickUpstream decides which upstream SOCKS proxy a CONNECT is forwarded to,
// based only on the destination host — the same "route by destination" idea as
// a multiplexing proxy like hedproxy, but with just two upstreams:
//
//   - onion names (domain ATYP ending in the onion suffix) -> the Tor upstream,
//     so .onion reachability "just works" on the connectivity port;
//   - everything else — clearnet names and IP literals — -> the clearnet
//     upstream (Dante), which enforces the egress policy (blocks fd00::/8,
//     RFC1918, metadata, SMTP, bind) and resolves DNS server-side.
//
// It returns the upstream address and repSucceeded, or a SOCKS reply code to
// fail the request (onion requested but no Tor upstream configured on this node).
//
// Routing is by hostname only; the clearnet path never re-implements Dante's
// guards, and the onion path can't reach fips (Tor rejects internal addresses),
// so the dispatcher itself carries no egress policy.
func pickUpstream(host string, isDomain bool, cfg config) (string, byte) {
	if isDomain && isOnion(host, cfg.onionSuffix) {
		if cfg.torUpstream == "" {
			return "", repNotAllowed // onion routing disabled on this node
		}
		return cfg.torUpstream, repSucceeded
	}
	return cfg.clearnetUpstream, repSucceeded
}

// isOnion reports whether host is an onion name. The comparison is
// case-insensitive and tolerates a trailing dot (FQDN form).
func isOnion(host, suffix string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return strings.HasSuffix(h, suffix)
}
