package main

import "testing"

func TestPickUpstream(t *testing.T) {
	cfg := config{clearnetUpstream: "clear", torUpstream: "tor", onionSuffix: ".onion"}
	cases := []struct {
		name     string
		host     string
		isDomain bool
		want     string
		wantRep  byte
	}{
		{"onion lowercase", "abcdefghij.onion", true, "tor", repSucceeded},
		{"onion uppercase", "ABCDEFGHIJ.ONION", true, "tor", repSucceeded},
		{"onion trailing dot", "abcdefghij.onion.", true, "tor", repSucceeded},
		{"clearnet name", "example.com", true, "clear", repSucceeded},
		{"onion substring not suffix", "onion.example.com", true, "clear", repSucceeded},
		{"name ending in word onion", "myonion.com", true, "clear", repSucceeded},
		{"ipv4 literal", "203.0.113.4", false, "clear", repSucceeded},
		{"ipv6 literal", "2001:db8::1", false, "clear", repSucceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rep := pickUpstream(tc.host, tc.isDomain, cfg)
			if got != tc.want || rep != tc.wantRep {
				t.Fatalf("pickUpstream(%q,%v) = (%q,0x%02x), want (%q,0x%02x)",
					tc.host, tc.isDomain, got, rep, tc.want, tc.wantRep)
			}
		})
	}
}

func TestPickUpstreamOnionDisabled(t *testing.T) {
	cfg := config{clearnetUpstream: "clear", torUpstream: "", onionSuffix: ".onion"}
	if got, rep := pickUpstream("abcdefghij.onion", true, cfg); rep != repNotAllowed || got != "" {
		t.Fatalf("onion with no Tor upstream = (%q,0x%02x), want (\"\",0x%02x)", got, rep, repNotAllowed)
	}
	// Clearnet still works with onion disabled.
	if got, rep := pickUpstream("example.com", true, cfg); rep != repSucceeded || got != "clear" {
		t.Fatalf("clearnet with onion disabled = (%q,0x%02x), want (clear,0x00)", got, rep)
	}
}

// An IP literal must never be treated as onion, even if isDomain were mis-set.
func TestIsOnion(t *testing.T) {
	if isOnion("example.com", ".onion") {
		t.Fatal("example.com classified as onion")
	}
	if !isOnion("xyz.onion", ".onion") {
		t.Fatal("xyz.onion not classified as onion")
	}
}
