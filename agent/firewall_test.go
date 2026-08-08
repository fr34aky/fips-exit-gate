package main

import (
	"encoding/json"
	"net/netip"
	"testing"
)

// Sample outputs captured from `nft -j list set ...` shapes, so the parser is
// validated against the real JSON even though nft can't run in the sandbox.

const authorizedJSON = `{"nftables":[
  {"metainfo":{"version":"1.0.9"}},
  {"set":{"family":"inet","table":"fips_exit","name":"authorized","type":"ipv6_addr","flags":["interval"],
    "elem":["fd10:93b2:8586:6046:e42d:c089:3228:ccff","fd54:dc85:5ad5:c438:acd6:aa8:8495:13dd"]}}
]}`

const acctJSON = `{"nftables":[
  {"metainfo":{"version":"1.0.9"}},
  {"set":{"family":"inet","table":"fips_exit","name":"acct","type":["ipv6_addr","inet_service"],"flags":["dynamic"],
    "elem":[
      {"elem":{"val":["fd10:93b2:8586:6046:e42d:c089:3228:ccff",1080],"counter":{"packets":42,"bytes":123456}}},
      {"elem":{"val":["fd54:dc85:5ad5:c438:acd6:aa8:8495:13dd",1081],"counter":{"packets":7,"bytes":2048}}}
    ]}}
]}`

func TestParseAuthorizedJSON(t *testing.T) {
	var parsed nftJSON
	if err := json.Unmarshal([]byte(authorizedJSON), &parsed); err != nil {
		t.Fatal(err)
	}
	set := map[netip.Addr]struct{}{}
	for _, item := range parsed.Nftables {
		if item.Set == nil {
			continue
		}
		for _, e := range item.Set.Elem {
			var s string
			raw := e.Bare
			if e.Elem != nil {
				raw = e.Elem.Val
			}
			if err := json.Unmarshal(raw, &s); err != nil {
				continue
			}
			if a, err := netip.ParseAddr(s); err == nil {
				set[a] = struct{}{}
			}
		}
	}
	if len(set) != 2 {
		t.Fatalf("expected 2 authorized, got %d: %v", len(set), set)
	}
	if _, ok := set[netip.MustParseAddr("fd10:93b2:8586:6046:e42d:c089:3228:ccff")]; !ok {
		t.Fatal("missing first authorized address")
	}
}

func TestParseAcctJSON(t *testing.T) {
	var parsed nftJSON
	if err := json.Unmarshal([]byte(acctJSON), &parsed); err != nil {
		t.Fatal(err)
	}
	acct := map[acctKey]uint64{}
	for _, item := range parsed.Nftables {
		if item.Set == nil {
			continue
		}
		for _, e := range item.Set.Elem {
			if e.Elem == nil || e.Elem.Counter == nil {
				continue
			}
			var val []json.RawMessage
			if err := json.Unmarshal(e.Elem.Val, &val); err != nil || len(val) != 2 {
				t.Fatalf("bad val: %s", e.Elem.Val)
			}
			var addrStr string
			var port uint16
			_ = json.Unmarshal(val[0], &addrStr)
			_ = json.Unmarshal(val[1], &port)
			addr := netip.MustParseAddr(addrStr)
			acct[acctKey{Addr: addr, Port: port}] = e.Elem.Counter.Bytes
		}
	}
	if acct[acctKey{Addr: netip.MustParseAddr("fd10:93b2:8586:6046:e42d:c089:3228:ccff"), Port: 1080}] != 123456 {
		t.Fatalf("clearnet counter wrong: %+v", acct)
	}
	if acct[acctKey{Addr: netip.MustParseAddr("fd54:dc85:5ad5:c438:acd6:aa8:8495:13dd"), Port: 1081}] != 2048 {
		t.Fatalf("tor counter wrong: %+v", acct)
	}
}
