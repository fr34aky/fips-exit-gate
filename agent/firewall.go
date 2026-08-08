package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// acctKey identifies one accounting element: a client address on a service port.
type acctKey struct {
	Addr netip.Addr
	Port uint16
}

// Firewall is the exit's netfilter surface the agent drives. Abstracted so the
// reconciliation and accounting logic can be unit-tested without root/nft.
type Firewall interface {
	// ListAuthorized returns the current members of the authorized set.
	ListAuthorized() (map[netip.Addr]struct{}, error)
	// ApplyAuthorized adds and removes members atomically.
	ApplyAuthorized(add, del []netip.Addr) error
	// ReadAcct returns absolute byte counters per (addr, service port).
	ReadAcct() (map[acctKey]uint64, error)
	// DeleteAcct removes accounting elements (used to GC revoked addresses).
	DeleteAcct(keys []acctKey) error
}

// nftFirewall drives netfilter by shelling out to the nft binary. nft is
// present on both Ubuntu and OpenWrt, keeping the agent dependency-free.
type nftFirewall struct {
	nftPath string
	table   string // e.g. "inet fips_exit"
}

func newNftFirewall(nftPath, table string) *nftFirewall {
	return &nftFirewall{nftPath: nftPath, table: table}
}

func (f *nftFirewall) run(stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command(f.nftPath, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// nftJSON mirrors the parts of `nft -j list set ...` output we consume.
type nftJSON struct {
	Nftables []struct {
		Set *struct {
			Name string           `json:"name"`
			Elem []nftElemWrapper `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

// An element is either a bare value (no stateful object) or an object with
// "val" and, for counter sets, "counter". json.RawMessage lets us handle both.
type nftElemWrapper struct {
	Elem *struct {
		Val     json.RawMessage `json:"val"`
		Counter *struct {
			Bytes uint64 `json:"bytes"`
		} `json:"counter"`
	} `json:"elem"`
	Bare json.RawMessage `json:"-"`
}

func (w *nftElemWrapper) UnmarshalJSON(b []byte) error {
	// Try the {"elem": {...}} wrapper first; fall back to a bare scalar/array.
	type alias nftElemWrapper
	var a alias
	if err := json.Unmarshal(b, &a); err == nil && a.Elem != nil {
		*w = nftElemWrapper(a)
		return nil
	}
	w.Elem = nil
	w.Bare = append([]byte(nil), b...)
	return nil
}

func (f *nftFirewall) listSet(name string) (*nftJSON, error) {
	fields := strings.Fields(f.table) // "inet fips_exit"
	if len(fields) != 2 {
		return nil, fmt.Errorf("firewall: bad table %q", f.table)
	}
	out, err := f.run("", "-j", "list", "set", fields[0], fields[1], name)
	if err != nil {
		return nil, err
	}
	var parsed nftJSON
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("firewall: parse %s: %w", name, err)
	}
	return &parsed, nil
}

func (f *nftFirewall) ListAuthorized() (map[netip.Addr]struct{}, error) {
	parsed, err := f.listSet("authorized")
	if err != nil {
		return nil, err
	}
	set := make(map[netip.Addr]struct{})
	for _, item := range parsed.Nftables {
		if item.Set == nil {
			continue
		}
		for _, e := range item.Set.Elem {
			var raw json.RawMessage
			if e.Elem != nil {
				raw = e.Elem.Val
			} else {
				raw = e.Bare
			}
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				continue // ranges/prefixes not expected for authorized; skip
			}
			if a, err := netip.ParseAddr(s); err == nil {
				set[a] = struct{}{}
			}
		}
	}
	return set, nil
}

func (f *nftFirewall) ApplyAuthorized(add, del []netip.Addr) error {
	if len(add) == 0 && len(del) == 0 {
		return nil
	}
	var sb strings.Builder
	if len(add) > 0 {
		fmt.Fprintf(&sb, "add element %s authorized { %s }\n", f.table, joinAddrs(add))
	}
	if len(del) > 0 {
		fmt.Fprintf(&sb, "delete element %s authorized { %s }\n", f.table, joinAddrs(del))
	}
	_, err := f.run(sb.String(), "-f", "-")
	return err
}

func (f *nftFirewall) ReadAcct() (map[acctKey]uint64, error) {
	parsed, err := f.listSet("acct")
	if err != nil {
		return nil, err
	}
	acct := make(map[acctKey]uint64)
	for _, item := range parsed.Nftables {
		if item.Set == nil {
			continue
		}
		for _, e := range item.Set.Elem {
			if e.Elem == nil || e.Elem.Counter == nil {
				continue
			}
			parts, ok := concatParts(e.Elem.Val)
			if !ok || len(parts) != 2 {
				continue
			}
			var addrStr string
			if err := json.Unmarshal(parts[0], &addrStr); err != nil {
				continue
			}
			port, ok := parsePort(parts[1])
			if !ok {
				continue
			}
			addr, err := netip.ParseAddr(addrStr)
			if err != nil {
				continue
			}
			acct[acctKey{Addr: addr, Port: port}] = e.Elem.Counter.Bytes
		}
	}
	return acct, nil
}

func (f *nftFirewall) DeleteAcct(keys []acctKey) error {
	if len(keys) == 0 {
		return nil
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s . %d", k.Addr, k.Port))
	}
	stmt := fmt.Sprintf("delete element %s acct { %s }\n", f.table, strings.Join(parts, ", "))
	_, err := f.run(stmt, "-f", "-")
	return err
}

// concatParts extracts the components of a concatenated set-element value.
// nftables renders these as {"concat": [a, b]}, but a bare [a, b] is also
// accepted for robustness.
func concatParts(val json.RawMessage) ([]json.RawMessage, bool) {
	var wrapped struct {
		Concat []json.RawMessage `json:"concat"`
	}
	if err := json.Unmarshal(val, &wrapped); err == nil && wrapped.Concat != nil {
		return wrapped.Concat, true
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(val, &arr); err == nil {
		return arr, true
	}
	return nil, false
}

// parsePort reads an inet_service element, which nft may render as a number
// (1080) or, for well-known ports, a service name string ("socks").
func parsePort(raw json.RawMessage) (uint16, bool) {
	var n uint16
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if p, err := netip.ParseAddrPort("[::]:" + s); err == nil {
			return p.Port(), true
		}
	}
	return 0, false
}

func joinAddrs(addrs []netip.Addr) string {
	// Sorted for deterministic command strings (nicer logs/tests).
	ss := make([]string, len(addrs))
	for i, a := range addrs {
		ss[i] = a.String()
	}
	sort.Strings(ss)
	return strings.Join(ss, ", ")
}
