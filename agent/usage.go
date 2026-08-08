package main

import (
	"fmt"
	"net/netip"
)

// baselineKey is the persisted-map key for a per-(addr,port) counter baseline.
func baselineKey(k acctKey) string {
	return fmt.Sprintf("%s|%d", k.Addr, k.Port)
}

// computeDelta turns absolute nftables counters into per-service usage samples.
//
// For each accounting element it subtracts the stored baseline; a current value
// below the baseline means the kernel counter was reset (set flush / element
// recreated), so the whole current value is the delta. It returns the samples
// (only positive ones) and the new baseline map to persist.
//
// services maps a service port to its catalog key; unknown ports are labeled
// so traffic is never silently dropped from accounting.
func computeDelta(prev map[string]uint64, cur map[acctKey]uint64, services map[uint16]string) ([]usageSample, map[string]uint64) {
	samples := make([]usageSample, 0, len(cur))
	next := make(map[string]uint64, len(cur))
	for k, absBytes := range cur {
		bk := baselineKey(k)
		next[bk] = absBytes
		last := prev[bk]
		var delta uint64
		if absBytes >= last {
			delta = absBytes - last
		} else {
			delta = absBytes // counter reset since last read
		}
		if delta == 0 {
			continue
		}
		svc, ok := services[k.Port]
		if !ok {
			svc = fmt.Sprintf("unknown:%d", k.Port)
		}
		samples = append(samples, usageSample{Service: svc, Addr: k.Addr, Bytes: delta})
	}
	return samples, next
}

// diffAuthorized computes the add/remove needed to turn `current` into `desired`.
func diffAuthorized(current, desired map[netip.Addr]struct{}) (add, del []netip.Addr) {
	for a := range desired {
		if _, ok := current[a]; !ok {
			add = append(add, a)
		}
	}
	for a := range current {
		if _, ok := desired[a]; !ok {
			del = append(del, a)
		}
	}
	return add, del
}
