package main

import (
	"testing"
	"time"
)

func TestRateLimiterBurstAndRefill(t *testing.T) {
	l := newRateLimiter(3, 30*time.Second) // 3 per 30 s = one every 10 s
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.allow("a") {
			t.Fatalf("burst call %d denied", i)
		}
	}
	if l.allow("a") {
		t.Fatal("fourth call within burst allowed")
	}
	if !l.allow("b") {
		t.Fatal("other key must have its own bucket")
	}
	now = now.Add(10 * time.Second)
	if !l.allow("a") {
		t.Fatal("one token should have refilled after 10s")
	}
	if l.allow("a") {
		t.Fatal("only one token should have refilled")
	}
	var nilLimiter *rateLimiter
	if !nilLimiter.allow("x") {
		t.Fatal("nil limiter must allow")
	}
}
