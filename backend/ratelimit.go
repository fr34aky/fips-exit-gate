package main

import (
	"sync"
	"time"
)

// rateLimiter is a small per-key token bucket for portal actions that create
// rows or external side effects (invitations, purchases). In-memory and
// per-process: good enough to stop a script from hammering a form, not a
// substitute for network-level limits.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	burst   float64
	perSec  float64
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter allows `burst` actions at once per key, refilling at
// burst/per (e.g. 10 per 10 min).
func newRateLimiter(burst int, per time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets: map[string]*bucket{},
		burst:   float64(burst),
		perSec:  float64(burst) / per.Seconds(),
		now:     time.Now,
	}
}

// allow consumes one token for key if available.
func (l *rateLimiter) allow(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 10000 {
			l.prune(now)
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.perSec
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune drops buckets that have fully refilled (idle long enough to be fresh).
func (l *rateLimiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst {
			delete(l.buckets, k)
		}
	}
}
