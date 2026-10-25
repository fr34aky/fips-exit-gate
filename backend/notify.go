package main

import "sync"

// revWaiter fans a "the authz revision changed" signal out to every waiting
// long-poll. wait() hands back a channel that is closed on the next broadcast;
// callers select on it next to their deadline and a slow fallback poll, so a
// missed notification only costs latency, never correctness.
type revWaiter struct {
	mu sync.Mutex
	ch chan struct{}
}

func newRevWaiter() *revWaiter { return &revWaiter{ch: make(chan struct{})} }

// wait returns a channel closed by the next broadcast. On a nil receiver it
// returns nil, which never fires (tests and the fake backend run without a
// listener and rely on the fallback poll alone).
func (w *revWaiter) wait() <-chan struct{} {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ch
}

// broadcast wakes every current waiter.
func (w *revWaiter) broadcast() {
	if w == nil {
		return
	}
	w.mu.Lock()
	close(w.ch)
	w.ch = make(chan struct{})
	w.mu.Unlock()
}
