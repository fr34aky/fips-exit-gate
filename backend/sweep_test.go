package main

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type countingRecomputer struct{ calls atomic.Int32 }

func (c *countingRecomputer) RecomputeAuthz(context.Context) ([]netip.Addr, int64, error) {
	c.calls.Add(1)
	return nil, 0, nil
}

func TestExpirySweepRecomputesOnTimer(t *testing.T) {
	rc := &countingRecomputer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runExpirySweep(ctx, rc, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for rc.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if rc.calls.Load() < 3 {
		t.Fatalf("expected at least 3 recomputes, got %d", rc.calls.Load())
	}
}

func TestExpirySweepDisabledWhenZero(t *testing.T) {
	rc := &countingRecomputer{}
	runExpirySweep(context.Background(), rc, 0) // must return immediately
	if rc.calls.Load() != 0 {
		t.Fatal("sweep ran with interval 0")
	}
}

func TestRevWaiterBroadcastWakesWaiters(t *testing.T) {
	w := newRevWaiter()
	ch := w.wait()
	select {
	case <-ch:
		t.Fatal("fired before broadcast")
	default:
	}
	w.broadcast()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("broadcast did not close the channel")
	}
	var nilw *revWaiter
	if nilw.wait() != nil {
		t.Fatal("nil waiter should return a nil channel")
	}
	nilw.broadcast() // must not panic
}
