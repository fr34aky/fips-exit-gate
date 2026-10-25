package main

import (
	"net"
	"testing"
	"time"
)

// relayDone runs relay in the background and reports when it returns.
func relayDone(a, b net.Conn, idle, maxLife time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() { relay(a, b, idle, maxLife); close(done) }()
	return done
}

func TestRelayIdleTimeoutClosesTunnel(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	done := relayDone(a1, b1, 100*time.Millisecond, 0)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end after idle timeout")
	}
}

func TestRelayMaxLifetimeClosesActiveTunnel(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	done := relayDone(a1, b1, 0, 150*time.Millisecond)
	// Keep traffic flowing so only the lifetime bound can end it.
	go func() {
		buf := make([]byte, 4)
		for {
			if _, err := a2.Write([]byte("ping")); err != nil {
				return
			}
			if _, err := b2.Read(buf); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end after max lifetime")
	}
}

func TestRelayActivityDefersIdleTimeout(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	done := relayDone(a1, b1, 200*time.Millisecond, 0)
	buf := make([]byte, 4)
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := a2.Write([]byte("ping")); err != nil {
			t.Fatalf("write during active tunnel: %v", err)
		}
		if _, err := b2.Read(buf); err != nil {
			t.Fatalf("read during active tunnel: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("relay ended while traffic was flowing")
	default:
	}
	// Go quiet: now the idle bound should end it.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end after traffic stopped")
	}
}

func TestRelayEndsWhenPeerCloses(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer b2.Close()
	done := relayDone(a1, b1, time.Hour, time.Hour)
	a2.Close()
	// net.Pipe has no CloseWrite, so the b side only ends once b2 closes too.
	b2.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end after both peers closed")
	}
}

func TestWatchdogInterval(t *testing.T) {
	if got := watchdogInterval(0, 0); got != 5*time.Second {
		t.Fatalf("no bounds: got %v", got)
	}
	if got := watchdogInterval(time.Second, 0); got != 250*time.Millisecond {
		t.Fatalf("idle 1s: got %v", got)
	}
	if got := watchdogInterval(0, 20*time.Millisecond); got != 10*time.Millisecond {
		t.Fatalf("floor: got %v", got)
	}
}
