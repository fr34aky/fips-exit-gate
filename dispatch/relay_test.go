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

func TestRelayMaxLifetimeClosesActiveTunnel(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer a2.Close()
	defer b2.Close()
	done := relayDone(a1, b1, 0, 150*time.Millisecond)
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

// Conn types without a kernel idle signal (net.Pipe in tests) are never cut
// by the idle bound: the watchdog bows out rather than guessing.
func TestRelayIdleBoundNotEnforcedWithoutSignal(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := relayDone(a1, b1, 100*time.Millisecond, 0)
	select {
	case <-done:
		t.Fatal("relay ended on a conn type with no idle signal")
	case <-time.After(1500 * time.Millisecond):
	}
	a2.Close()
	b2.Close()
	<-done
}

func TestRelayEndsWhenPeerCloses(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	defer b2.Close()
	done := relayDone(a1, b1, time.Hour, time.Hour)
	a2.Close()
	b2.Close() // net.Pipe has no CloseWrite, so the b side only ends once b2 closes too
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end after both peers closed")
	}
}
