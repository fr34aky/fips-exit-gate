//go:build !linux

package main

import (
	"net"
	"time"
)

// sinceLastRecv has no portable implementation; the idle bound is then not
// enforced (the exit runs on Linux).
func sinceLastRecv(net.Conn) (time.Duration, bool) { return 0, false }
