//go:build linux

package main

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// sinceLastRecv returns how long the TCP socket behind c has gone without
// receiving data (TCP_INFO tcpi_last_data_recv, millisecond resolution). ok is
// false for non-TCP conns or when the query fails.
func sinceLastRecv(c net.Conn) (d time.Duration, ok bool) {
	tc, isTCP := c.(*net.TCPConn)
	if !isTCP {
		return 0, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var info *unix.TCPInfo
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		info, gerr = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
	}); err != nil || gerr != nil || info == nil {
		return 0, false
	}
	return time.Duration(info.Last_data_recv) * time.Millisecond, true
}
