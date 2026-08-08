package main

import (
	"errors"
	"fmt"
	"io"
)

// Minimal server side of SOCKS5 (RFC 1928), just enough to accept the
// handshake and a CONNECT so we can read the first application bytes and
// answer plain HTTP with a redirect. We never actually proxy anything.

const (
	socksVersion = 0x05
	methodNoAuth = 0x00
	cmdConnect   = 0x01
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04

	repSucceeded             = 0x00
	repCommandNotSupported   = 0x07
	repAddressTypeNotAllowed = 0x08
)

var errNotConnect = errors.New("captive: non-CONNECT SOCKS command")

// socksAccept performs method negotiation (offering only no-auth) and reads
// the client's request. On a CONNECT it replies "succeeded" so the client
// will send its application data; on any other command it replies an error.
// It returns whether the negotiated command was CONNECT.
func socksAccept(rw io.ReadWriter) error {
	// Version/method selection: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return fmt.Errorf("captive: read greeting: %w", err)
	}
	if hdr[0] != socksVersion {
		return fmt.Errorf("captive: not SOCKS5 (ver=0x%02x)", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return fmt.Errorf("captive: read methods: %w", err)
	}
	// We only support no-auth; unauthorized clients present it (SOCKS is
	// credential-free in this system).
	if _, err := rw.Write([]byte{socksVersion, methodNoAuth}); err != nil {
		return fmt.Errorf("captive: write method reply: %w", err)
	}

	// Request: VER, CMD, RSV, ATYP, ADDR, PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(rw, req); err != nil {
		return fmt.Errorf("captive: read request: %w", err)
	}
	if req[0] != socksVersion {
		return fmt.Errorf("captive: bad request version")
	}
	if err := discardAddrPort(rw, req[3]); err != nil {
		return err
	}
	if req[1] != cmdConnect {
		writeSocksReply(rw, repCommandNotSupported)
		return errNotConnect
	}
	// Tell the client to proceed; BND.ADDR/PORT are irrelevant (we don't proxy).
	if err := writeSocksReply(rw, repSucceeded); err != nil {
		return err
	}
	return nil
}

func discardAddrPort(r io.Reader, atyp byte) error {
	var n int
	switch atyp {
	case atypIPv4:
		n = 4
	case atypIPv6:
		n = 16
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return fmt.Errorf("captive: read domain len: %w", err)
		}
		n = int(lb[0])
	default:
		return fmt.Errorf("captive: unknown ATYP 0x%02x", atyp)
	}
	if _, err := io.ReadFull(r, make([]byte, n+2)); err != nil { // +2 for PORT
		return fmt.Errorf("captive: read addr/port: %w", err)
	}
	return nil
}

func writeSocksReply(w io.Writer, rep byte) error {
	// VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
	_, err := w.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return fmt.Errorf("captive: write reply: %w", err)
	}
	return nil
}
