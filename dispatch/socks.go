package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Minimal SOCKS5 (RFC 1928) on both sides: server side toward the fips client
// (accept the no-auth handshake, read the CONNECT target) and client side
// toward the chosen upstream (Dante or Tor). We never resolve or egress here —
// the target is forwarded verbatim to the upstream, which does the real work.

const (
	ver          = 0x05
	methNoAuth   = 0x00
	methNoAccept = 0xff
	cmdConnect   = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded        = 0x00
	repGeneralFailure   = 0x01
	repNotAllowed       = 0x02
	repHostUnreachable  = 0x04
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

// errUnsupported means we already wrote the appropriate SOCKS error reply; the
// caller should just close the connection.
var errUnsupported = errors.New("dispatch: unsupported request")

// negotiate performs SOCKS5 method selection with the client, offering only
// no-auth (authentication is by fips source address, enforced in nftables
// before traffic reaches this port).
func negotiate(rw io.ReadWriter) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return fmt.Errorf("dispatch: read greeting: %w", err)
	}
	if hdr[0] != ver {
		return fmt.Errorf("dispatch: not SOCKS5 (ver=0x%02x)", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return fmt.Errorf("dispatch: read methods: %w", err)
	}
	for _, m := range methods {
		if m == methNoAuth {
			_, err := rw.Write([]byte{ver, methNoAuth})
			return err
		}
	}
	_, _ = rw.Write([]byte{ver, methNoAccept})
	return fmt.Errorf("dispatch: client offered no no-auth method")
}

// readConnect reads the client's request and returns the CONNECT target
// (ATYP, host, port). For an IP literal, host is its string form; for a domain,
// host is the name as sent (not resolved). On a valid-but-unsupported request
// (non-CONNECT command, unknown address type) it writes the matching SOCKS
// error reply and returns errUnsupported.
func readConnect(rw io.ReadWriter) (byte, string, uint16, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(rw, h); err != nil {
		return 0, "", 0, fmt.Errorf("dispatch: read request: %w", err)
	}
	if h[0] != ver {
		return 0, "", 0, fmt.Errorf("dispatch: bad request version")
	}
	atyp := h[3]

	var host string
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(rw, b); err != nil {
			return 0, "", 0, fmt.Errorf("dispatch: read ipv4: %w", err)
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(rw, b); err != nil {
			return 0, "", 0, fmt.Errorf("dispatch: read ipv6: %w", err)
		}
		host = net.IP(b).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(rw, lb); err != nil {
			return 0, "", 0, fmt.Errorf("dispatch: read domain len: %w", err)
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(rw, b); err != nil {
			return 0, "", 0, fmt.Errorf("dispatch: read domain: %w", err)
		}
		host = string(b)
	default:
		_ = writeReply(rw, repAtypNotSupported)
		return 0, "", 0, errUnsupported
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(rw, pb); err != nil {
		return 0, "", 0, fmt.Errorf("dispatch: read port: %w", err)
	}
	port := uint16(pb[0])<<8 | uint16(pb[1])

	if h[1] != cmdConnect {
		// Connect-only exit, mirroring Dante (bind/udp-associate are blocked).
		_ = writeReply(rw, repCmdNotSupported)
		return atyp, host, port, errUnsupported
	}
	return atyp, host, port, nil
}

// writeReply writes a SOCKS5 reply with a zero BND.ADDR/PORT (irrelevant for a
// failed CONNECT; on success we forward the upstream's real reply instead).
func writeReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{ver, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// dialThrough opens a SOCKS5 client connection to upstream and issues a CONNECT
// for (atyp, host, port). It returns the upstream connection and the upstream's
// raw reply bytes (including its REP code and BND fields) to relay verbatim to
// the client. The caller must check reply[1] (the REP code) and close on error.
func dialThrough(upstream string, atyp byte, host string, port uint16, timeout time.Duration) (net.Conn, []byte, error) {
	c, err := net.DialTimeout("tcp", upstream, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("dispatch: dial upstream: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(timeout))

	if _, err := c.Write([]byte{ver, 1, methNoAuth}); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("dispatch: upstream greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c, sel); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("dispatch: upstream method: %w", err)
	}
	if sel[0] != ver || sel[1] != methNoAuth {
		c.Close()
		return nil, nil, fmt.Errorf("dispatch: upstream refused no-auth")
	}

	req := []byte{ver, cmdConnect, 0x00, atyp}
	switch atyp {
	case atypDomain:
		req = append(req, byte(len(host)))
		req = append(req, host...)
	case atypIPv4:
		ip := net.ParseIP(host).To4()
		if ip == nil {
			c.Close()
			return nil, nil, fmt.Errorf("dispatch: bad ipv4 literal")
		}
		req = append(req, ip...)
	case atypIPv6:
		ip := net.ParseIP(host).To16()
		if ip == nil {
			c.Close()
			return nil, nil, fmt.Errorf("dispatch: bad ipv6 literal")
		}
		req = append(req, ip...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("dispatch: upstream request: %w", err)
	}

	reply, err := readReply(c)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, reply, nil
}

// readReply reads a full SOCKS5 reply message and returns its raw bytes, so the
// dispatcher can relay it to the client without re-encoding.
func readReply(r io.Reader) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, fmt.Errorf("dispatch: read upstream reply: %w", err)
	}
	switch h[3] {
	case atypIPv4:
		rest := make([]byte, 4+2)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, fmt.Errorf("dispatch: read upstream reply addr: %w", err)
		}
		return append(h, rest...), nil
	case atypIPv6:
		rest := make([]byte, 16+2)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, fmt.Errorf("dispatch: read upstream reply addr: %w", err)
		}
		return append(h, rest...), nil
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, fmt.Errorf("dispatch: read upstream reply domain len: %w", err)
		}
		rest := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, fmt.Errorf("dispatch: read upstream reply domain: %w", err)
		}
		return append(append(h, lb...), rest...), nil
	default:
		return nil, fmt.Errorf("dispatch: upstream reply bad ATYP 0x%02x", h[3])
	}
}
