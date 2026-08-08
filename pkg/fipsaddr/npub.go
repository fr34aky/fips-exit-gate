package fipsaddr

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// NIP-19 npub handling: classic Bech32 (BIP-173), HRP "npub", 32-byte payload
// that must be a valid secp256k1 x-only public key. Implemented here with the
// stdlib only to keep the package dependency-free.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var (
	// ErrNotNpub is returned for inputs whose human-readable part is not "npub".
	ErrNotNpub = errors.New("fipsaddr: not an npub (wrong bech32 prefix)")
	// ErrInvalidPubkey is returned when the 32-byte payload is not a valid
	// secp256k1 x-only public key.
	ErrInvalidPubkey = errors.New("fipsaddr: payload is not a valid secp256k1 x-only pubkey")
)

// secp256k1 field prime p = 2^256 - 2^32 - 977, and (p+1)/4 for the
// Tonelli-Shanks shortcut valid because p ≡ 3 (mod 4).
var (
	secpP     *big.Int
	secpPExp  *big.Int
	secpSeven = big.NewInt(7)
)

func init() {
	secpP, _ = new(big.Int).SetString(
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	secpPExp = new(big.Int).Rsh(new(big.Int).Add(secpP, big.NewInt(1)), 2)
}

// DecodeNpub decodes a NIP-19 "npub1..." string into a 32-byte x-only pubkey,
// verifying the bech32 checksum and that the payload is a valid curve point.
func DecodeNpub(npub string) ([32]byte, error) {
	var out [32]byte
	hrp, data, err := bech32Decode(npub)
	if err != nil {
		return out, err
	}
	if hrp != "npub" {
		return out, ErrNotNpub
	}
	payload, err := convertBits(data, 5, 8, false)
	if err != nil {
		return out, fmt.Errorf("fipsaddr: %w", err)
	}
	if len(payload) != 32 {
		return out, fmt.Errorf("fipsaddr: npub payload is %d bytes, want 32", len(payload))
	}
	copy(out[:], payload)
	if !validXOnly(out) {
		return out, ErrInvalidPubkey
	}
	return out, nil
}

// EncodeNpub encodes a 32-byte x-only pubkey as a NIP-19 npub string.
func EncodeNpub(pubkey [32]byte) string {
	data, _ := convertBits(pubkey[:], 8, 5, true)
	return bech32Encode("npub", data)
}

// validXOnly reports whether x is a valid secp256k1 x-coordinate:
// x < p and x^3 + 7 is a quadratic residue mod p.
func validXOnly(pubkey [32]byte) bool {
	x := new(big.Int).SetBytes(pubkey[:])
	if x.Cmp(secpP) >= 0 {
		return false
	}
	rhs := new(big.Int).Exp(x, big.NewInt(3), secpP)
	rhs.Add(rhs, secpSeven).Mod(rhs, secpP)
	y := new(big.Int).Exp(rhs, secpPExp, secpP)
	y.Mul(y, y).Mod(y, secpP)
	return y.Cmp(rhs) == 0
}

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("fipsaddr: bech32 string uses mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("fipsaddr: malformed bech32 string")
	}
	hrp := s[:pos]
	data := make([]byte, 0, len(s)-pos-1)
	for i := pos + 1; i < len(s); i++ {
		idx := strings.IndexByte(bech32Charset, s[i])
		if idx < 0 {
			return "", nil, fmt.Errorf("fipsaddr: invalid bech32 character %q", s[i])
		}
		data = append(data, byte(idx))
	}
	if bech32Polymod(append(bech32HrpExpand(hrp), data...)) != 1 {
		return "", nil, errors.New("fipsaddr: bech32 checksum mismatch")
	}
	return hrp, data[:len(data)-6], nil
}

func bech32Encode(hrp string, data []byte) string {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range data {
		sb.WriteByte(bech32Charset[d])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[(polymod>>uint(5*(5-i)))&31])
	}
	return sb.String()
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc, bits uint32
	maxv := uint32(1)<<toBits - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	for _, v := range data {
		if uint32(v)>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data value %d for %d-bit group", v, fromBits)
		}
		acc = acc<<fromBits | uint32(v)
		bits += uint32(fromBits)
		for bits >= uint32(toBits) {
			bits -= uint32(toBits)
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(uint32(toBits)-bits)&maxv))
		}
	} else if bits >= uint32(fromBits) || acc<<(uint32(toBits)-bits)&maxv != 0 {
		return nil, errors.New("invalid bech32 padding")
	}
	return out, nil
}
