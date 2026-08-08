# npub → fips address derivation

Verified against the reference implementation in
[jmcorgan/fips](https://github.com/jmcorgan/fips):
`src/identity/node_addr.rs`, `src/identity/address.rs`,
`src/identity/encoding.rs`.

## Specification

1. **npub decode** — NIP-19: classic Bech32 (BIP-173, not bech32m), HRP
   `npub`, payload exactly 32 bytes, which must be a valid secp256k1 x-only
   public key (x < p and x³+7 a quadratic residue mod p).
2. **node_addr** — first 16 bytes of `SHA-256(pubkey)`. Hashing prevents
   grinding attacks on secp256k1's algebraic structure.
3. **fips address** — `0xfd || node_addr[0..15]`: one prefix byte plus the
   first 15 bytes of node_addr → an IPv6 address in **fd00::/8**.

Notes:

- Only the `fd`-prefixed half of the RFC 4193 ULA space is fips; `fc00::/8`
  is not.
- The mapping npub → address is deterministic and collision-resistant
  (120 bits), but **not reversible** — the backend must derive and store the
  address for every known npub (owners and whitelisted npubs) to resolve
  source addresses back to accounts.

## Go implementation

`pkg/fipsaddr` (stdlib-only). Key functions: `FromNpub`, `FromPubkey`,
`NodeAddr`, `DecodeNpub`/`EncodeNpub`, `Valid`, `CheckDerivation`.

## Test vectors

Cross-generated with an independent Python implementation; vector 1 is the
NIP-19 spec example, 2–3 are the NIP-06 test-vector keys.

| npub | node_addr (hex) | fips address |
|---|---|---|
| `npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6` | `1093b285866046e42dc0893228ccffb4` | `fd10:93b2:8586:6046:e42d:c089:3228:ccff` |
| `npub1l2vyh47mk2p0qlsku7hg0vn29faehy9hy34ygaclpn66ukqp3afqutajft` | `54dc855ad5c438acd60aa8849513dd18` | `fd54:dc85:5ad5:c438:acd6:aa8:8495:13dd` |
| `npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu` | `e4f76c66657548be8645ec3f9bfbb58c` | `fde4:f76c:6665:7548:be86:45ec:3f9b:fbb5` |

**TODO before Phase 1 completes:** validate at least one vector against a
running fips node (compare `fipsctl` / node log output for a known nsec).
