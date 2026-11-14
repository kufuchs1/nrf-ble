# nrf-ble-p256

The P-256 elliptic curve cryptography of nrf-ble's LE Secure Connections pairing, as a crate of its own in the nrf-ble
repository (`p256/`), a path dependency of nrf-ble. A firmware that takes nrf-ble from Git gets it from the same
repository and revision; it never names it as a dependency itself.

It is the only crate of nrf-ble that uses the RustCrypto `p256` crate (with `arithmetic` and `ecdh`, without
`precomputed-tables`), and it has four entry points, all on plain byte arrays, most significant octet first:

| Entry point | What it does | Multiplications |
|---|---|---|
| `SecretKey::from_bytes(&[u8; 32]) -> Option<SecretKey>` | The private key, refused when zero or not below the order of the curve | none |
| `SecretKey::public_key(&self) -> [u8; 64]` | The public key, X then Y: the generator times the private key | one |
| `PublicKey::from_coordinates(&[u8; 64]) -> Option<PublicKey>` | The central's key, refused when a coordinate is not below the field prime or the point is not on the curve (the identity has no coordinates) | none |
| `SecretKey::diffie_hellman(&self, &PublicKey) -> [u8; 32]` | The Diffie-Hellman key, the X coordinate of the product | one |

`SecretKey` and `PublicKey` are opaque; `SecretKey` (`p256::SecretKey`) overwrites itself when it is dropped, and the
shared secret of the Diffie-Hellman key overwrites itself before `diffie_hellman` returns. Everything around it stays
in nrf-ble (`host::smp::ecc`): the debug key and our own key refused as the central's key, the firmware's watchdog hook
before each multiplication, overwriting the caller's octets, and nrf-ble's own API, which is unchanged. nrf-ble's
readme, section "Cryptography of pairing", describes what the crates claim about constant time and what stays on the
stack.

## Why a crate of its own

For the build, not for the code. A Cargo profile override sets the opt-level of a package, and a generic function is
compiled in the crate that instantiates it, with that crate's opt-level. The scalar multiplication of `p256` is
generic code of `primeorder` and `elliptic-curve` (`ProjectivePoint::mul`, `ProjectivePoint::add`,
`LookupTable::select`, `SecretKey::public_key`, `diffie_hellman`), instantiated for `NistP256` by whoever calls it.
When nrf-ble called `p256` itself, all of that was nrf-ble's code and was built at nrf-ble's opt-level, which the
firmwares keep at 3 for the link layer's timing: about 25.8 KB of flash on the nRF52832 firmwares even with `p256`,
`primeorder`, `primefield`, `crypto-bigint` and `elliptic-curve` overridden to "z".

Here the API has no type parameters, no closures and no type of `p256` in a signature, and each entry point is
`#[inline(never)]`. So its body, and every generic function it instantiates, is compiled in this crate, and nothing of
`p256` is instantiated in nrf-ble (nrf-ble only drops the private key, the zeroing of 32 octets). The opt-level of all
of pairing's elliptic curve code is then this crate's and the five RustCrypto crates' own, and a firmware can build
that code for size while the firmware and nrf-ble, link layer included, stay at opt-level 3. The code is only run by
nrf-ble's crypto task, a pairing's two multiplications, outside the link layer and its timing.

Measured on the MX Master 3S and MX Keys S firmwares (nRF52832, fat LTO, opt-level 3) with the lines below: about
34.4 KB less flash than with `p256` called from nrf-ble and the five crates at "z", in the release build and every
logging build, and 8.5 KB to 8.9 KB less than nrf-ble's own P-256 code before the crates.

## In a firmware

Profile settings apply only in the workspace being built, so nrf-ble cannot set them; a firmware that uses nrf-ble
adds to its own Cargo.toml (a profile that inherits `release`, such as a logging profile, inherits them):

```toml
# The P-256 of nrf-ble's pairing for size: nrf-ble-p256 holds the point
# arithmetic (generic code of primeorder and elliptic-curve), the five
# RustCrypto crates the field and integer arithmetic below it. Only nrf-ble's
# crypto task runs it; the firmware and nrf-ble stay at their opt-level.
[profile.release.package.nrf-ble-p256]
opt-level = "z"
[profile.release.package.p256]
opt-level = "z"
[profile.release.package.primeorder]
opt-level = "z"
[profile.release.package.primefield]
opt-level = "z"
[profile.release.package.crypto-bigint]
opt-level = "z"
[profile.release.package.elliptic-curve]
opt-level = "z"
```

nrf-ble's readme, section "Cryptography of pairing", gives the flash this takes in the firmwares, and the time and
size of "s" in place of "z".

## Tests

`cargo test -p nrf-ble-p256` in the nrf-ble repository: the debug key pair and P-256 data sets 1 and 2 of the Core
specification (volume 2, part G, section 7.1.2; volume 3, part H, section 2.3.5.6.1) both ways, scalars at the edges
of the digit recoding and 64 seeded random scalar pairs against `p256` used directly, private keys of zero, the order,
above it and the field prime refused, and public keys refused off the curve or with a coordinate not below the field
prime whose reduced value would be a point of the curve, beside the points at the edges that are taken. The crate
has nrf-ble's lints (the workspace's, in nrf-ble's Cargo.toml).

## License

MIT or Apache-2.0, as nrf-ble ([LICENSE-MIT](../LICENSE-MIT), [LICENSE-APACHE](../LICENSE-APACHE)).
