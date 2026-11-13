//! The P-256 of nrf-ble's LE Secure Connections pairing: the private key
//! from random octets, its public key, the check of the central's public key
//! and the Diffie-Hellman key, all of it that of the
//! `RustCrypto` `p256` crate.
//!
//! The crate exists for the build, not for the code. `p256` reaches its
//! scalar multiplication through generic code of `primeorder` and
//! `elliptic-curve`, and a generic function is compiled in the crate that
//! instantiates it, with that crate's opt-level: called from nrf-ble, the
//! point arithmetic was nrf-ble's code, built at the firmware's opt-level 3
//! even with `p256` and the crates below it at "z" (about 34 KB more flash
//! on the nRF52832 firmwares than here). This crate is the only one that uses
//! `p256`, and its API is not generic: plain byte arrays and two opaque key
//! types, no type parameters, no closures, no type of `p256` in a signature.
//! Each entry point is `#[inline(never)]`, so its body, and every generic
//! function of `p256`, `primeorder` and `elliptic-curve` it instantiates, is
//! compiled here, and a firmware sets the opt-level of all of pairing's
//! elliptic curve cryptography with profile overrides of this crate and of
//! the five `RustCrypto` crates below it (the readme gives the lines), while
//! nrf-ble's link layer and the firmware stay at theirs.
//!
//! Byte order: the private key, each coordinate and the Diffie-Hellman key
//! most significant octet first, and a public key X then Y, as nrf-ble's
//! security manager holds them (the Pairing Public Key PDU carries each
//! coordinate the other way round; nrf-ble reverses them).
//!
//! What `p256` does here, through its public API only:
//!
//! - The private key is `p256::SecretKey::from_bytes`, which refuses zero and
//!   anything not below the order of the curve, and overwrites itself when it
//!   is dropped.
//! - The public key is `SecretKey::public_key`, the generator times the private
//!   key.
//! - A public key from its coordinates is `AffinePoint::from_coordinates`,
//!   which refuses a coordinate not below the field prime and a point off the
//!   curve, and `PublicKey::from_affine`, which refuses the identity. P-256 has
//!   a cofactor of 1, so every other point has the prime order and needs no
//!   subgroup check.
//! - The Diffie-Hellman key is `SecretKey::diffie_hellman`, the X coordinate of
//!   the private key times the central's public key, whose `SharedSecret`
//!   overwrites itself when it is dropped, before the function returns.
//!
//! What stays with nrf-ble: the checks the Core specification adds (the
//! debug public key and our own public key are refused), the firmware's
//! watchdog hook before each multiplication, overwriting the caller's
//! octets of the private key and the Diffie-Hellman key it gets from here,
//! and its own API. nrf-ble's module `host::smp::ecc` and its readme, section
//! "Cryptography of pairing", describe the crates' claims about constant
//! time, what is overwritten and what stays on the stack, and the time a
//! multiplication takes.

#![no_std]

use p256::{AffinePoint, FieldBytes, PublicKey as Point, SecretKey as Scalar, elliptic_curve::point};

/// Octets of a private key, of one coordinate and of the Diffie-Hellman key.
pub const KEY_LEN: usize = 32;

/// Octets of a public key: X then Y.
pub const PUBLIC_KEY_LEN: usize = 64;

/// A public key: a point of the curve other than the identity, checked by
/// [`PublicKey::from_coordinates`].
pub struct PublicKey {
    /// The point.
    point: Point,
}

impl PublicKey {
    /// The public key of the coordinates `key`, X then Y, or `None` if a
    /// coordinate is not below the field prime or the coordinates do not
    /// satisfy the curve equation. The identity has no coordinates, so it is
    /// never a public key. Costs no multiplication.
    #[inline(never)]
    #[must_use = "the key is only checked"]
    pub fn from_coordinates(key: &[u8; PUBLIC_KEY_LEN]) -> Option<Self> {
        let (x, rest) = key.split_first_chunk::<KEY_LEN>()?;
        let y = rest.first_chunk::<KEY_LEN>()?;
        let on_curve: Option<AffinePoint> =
            <AffinePoint as point::AffineCoordinates>::from_coordinates(x.into(), y.into()).into();
        let point = Point::from_affine(on_curve?).ok()?;
        Some(Self { point })
    }
}

/// A private key, from 1 to the order of the curve less 1. It overwrites
/// itself when it is dropped.
pub struct SecretKey {
    /// The scalar.
    scalar: Scalar,
}

impl SecretKey {
    /// The Diffie-Hellman key of this private key and the public key `peer`:
    /// the X coordinate of their product. One multiplication.
    ///
    /// The shared secret of `p256` overwrites itself before this returns; the
    /// returned copy is the caller's to overwrite.
    #[inline(never)]
    #[must_use = "the key is only computed"]
    pub fn diffie_hellman(&self, peer: &PublicKey) -> [u8; KEY_LEN] {
        let shared = self.scalar.diffie_hellman(&peer.point);
        (*shared.raw_secret_bytes()).into()
    }

    /// The private key of the octets `secret`, or `None` if they are zero or
    /// not below the order of the curve, as about one in four billion random
    /// ones are. Costs no multiplication. `secret` is the caller's to
    /// overwrite; this makes no copy of it outside the key.
    #[inline(never)]
    #[must_use = "the key is only checked"]
    pub fn from_bytes(secret: &[u8; KEY_LEN]) -> Option<Self> {
        let repr: &FieldBytes = secret.into();
        let scalar = Scalar::from_bytes(repr).ok()?;
        Some(Self { scalar })
    }

    /// The public key, X then Y: the generator times this private key. One
    /// multiplication.
    #[inline(never)]
    #[must_use = "the key is only computed"]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        let point = self.scalar.public_key();
        let affine = point.as_affine();
        let mut out = [0; PUBLIC_KEY_LEN];
        if let Some((x, rest)) = out.split_first_chunk_mut::<KEY_LEN>() {
            *x = point::AffineCoordinates::x(affine).into();
            if let Some(y) = rest.first_chunk_mut::<KEY_LEN>() {
                *y = point::AffineCoordinates::y(affine).into();
            }
        }
        out
    }
}

#[cfg(test)] mod tests;
