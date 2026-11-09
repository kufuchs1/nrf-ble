//! P-256 for LE Secure Connections: the key pair, the check of the central's
//! public key and the Diffie-Hellman key.
//!
//! Keys are in the byte order of the toolbox: the private key, each
//! coordinate and the Diffie-Hellman key most significant octet first, and a
//! public key as X then Y, the order the Pairing Public Key PDU carries them
//! in. The PDU carries each coordinate least significant octet first, so the
//! security manager reverses each one on the way in and out.
//!
//! The field and point arithmetic is that of the `p256` crate, in pure Rust
//! and without tables kept in RAM; the scalar multiplication loop is our own,
//! a fixed window of signed radix 16 digits on `ProjectivePoint` with a
//! table of 8 points selected in constant time, as `p256` does, but with the
//! table on the multiplication's own frame and the point formulas called
//! rather than inlined into the loop. The research benchmark of
//! research-crypto.md, on an emulated nRF51 at opt level "z", found this loop
//! as fast as `ProjectivePoint::mul` (2.94 s against 2.93 s per
//! multiplication), with about 0.5 KB less stack (2.65 KB against 3.13 to
//! 3.22 KB for the whole call) and about 0.2 KB less flash. These figures
//! were not measured on this crate and are still to be checked on the chip.
//! Public key and Diffie-Hellman key go through the same multiplication, so
//! there is one copy of it.
//!
//! Secrets are overwritten once they are no longer needed: the private key
//! when the [`KeyPair`] is dropped, the caller's random octets by
//! [`KeyPair::generate`], and the recoded private key and the products on
//! the multiplication's own frame. The Diffie-Hellman key that
//! [`KeyPair::dh_key`] returns is the caller's to wipe, once f5 has derived
//! the keys from it.
//!
//! Each multiplication blocks the thread for about 3 s on the nRF51, so the
//! security manager runs them as jobs outside its state machine, and each
//! call here takes a hook it calls right before its multiplication, for the
//! firmware to feed its watchdog.

use crate::crypto::wipe;
use core::{
    hint::black_box,
    sync::atomic::{Ordering, compiler_fence},
};
use p256::{
    AffinePoint,
    FieldBytes,
    NonZeroScalar,
    ProjectivePoint,
    elliptic_curve::{
        group::Group as _,
        point::AffineCoordinates as _,
        subtle::{Choice, ConditionallySelectable as _, ConstantTimeEq as _},
    },
};

/// Octets of a private key, of one coordinate and of the Diffie-Hellman key.
pub const KEY_LEN: usize = 32;

/// Octets of a public key: X then Y.
pub const PUBLIC_KEY_LEN: usize = 64;

/// The public key of the debug key pair (Core specification, volume 3, part
/// H, section 2.3.5.6.1), X then Y. Its private key is public, so a central
/// that sends it, or its negation, is refused.
pub const DEBUG_PUBLIC_KEY: [u8; PUBLIC_KEY_LEN] = [
    0x20, 0xB0, 0x03, 0xD2, 0xF2, 0x97, 0xBE, 0x2C, 0x5E, 0x2C, 0x83, 0xA7, 0xE9, 0xF9, 0xA5, 0xB9, 0xEF, 0xF4, 0x91,
    0x11, 0xAC, 0xF4, 0xFD, 0xDB, 0xCC, 0x03, 0x01, 0x48, 0x0E, 0x35, 0x9D, 0xE6, 0xDC, 0x80, 0x9C, 0x49, 0x65, 0x2A,
    0xEB, 0x6D, 0x63, 0x32, 0x9A, 0xBF, 0x5A, 0x52, 0x15, 0x5C, 0x76, 0x63, 0x45, 0xC2, 0x8F, 0xED, 0x30, 0x24, 0x74,
    0x1C, 0x8E, 0xD0, 0x15, 0x89, 0xD2, 0x8B,
];

/// Signed radix 16 digits of a scalar: two per octet, and one for the carry
/// out of the most significant one.
const DIGITS: usize = 2 * KEY_LEN + 1;

/// Why a public key is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum KeyError {
    /// The key is the debug public key or its negation, whose private key
    /// is known.
    Debug,
    /// The key is not a point of the curve: a coordinate is not below the
    /// field prime, or the coordinates do not satisfy the curve equation.
    /// The identity has no coordinates, so it is never a public key.
    Invalid,
    /// The key is our own public key or its negation, which a central only
    /// sends to reflect our own values back to us.
    Own,
}

/// Our key pair for one pairing: the private key and the public key it
/// gives, 96 octets. The private key is overwritten when it is dropped.
pub struct KeyPair {
    /// The public key, X then Y.
    public: [u8; PUBLIC_KEY_LEN],
    /// The private key, from 1 to the order of the curve less 1.
    secret: [u8; KEY_LEN],
}

impl KeyPair {
    /// The Diffie-Hellman key of our private key and the central's public
    /// key `peer`: the X coordinate of their product.
    ///
    /// `peer` is checked first (see [`check_public_key`]); a refused key
    /// costs no multiplication. Otherwise `before_multiplication` is called,
    /// right before the multiplication.
    ///
    /// # Errors
    ///
    /// The reason `peer` is refused.
    #[inline]
    pub fn dh_key<F>(&self, peer: &[u8; PUBLIC_KEY_LEN], before_multiplication: F) -> Result<[u8; KEY_LEN], KeyError>
    where
        F: FnOnce(),
    {
        let point = decode(peer, &self.public)?;
        before_multiplication();
        let mut product = multiply(&self.secret, &ProjectivePoint::from(point));
        let key = x_coordinate(&product).ok_or(KeyError::Invalid);
        clear(&mut product);
        key
    }

    /// The key pair of the private key `secret`, random octets, or `None` if
    /// they are zero or not below the order of the curve, as about one in
    /// four billion are: then the caller draws new ones.
    ///
    /// `secret` is overwritten with zeros either way, so the caller's copy
    /// of the private key does not stay in RAM.
    ///
    /// `before_multiplication` is called right before the multiplication,
    /// and not at all if `secret` is refused.
    #[inline]
    #[must_use = "the key pair is only computed"]
    pub fn generate<F>(secret: &mut [u8; KEY_LEN], before_multiplication: F) -> Option<Self>
    where
        F: FnOnce(),
    {
        let mut pair = Self { public: [0; PUBLIC_KEY_LEN], secret: *secret };
        wipe(secret);
        let mut repr = FieldBytes::from(pair.secret);
        let valid = bool::from(NonZeroScalar::from_repr(repr).is_some());
        wipe(&mut repr);
        if !valid {
            return None;
        }
        before_multiplication();
        let mut product = multiply(&pair.secret, &ProjectivePoint::GENERATOR);
        let public = encode(&product);
        clear(&mut product);
        pair.public = public?;
        Some(pair)
    }

    /// The public key, X then Y.
    #[inline]
    #[must_use = "the key is only borrowed"]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] { &self.public }
}

impl Drop for KeyPair {
    #[inline]
    fn drop(&mut self) { wipe(&mut self.secret); }
}

/// Adds `term` to `sum`, outside the loop, so the formulas are not inlined
/// into it and their frame does not add to the loop's.
#[inline(never)]
fn add_in_place(sum: &mut ProjectivePoint, term: &ProjectivePoint) { *sum = sum.add(term); }

/// Checks the central's public key `peer` against our own public key `own`.
///
/// The key must be a point of the curve, and neither the debug public key
/// nor our own, nor their negations. The security manager checks it when
/// the Pairing Public Key PDU arrives, before the Diffie-Hellman key job.
///
/// # Errors
///
/// The reason `peer` is refused.
#[inline]
pub fn check_public_key(peer: &[u8; PUBLIC_KEY_LEN], own: &[u8; PUBLIC_KEY_LEN]) -> Result<(), KeyError> {
    decode(peer, own).map(drop)
}

/// The point of the central's public key `peer`, checked as
/// [`check_public_key`] describes.
///
/// A key and its negation share their X coordinate, which is all the
/// Diffie-Hellman key depends on, so the debug key and our own key are
/// recognised by X alone.
fn decode(peer: &[u8; PUBLIC_KEY_LEN], own: &[u8; PUBLIC_KEY_LEN]) -> Result<AffinePoint, KeyError> {
    let (x, rest) = peer.split_first_chunk::<KEY_LEN>().ok_or(KeyError::Invalid)?;
    let y = rest.first_chunk::<KEY_LEN>().ok_or(KeyError::Invalid)?;
    if Some(x) == DEBUG_PUBLIC_KEY.first_chunk::<KEY_LEN>() {
        return Err(KeyError::Debug);
    }
    if Some(x) == own.first_chunk::<KEY_LEN>() {
        return Err(KeyError::Own);
    }
    // The coordinates are taken only below the field prime, and the point
    // only if it satisfies the curve equation.
    let point: Option<AffinePoint> = AffinePoint::from_coordinates(&FieldBytes::from(*x), &FieldBytes::from(*y)).into();
    point.filter(|valid| !bool::from(valid.is_identity())).ok_or(KeyError::Invalid)
}

/// Overwrites `point`, which depends on a private key, with the identity,
/// so it does not stay in RAM.
fn clear(point: &mut ProjectivePoint) {
    *point = ProjectivePoint::IDENTITY;
    // As in `wipe`: keeps the compiler from dropping the store.
    black_box(point);
    compiler_fence(Ordering::SeqCst);
}

/// Doubles `point`, outside the loop, as [`add_in_place`] adds.
#[inline(never)]
fn double_in_place(point: &mut ProjectivePoint) { *point = point.double(); }

/// The affine coordinates of `point`, X then Y, or `None` for the identity.
#[inline(never)]
fn encode(point: &ProjectivePoint) -> Option<[u8; PUBLIC_KEY_LEN]> {
    let affine = point.to_affine();
    if bool::from(affine.is_identity()) {
        return None;
    }
    let mut out = [0; PUBLIC_KEY_LEN];
    for (target, &octet) in out.iter_mut().zip(affine.x().iter().chain(affine.y().iter())) {
        *target = octet;
    }
    Some(out)
}

/// `secret` times `base`, in constant time: `secret` must be from 1 to the
/// order of the curve less 1.
///
/// The table holds 1 to 8 times `base`; each digit, from the most
/// significant, takes four doublings and the addition of the table entry
/// of its magnitude, negated for a negative digit. The digits, which are
/// the private key in another form, and the term are overwritten before it
/// returns, and so is its copy of the product; the caller clears its own.
#[inline(never)]
fn multiply(secret: &[u8; KEY_LEN], base: &ProjectivePoint) -> ProjectivePoint {
    let mut table = [ProjectivePoint::IDENTITY; 8];
    let mut multiple = *base;
    for entry in &mut table {
        *entry = multiple;
        add_in_place(&mut multiple, base);
    }
    let mut digits = recode(secret);
    let mut product = ProjectivePoint::IDENTITY;
    let mut term = ProjectivePoint::IDENTITY;
    let mut first = true;
    for &digit in digits.iter().rev() {
        if !first {
            for _ in 0_u8..4 {
                double_in_place(&mut product);
            }
        }
        first = false;
        select(&table, digit, &mut term);
        add_in_place(&mut product, &term);
    }
    digits.fill(0);
    black_box(&mut digits);
    compiler_fence(Ordering::SeqCst);
    clear(&mut term);
    let result = product;
    clear(&mut product);
    result
}

/// The digits of `secret`, least significant first, each from -8 to 7 but
/// the last, which is 0 or 1: the nibbles, each brought into range by
/// carrying 16 into the next.
fn recode(secret: &[u8; KEY_LEN]) -> [i8; DIGITS] {
    let mut digits = [0_i8; DIGITS];
    for (pair, &octet) in digits.as_chunks_mut::<2>().0.iter_mut().zip(secret.iter().rev()) {
        *pair = [(octet & 0x0F).cast_signed(), octet.wrapping_shr(4).cast_signed()];
    }
    let mut carry = 0_i8;
    for digit in &mut digits {
        let value = digit.wrapping_add(carry);
        carry = value.wrapping_add(8).wrapping_shr(4);
        *digit = value.wrapping_sub(carry.wrapping_shl(4));
    }
    digits
}

/// Sets `out` to `digit` times the base of `table`, which holds 1 to 8
/// times it, reading every entry so the time does not depend on the digit.
#[inline(never)]
fn select(table: &[ProjectivePoint; 8], digit: i8, out: &mut ProjectivePoint) {
    // All ones for a negative digit, zero otherwise.
    let sign = digit.wrapping_shr(7);
    let magnitude = (digit ^ sign).wrapping_sub(sign).cast_unsigned();
    *out = ProjectivePoint::IDENTITY;
    let mut index = 0_u8;
    for entry in table {
        index = index.wrapping_add(1);
        out.conditional_assign(entry, magnitude.ct_eq(&index));
    }
    let negated = out.neg();
    out.conditional_assign(&negated, Choice::from(sign.cast_unsigned() & 1));
}

/// The X coordinate of `point`, or `None` for the identity.
fn x_coordinate(point: &ProjectivePoint) -> Option<[u8; KEY_LEN]> {
    let xy = encode(point)?;
    xy.first_chunk::<KEY_LEN>().copied()
}

#[cfg(test)] mod tests;
