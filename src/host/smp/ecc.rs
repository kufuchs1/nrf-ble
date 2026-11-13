//! P-256 for LE Secure Connections: the key pair, the check of the central's
//! public key and the Diffie-Hellman key.
//!
//! Keys are in the byte order of the toolbox: the private key, each
//! coordinate and the Diffie-Hellman key most significant octet first, and a
//! public key as X then Y, the order the Pairing Public Key PDU carries them
//! in. The PDU carries each coordinate least significant octet first, so the
//! security manager reverses each one on the way in and out.
//!
//! All of the elliptic curve cryptography is that of the RustCrypto `p256`
//! crate, through its public API only, in pure Rust and without tables kept
//! in RAM (its `precomputed-tables` feature stays off):
//!
//! - The private key is a [`SecretKey`] from the caller's random octets
//!   ([`SecretKey::from_bytes`], which refuses zero and anything not below the
//!   order of the curve), and overwrites itself when it is dropped.
//! - The public key is [`SecretKey::public_key`], the generator times the
//!   private key.
//! - The central's key is decoded with
//!   [`point::AffineCoordinates::from_coordinates`], which refuses a coordinate
//!   not below the field prime and a point off the curve, and
//!   [`PublicKey::from_affine`], which refuses the identity. P-256 has a
//!   cofactor of 1, so every other point is of the prime order and no subgroup
//!   check is needed: the invalid curve attack (a point of another curve, or of
//!   a small subgroup) has no point to start from.
//! - The Diffie-Hellman key is [`SecretKey::diffie_hellman`], whose
//!   [`p256::ecdh::SharedSecret`] overwrites itself when it is dropped.
//!
//! Both multiplications are `ProjectivePoint::mul` of the `primeorder` crate
//! under `p256`: a fixed window of signed radix 16 digits, a table of 1 to 8
//! times the point read in full for every digit and selected with the
//! constant time operations of `subtle`, and the complete addition formulas
//! of Renes, Costello and Batina, which have no exceptional cases to branch
//! on. The field arithmetic below them is that of `p256` and `crypto-bigint`.
//! What their own documentation claims (the README files of `p256` and
//! `primeorder` at the revision in use): the code is designed so that the
//! operations that depend on a secret run in constant time, but it has never
//! been independently audited, and whether the generated machine code is
//! constant time has not been assessed thoroughly. `crypto-bigint` was
//! audited by NCC Group, before larger changes since; its CI checks the
//! machine code of the functions its `checkct` driver names, on thumbv6m and
//! thumbv7em among others, but those are its own building blocks (limb
//! carries, wide multiplication, Montgomery multiplication and squaring,
//! inversion, division), not the P-256 code built from them: the field
//! functions of `p256`, the table selection and the point formulas of
//! `primeorder` are not checked that way, nor the code the firmware's build
//! makes of them. On the multipliers, the readme (section "Cryptography of
//! pairing") gives the instruction timing of both cores and its sources.
//!
//! What stays ours is the protocol around it: the byte order, the checks
//! the Core specification asks for beyond a valid point (the debug public
//! key and our own public key are refused, see [`check_public_key`]), the
//! hook before each multiplication, and overwriting the caller's copy of
//! the private key. The library overwrites its [`SecretKey`] and its
//! [`p256::ecdh::SharedSecret`] when they are dropped, and nothing else: the
//! copy of the private key as a scalar that [`SecretKey::public_key`] and
//! [`SecretKey::diffie_hellman`] make (`NonZeroScalar`, which is `Copy` and
//! not overwritten), the recoded digits and the table of multiples of a
//! multiplication, and in the Diffie-Hellman the shared point itself,
//! projective and affine, whose X is the Diffie-Hellman key, all stay on the
//! stack of the thread that ran the job until something else happens to
//! write over them. The Diffie-Hellman key that [`KeyPair::dh_key`] returns
//! is the caller's to wipe, once f5 has derived the keys from it.
//!
//! Each multiplication blocks the thread for several seconds on the nRF51
//! (the readme gives the emulated figures per build; not yet measured on the
//! chip), so the security manager runs them as jobs outside its state
//! machine, and each call here takes a hook it calls right before its
//! multiplication, for the firmware to feed its watchdog.

use crate::crypto::wipe;
use p256::{AffinePoint, FieldBytes, PublicKey, SecretKey, elliptic_curve::point};

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

/// Why a public key is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

impl KeyError {
    /// The name of the error, for a defmt log line (`{=istr}`): interned,
    /// so the string stays in the `.defmt` section, which takes no flash.
    #[cfg(feature = "defmt")]
    #[inline]
    #[must_use = "the name is only read"]
    pub fn name(self) -> defmt::Str {
        match self {
            Self::Debug => defmt::intern!("Debug"),
            Self::Invalid => defmt::intern!("Invalid"),
            Self::Own => defmt::intern!("Own"),
        }
    }
}

/// Our key pair for one pairing: the private key and the public key it
/// gives. The private key, a [`SecretKey`] of the `p256` crate, overwrites
/// itself when it is dropped.
pub struct KeyPair {
    /// The public key, X then Y.
    public: [u8; PUBLIC_KEY_LEN],
    /// The private key, from 1 to the order of the curve less 1.
    secret: SecretKey,
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
        let key = decode(peer, &self.public)?;
        before_multiplication();
        // The shared secret overwrites itself when it is dropped, here.
        let shared = self.secret.diffie_hellman(&key);
        Ok((*shared.raw_secret_bytes()).into())
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
        let mut repr = FieldBytes::from(*secret);
        wipe(secret);
        let checked = SecretKey::from_bytes(&repr);
        wipe(&mut repr);
        let key = checked.ok()?;
        before_multiplication();
        let public = encode(key.public_key().as_affine());
        Some(Self { public, secret: key })
    }

    /// The public key, X then Y.
    #[inline]
    #[must_use = "the key is only borrowed"]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] { &self.public }
}

/// Checks the central's public key `peer` against our own public key `own`.
///
/// The key must be a point of the curve other than the identity, as the
/// `p256` crate checks it (see the module documentation), and neither the
/// debug public key nor our own, nor their negations. The security manager
/// checks it when the Pairing Public Key PDU arrives, before the
/// Diffie-Hellman key job.
///
/// # Errors
///
/// The reason `peer` is refused.
#[inline]
pub fn check_public_key(peer: &[u8; PUBLIC_KEY_LEN], own: &[u8; PUBLIC_KEY_LEN]) -> Result<(), KeyError> {
    decode(peer, own).map(drop)
}

/// The public key `peer` of the central, checked as [`check_public_key`]
/// describes.
///
/// A key and its negation share their X coordinate, which is all the
/// Diffie-Hellman key depends on, so the debug key and our own key are
/// recognised by X alone.
fn decode(peer: &[u8; PUBLIC_KEY_LEN], own: &[u8; PUBLIC_KEY_LEN]) -> Result<PublicKey, KeyError> {
    let (x, rest) = peer.split_first_chunk::<KEY_LEN>().ok_or(KeyError::Invalid)?;
    let y = rest.first_chunk::<KEY_LEN>().ok_or(KeyError::Invalid)?;
    if Some(x) == DEBUG_PUBLIC_KEY.first_chunk::<KEY_LEN>() {
        return Err(KeyError::Debug);
    }
    if Some(x) == own.first_chunk::<KEY_LEN>() {
        return Err(KeyError::Own);
    }
    // The coordinates are taken only below the field prime, the point only
    // if it satisfies the curve equation, and the key only if it is not the
    // identity.
    let on_curve: Option<AffinePoint> =
        <AffinePoint as point::AffineCoordinates>::from_coordinates(&FieldBytes::from(*x), &FieldBytes::from(*y))
            .into();
    on_curve.and_then(|valid| PublicKey::from_affine(valid).ok()).ok_or(KeyError::Invalid)
}

/// The coordinates of `key`, X then Y.
fn encode(key: &AffinePoint) -> [u8; PUBLIC_KEY_LEN] {
    let mut out = [0; PUBLIC_KEY_LEN];
    if let Some((x, rest)) = out.split_first_chunk_mut::<KEY_LEN>() {
        *x = point::AffineCoordinates::x(key).into();
        if let Some(y) = rest.first_chunk_mut::<KEY_LEN>() {
            *y = point::AffineCoordinates::y(key).into();
        }
    }
    out
}

#[cfg(test)] mod tests;
