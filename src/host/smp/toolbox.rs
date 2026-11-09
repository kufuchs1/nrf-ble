//! The cryptographic functions of the security manager: AES-CMAC and the
//! functions f4, f5, f6, g2 and ah.
//!
//! The CMAC is that of RFC 4493, and the functions are written from the Core
//! specification, volume 3, part H, section 2.2.
//!
//! Every value is most significant octet first, as the specification writes
//! them: keys, nonces, the X coordinates of the public keys, the Diffie-Hellman
//! key and the 56-bit addresses of f5 and f6 (see [`address`]). The security
//! manager's PDUs carry most of these values least significant octet first, so
//! the security manager reverses them on the way in and out; the long term key
//! that f5 gives is reversed for [`crate::link::Link::ltk_reply`].
//!
//! Every AES block goes through the [`Aes`] trait: the hardware ECB in the
//! firmware, software AES in the host tests. The CMAC is fed piece by piece
//! ([`Cmac::update`]), so no message is assembled on the stack: it keeps one
//! chaining block and one pending block, and a CMAC of f5 needs 13 blocks.

use crate::{host::Aes, pdu::Peer};

/// The SALT of f5 (Core specification, volume 3, part H, section 2.2.7).
const F5_SALT: [u8; 16] =
    [0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE];

/// The keyID of f5: "btle".
const F5_KEY_ID: [u8; 4] = *b"btle";

/// The Length of f5: the 256 bits of the `MacKey` and the LTK together.
const F5_LENGTH: [u8; 2] = 256_u16.to_be_bytes();

/// The feedback polynomial of the subkey doubling, x^7 + x^2 + x + 1.
const CMAC_RB: u128 = 0x87;

/// AES-CMAC (RFC 4493) of a message fed in pieces of any length.
///
/// The last block of a message is treated apart from the others, so a full
/// block is kept pending until more of the message arrives or
/// [`Self::finish`] is called.
pub struct Cmac<'aes, A: Aes> {
    /// The block cipher.
    aes:    &'aes A,
    /// The pending block, zero after its filled octets.
    block:  [u8; 16],
    /// The number of octets in the pending block, 0 to 16.
    filled: usize,
    /// The key, most significant octet first.
    key:    [u8; 16],
    /// The chaining value: the encryption of every block before the pending
    /// one.
    state:  [u8; 16],
}

impl<'aes, A: Aes> Cmac<'aes, A> {
    /// The CMAC of the message fed so far, most significant octet first.
    #[inline]
    #[must_use = "the CMAC is only computed"]
    pub fn finish(mut self) -> [u8; 16] {
        let subkey_1 = double(self.aes.encrypt(self.key, [0; 16]));
        let subkey = if self.filled == 16 {
            subkey_1
        } else {
            // The padding: one bit set, then zeros, which the block already
            // holds after its filled octets.
            if let Some(octet) = self.block.get_mut(self.filled) {
                *octet = 0x80;
            }
            double(subkey_1)
        };
        self.aes.encrypt(self.key, xor(xor(self.state, self.block), subkey))
    }

    /// A CMAC with `key`, most significant octet first, over an empty
    /// message.
    #[inline]
    #[must_use = "the CMAC is only started"]
    pub const fn new(aes: &'aes A, key: [u8; 16]) -> Self {
        Self { aes, block: [0; 16], filled: 0, key, state: [0; 16] }
    }

    /// Appends `data` to the message.
    #[inline]
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        for &octet in data {
            if self.filled == 16 {
                self.state = self.aes.encrypt(self.key, xor(self.state, self.block));
                self.block = [0; 16];
                self.filled = 0;
            }
            if let Some(target) = self.block.get_mut(self.filled) {
                *target = octet;
            }
            self.filled = self.filled.saturating_add(1);
        }
        self
    }
}

/// The 56-bit address of f5 and f6 for `peer`: its type in the most
/// significant octet (1 for a random address, 0 for a public one), then the
/// address most significant octet first.
///
/// Pairing uses the addresses on the air, [`crate::link::Info::peer`] and
/// [`crate::link::Info::local`], not the identities.
#[inline]
#[must_use = "the address is only built"]
pub fn address(peer: Peer) -> [u8; 7] {
    let mut out = [0; 7];
    let (kind, rest) = out.split_at_mut(1);
    if let Some(octet) = kind.first_mut() {
        *octet = u8::from(peer.random);
    }
    for (target, &octet) in rest.iter_mut().zip(peer.address.iter().rev()) {
        *target = octet;
    }
    out
}

/// The random address hash function ah (section 2.2.2): the least
/// significant 24 bits of AES-128 with `key` of `prand` padded with zeros.
///
/// `key` is an identity resolving key; `prand` and the hash are most
/// significant octet first.
#[inline]
#[must_use = "the hash is only computed"]
pub fn ah<A>(aes: &A, key: &[u8; 16], prand: [u8; 3]) -> [u8; 3]
where
    A: Aes,
{
    let mut block = [0; 16];
    if let Some(target) = block.last_chunk_mut::<3>() {
        *target = prand;
    }
    aes.encrypt(*key, block).last_chunk::<3>().copied().unwrap_or_default()
}

/// The CMAC with `key` of the message made of `parts` in order, most
/// significant octet first.
#[inline]
#[must_use = "the CMAC is only computed"]
pub fn cmac<A>(aes: &A, key: [u8; 16], parts: &[&[u8]]) -> [u8; 16]
where
    A: Aes,
{
    let mut mac = Cmac::new(aes, key);
    for part in parts {
        mac.update(part);
    }
    mac.finish()
}

/// Doubling in GF(2^128), the subkey step of RFC 4493: a left shift by one
/// bit, and the feedback polynomial added if the bit shifted out was set,
/// without a branch on it.
const fn double(block: [u8; 16]) -> [u8; 16] {
    let value = u128::from_be_bytes(block);
    let carry = value.wrapping_shr(127);
    (value.wrapping_shl(1) ^ (0_u128.wrapping_sub(carry) & CMAC_RB)).to_be_bytes()
}

/// The confirm value generation function f4 (section 2.2.6): AES-CMAC
/// with `key` of U || V || Z.
///
/// U and V, `u_x` and `v_x`, are the X coordinates of the two public keys,
/// `key` a random nonce, Z zero for Just Works and numeric comparison.
#[inline]
#[must_use = "the confirm value is only computed"]
pub fn f4<A>(aes: &A, u_x: &[u8; 32], v_x: &[u8; 32], key: &[u8; 16], z: u8) -> [u8; 16]
where
    A: Aes,
{
    cmac(aes, *key, &[u_x, v_x, &[z]])
}

/// The key generation function f5 (section 2.2.7): the `MacKey` and the
/// long term key, in that order.
///
/// They come from the Diffie-Hellman key `w`, the nonces N1 and N2 and the
/// 56-bit addresses A1 and A2 (see [`address`]), each pair in that order. It
/// takes three CMACs: T with the SALT over `w`, then one with T for each key,
/// which differ only in their counter octet.
#[inline]
#[must_use = "the keys are only computed"]
pub fn f5<A>(
    aes: &A,
    w: &[u8; 32],
    nonces: (&[u8; 16], &[u8; 16]),
    addresses: (&[u8; 7], &[u8; 7]),
) -> ([u8; 16], [u8; 16])
where
    A: Aes,
{
    let key_t = cmac(aes, F5_SALT, &[w]);
    let derive = |counter: u8| {
        cmac(aes, key_t, &[&[counter], &F5_KEY_ID, nonces.0, nonces.1, addresses.0, addresses.1, &F5_LENGTH])
    };
    (derive(0), derive(1))
}

/// The check value generation function f6 (section 2.2.8): AES-CMAC with
/// the `MacKey` `w` of N1 || N2 || R || `IOcap` || A1 || A2.
///
/// The nonces N1 and N2 and the 56-bit addresses A1 and A2 (see
/// [`address`]) are given in pairs. R, `r_value`, is zero for Just Works and
/// numeric comparison, and `io_cap` holds the `AuthReq`, OOB data flag and
/// IO capability octets of the side whose check value it is, in that order.
#[inline]
#[must_use = "the check value is only computed"]
pub fn f6<A>(
    aes: &A,
    w: &[u8; 16],
    nonces: (&[u8; 16], &[u8; 16]),
    r_value: &[u8; 16],
    io_cap: [u8; 3],
    addresses: (&[u8; 7], &[u8; 7]),
) -> [u8; 16]
where
    A: Aes,
{
    cmac(aes, *w, &[nonces.0, nonces.1, r_value, &io_cap, addresses.0, addresses.1])
}

/// The numeric comparison value generation function g2 (section 2.2.9): the
/// least significant 32 bits of AES-CMAC with `key` of U || V || `y`.
///
/// U and V, `u_x` and `v_x`, are the X coordinates of the two public keys,
/// `key` and `y` the two nonces; the six digits shown are the value modulo
/// 1 000 000.
#[inline]
#[must_use = "the value is only computed"]
pub fn g2<A>(aes: &A, u_x: &[u8; 32], v_x: &[u8; 32], key: &[u8; 16], y: &[u8; 16]) -> u32
where
    A: Aes,
{
    u32::from_be_bytes(cmac(aes, *key, &[u_x, v_x, y]).last_chunk::<4>().copied().unwrap_or_default())
}

/// The exclusive or of two blocks.
const fn xor(left: [u8; 16], right: [u8; 16]) -> [u8; 16] {
    (u128::from_be_bytes(left) ^ u128::from_be_bytes(right)).to_be_bytes()
}

#[cfg(test)] pub(crate) mod tests;
