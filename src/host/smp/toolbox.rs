//! The cryptographic functions of the security manager: f4, f5, f6, g2 and
//! ah.
//!
//! They are written from the Core specification, volume 3, part H, section
//! 2.2.
//!
//! The AES-CMAC under f4, f5, f6 and g2 is that of the RustCrypto `cmac`
//! crate (RFC 4493), not our own: [`cmac()`] hands it the [`Aes`] of the
//! firmware, the hardware ECB, as its block cipher, through an adapter that
//! implements the block cipher traits of the `cipher` crate for one key
//! (`KeyedAes`). The host tests run the same code over the software AES of
//! the `aes` crate, and check it against the examples of RFC 4493 and the
//! sample data of the Core specification, volume 3, part H, appendix D. What
//! stays ours here is the specification's formulas: which key, which message
//! and which octets of the result each function takes.
//!
//! Every value is most significant octet first, as the specification writes
//! them: keys, nonces, the X coordinates of the public keys, the Diffie-Hellman
//! key and the 56-bit addresses of f5 and f6 (see [`address`]). The security
//! manager's PDUs carry most of these values least significant octet first, so
//! the security manager reverses them on the way in and out; the long term key
//! that f5 gives is reversed for [`crate::link::Link::ltk_reply`].
//!
//! The CMAC is fed the message piece by piece, so no message is assembled on
//! the stack. A CMAC takes one AES block for its subkeys and one for each 16
//! octets of its message: 6 for f4, f6 and g2, and 13 for f5, which runs
//! three CMACs.
//!
//! The `cmac` crate, with its `zeroize` feature, overwrites its chaining
//! value and its pending block when it is dropped; the adapter overwrites its
//! copy of the key, and f5 overwrites its intermediate key T once both keys
//! are derived. The keys these functions return, and those the caller passes
//! in, are the caller's to wipe.

use crate::{
    bytes::{be16_bytes, be32},
    crypto::wipe,
    host::Aes,
    pdu::Peer,
};
use cipher::{
    Block,
    BlockCipherEncBackend,
    BlockCipherEncClosure,
    BlockCipherEncrypt,
    BlockSizeUser,
    InOut,
    InOutBuf,
    ParBlocks,
    ParBlocksSizeUser,
    consts::{U1, U16},
    inout::NotEqualError,
};
use cmac::{Cmac, Mac as _, digest::InnerInit};

/// The SALT of f5 (Core specification, volume 3, part H, section 2.2.7).
const F5_SALT: [u8; 16] =
    [0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE];

/// The keyID of f5: "btle".
const F5_KEY_ID: [u8; 4] = *b"btle";

/// The Length of f5: the 256 bits of the `MacKey` and the LTK together.
const F5_LENGTH: [u8; 2] = be16_bytes(256);

/// An [`Aes`] with one key, as the block cipher of the `cmac` crate.
///
/// It encrypts one block at a time, which is all CMAC asks of it. The key
/// travels with it, so it needs no key schedule of its own: each block goes
/// to [`Aes::encrypt`] with the key, as the hardware ECB takes them. The key
/// is overwritten when it is dropped, with the CMAC that owns it.
///
/// It is its own backend, one block wide, so every method of the two traits
/// comes down to `BlockCipherEncBackend::encrypt_block`; the lints ask for
/// each method to be written out rather than taken from the traits' defaults,
/// which do the same.
struct KeyedAes<'aes, A: Aes> {
    /// The block cipher.
    aes: &'aes A,
    /// The key, most significant octet first.
    key: [u8; 16],
}

impl<'aes, A: Aes> KeyedAes<'aes, A> {
    /// `aes` with `key`, most significant octet first.
    #[inline]
    #[must_use = "the cipher is only built"]
    const fn new(aes: &'aes A, key: [u8; 16]) -> Self { Self { aes, key } }
}

impl<A: Aes> BlockCipherEncBackend for KeyedAes<'_, A> {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let encrypted = self.aes.encrypt(self.key, (*block.get_in()).into());
        *block.get_out() = encrypted.into();
    }

    #[inline]
    fn encrypt_block_inplace(&self, block: &mut Block<Self>) {
        BlockCipherEncBackend::encrypt_block(self, block.into());
    }

    #[inline]
    fn encrypt_par_blocks(&self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // One block wide: the only block.
        BlockCipherEncBackend::encrypt_block(self, blocks.get(0));
    }

    #[inline]
    fn encrypt_par_blocks_inplace(&self, blocks: &mut ParBlocks<Self>) { self.encrypt_par_blocks(blocks.into()); }

    #[inline]
    fn encrypt_tail_blocks(&self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        // The trait asks for fewer blocks than the width, which is one: none.
        // As the trait's default does, a debug build checks that, and any
        // block there is anyway is encrypted on its own.
        debug_assert!(blocks.is_empty(), "a tail is shorter than the width of one block");
        for block in blocks {
            BlockCipherEncBackend::encrypt_block(self, block);
        }
    }

    #[inline]
    fn encrypt_tail_blocks_inplace(&self, blocks: &mut [Block<Self>]) { self.encrypt_tail_blocks(blocks.into()); }
}

impl<A: Aes> BlockCipherEncrypt for KeyedAes<'_, A> {
    #[inline]
    fn encrypt_block(&self, block: &mut Block<Self>) { BlockCipherEncBackend::encrypt_block(self, block.into()); }

    #[inline]
    fn encrypt_block_b2b(&self, in_block: &Block<Self>, out_block: &mut Block<Self>) {
        BlockCipherEncBackend::encrypt_block(self, (in_block, out_block).into());
    }

    #[inline]
    fn encrypt_block_inout(&self, block: InOut<'_, '_, Block<Self>>) {
        BlockCipherEncBackend::encrypt_block(self, block);
    }

    #[inline]
    fn encrypt_blocks(&self, blocks: &mut [Block<Self>]) { self.encrypt_blocks_inout(blocks.into()); }

    #[inline]
    fn encrypt_blocks_b2b(
        &self,
        in_blocks: &[Block<Self>],
        out_blocks: &mut [Block<Self>],
    ) -> Result<(), NotEqualError> {
        InOutBuf::new(in_blocks, out_blocks).map(|blocks| self.encrypt_blocks_inout(blocks))
    }

    #[inline]
    fn encrypt_blocks_inout(&self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        for block in blocks {
            BlockCipherEncBackend::encrypt_block(self, block);
        }
    }

    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) { f.call(self) }
}

impl<A: Aes> BlockSizeUser for KeyedAes<'_, A> {
    type BlockSize = U16;

    #[inline]
    fn block_size() -> usize { size_of::<Block<Self>>() }
}

impl<A: Aes> Drop for KeyedAes<'_, A> {
    #[inline]
    fn drop(&mut self) { wipe(&mut self.key); }
}

impl<A: Aes> ParBlocksSizeUser for KeyedAes<'_, A> {
    type ParBlocksSize = U1;
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

/// The AES-CMAC (RFC 4493) with `key` of the message made of `parts` in
/// order, most significant octet first, from the `cmac` crate over `aes`.
#[inline]
#[must_use = "the CMAC is only computed"]
pub fn cmac<A>(aes: &A, key: [u8; 16], parts: &[&[u8]]) -> [u8; 16]
where
    A: Aes,
{
    let mut mac: Cmac<KeyedAes<'_, A>> = InnerInit::inner_init(KeyedAes::new(aes, key));
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
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
    let mut key_t = cmac(aes, F5_SALT, &[w]);
    let derive = |key: [u8; 16], counter: u8| {
        cmac(aes, key, &[&[counter], &F5_KEY_ID, nonces.0, nonces.1, addresses.0, addresses.1, &F5_LENGTH])
    };
    let keys = (derive(key_t, 0), derive(key_t, 1));
    wipe(&mut key_t);
    keys
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
    be32(cmac(aes, *key, &[u_x, v_x, y]).last_chunk::<4>().copied().unwrap_or_default())
}

#[cfg(test)] pub(crate) mod tests;
