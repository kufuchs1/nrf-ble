//! The device's own identity: a static random address and an identity
//! resolving key.
//!
//! Both come from a device secret and a [`Variant`], with AES, so the
//! firmware can change identity without storing one: the address is the
//! first six octets of the secret's encryption root (ER) encrypting the
//! variant, with its two most significant bits set, as a static random
//! address must have them, and the identity resolving key is the identity
//! root (IR) encrypting the variant. On the chip the two roots are the
//! factory values in FICR ([`DeviceSecret::from_ficr`]); the host tests give
//! plain bytes ([`DeviceSecret::new`]).
//!
//! This is the scheme of the MX firmwares, which derive their address and key
//! the same way: the same roots and variant give the same identity, so a
//! firmware that moves to this host keeps the address its central bonded
//! with. Neither value reveals the factory device ID, and a central that
//! knows the identity of one variant cannot tell that of another from it.
//!
//! The variant is a slot number in its low octet and a generation in its high
//! one. The Spotlight has one slot, 0. Each time the device enters pairing
//! mode it takes the next generation ([`Variant::next_generation`]), so it
//! pairs again under a new identity and BlueZ, which keeps the old bond under
//! the old address, needs no `remove` first: it refuses a second Just Works
//! pairing with a device it has a bond with, and it would resolve the
//! resolvable private address of an old identity, connect and encrypt with
//! the old key, which the device no longer has.
//!
//! So the firmware stores the generation in flash apart from the bond, never
//! erased with it, and bumps and stores it before it advertises in pairing
//! mode, not when the pairing bonds. A bond that was cleared or lost, by a
//! torn write or a power failure before it was stored, then never brings back
//! a generation BlueZ may hold a bond with; nor does a pairing BlueZ
//! completed whose bond the device never stored. The bond itself keeps the
//! variant it was made under ([`crate::host::bond::Bond::local`]), which
//! reconnection advertises with. The generation wraps after 256 pairing
//! modes.
//!
//! The identity resolving key is kept least significant octet first, the
//! order the Identity Information PDU carries it in and
//! [`crate::link::Link::add_peer`] takes it in. It is the AES output as it
//! comes, as the MX firmwares hand it to the controller.

use crate::{crypto::wipe, host::Aes, pdu::Peer};

/// The device secret the identities derive from: the encryption root and the
/// identity root, 16 octets each. Both are overwritten when it is dropped.
pub struct DeviceSecret {
    /// The encryption root, as the AES key.
    er: [u8; 16],
    /// The identity root, as the AES key.
    ir: [u8; 16],
}

/// Our identity for one [`Variant`]: the static random address and the
/// identity resolving key. The key is overwritten when it is dropped.
#[derive(Clone, Eq, PartialEq)]
#[expect(clippy::module_name_repetitions, reason = "a local identity, apart from the central's")]
pub struct LocalIdentity {
    /// The static random address, least significant octet first.
    address: [u8; 6],
    /// The identity resolving key, least significant octet first.
    irk:     [u8; 16],
    /// The variant it was derived for.
    variant: Variant,
}

/// Which identity the device takes: a slot in the low octet and a generation
/// in the high one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Variant(u16);

impl DeviceSecret {
    /// The roots in FICR: ER and IR, each read as four words, every word
    /// least significant octet first, as the MX firmwares read them.
    #[inline]
    #[must_use = "the secret is only read"]
    pub fn from_ficr() -> Self {
        use embassy_nrf::pac::FICR;
        Self::from_words(
            core::array::from_fn(|word| FICR.er(word).read()),
            core::array::from_fn(|word| FICR.ir(word).read()),
        )
    }

    /// The roots from their four words each, every word least significant
    /// octet first.
    #[inline]
    #[must_use = "the secret is only built"]
    pub fn from_words(er: [u32; 4], ir: [u32; 4]) -> Self {
        let octets = |words: [u32; 4]| {
            let mut root = [0; 16];
            for (chunk, word) in root.as_chunks_mut::<4>().0.iter_mut().zip(words) {
                *chunk = word.to_le_bytes();
            }
            root
        };
        Self::new(octets(er), octets(ir))
    }

    /// The roots as AES keys: the encryption root `er` and the identity
    /// root `ir`.
    #[inline]
    #[must_use = "the secret is only built"]
    pub const fn new(er: [u8; 16], ir: [u8; 16]) -> Self { Self { er, ir } }
}

impl Drop for DeviceSecret {
    #[inline]
    fn drop(&mut self) {
        wipe(&mut self.er);
        wipe(&mut self.ir);
    }
}

impl LocalIdentity {
    /// The static random address, least significant octet first, for
    /// [`crate::link::Link::set_identity`] and the Identity Address
    /// Information PDU.
    #[inline]
    #[must_use = "the address is only read"]
    pub const fn address(&self) -> [u8; 6] { self.address }

    /// The identity of `variant` derived from `secret` with `aes`: see the
    /// module documentation.
    #[inline]
    #[must_use = "the identity is only derived"]
    pub fn derive<A>(aes: &A, secret: &DeviceSecret, variant: Variant) -> Self
    where
        A: Aes,
    {
        let block = variant.block();
        let mut address_block = aes.encrypt(secret.er, block);
        let address = static_random(address_block.first_chunk::<6>().copied().unwrap_or_default());
        wipe(&mut address_block);
        let mut irk = aes.encrypt(secret.ir, block);
        // An all zero key means "none" to the resolving list; the MX
        // firmwares take 1 in its place.
        if irk == [0; 16]
            && let Some(first) = irk.first_mut()
        {
            *first = 1;
        }
        Self { address, irk, variant }
    }

    /// The identity resolving key, least significant octet first.
    #[inline]
    #[must_use = "the key is only read"]
    pub const fn irk(&self) -> [u8; 16] { self.irk }

    /// The address with its type, random.
    #[inline]
    #[must_use = "the address is only read"]
    pub const fn peer(&self) -> Peer { Peer::new(self.address, true) }

    /// The variant the identity belongs to.
    #[inline]
    #[must_use = "the variant is only read"]
    pub const fn variant(&self) -> Variant { self.variant }
}

impl Drop for LocalIdentity {
    #[inline]
    fn drop(&mut self) { wipe(&mut self.irk); }
}

impl Variant {
    /// The variant as stored: the slot in the low octet, the generation in
    /// the high one.
    #[inline]
    #[must_use = "the value is only read"]
    pub const fn bits(self) -> u16 { self.0 }

    /// The AES block the roots encrypt: the variant least significant octet
    /// first, then zeros.
    const fn block(self) -> [u8; 16] {
        let [low, high] = self.0.to_le_bytes();
        [low, high, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    /// The variant stored as `bits`.
    #[inline]
    #[must_use = "the variant is only built"]
    pub const fn from_bits(bits: u16) -> Self { Self(bits) }

    /// The generation, which each pairing mode bumps.
    #[inline]
    #[must_use = "the generation is only read"]
    pub const fn generation(self) -> u8 {
        let [_, high] = self.0.to_le_bytes();
        high
    }

    /// The variant of `slot` in `generation`.
    #[inline]
    #[must_use = "the variant is only built"]
    pub const fn new(slot: u8, generation: u8) -> Self { Self(u16::from_le_bytes([slot, generation])) }

    /// The same slot in the next generation, for a new pairing mode; after
    /// 255 comes 0.
    #[inline]
    #[must_use = "the variant is only built"]
    pub const fn next_generation(self) -> Self { Self::new(self.slot(), self.generation().wrapping_add(1)) }

    /// The slot.
    #[inline]
    #[must_use = "the slot is only read"]
    pub const fn slot(self) -> u8 {
        let [low, _] = self.0.to_le_bytes();
        low
    }
}

/// A static random address from six random octets, least significant first
/// (Core, Vol 6, Part B, 1.3.2.1): the two most significant bits set, and the
/// rest neither all zeros nor all ones, which flips the lowest bit.
fn static_random(mut octets: [u8; 6]) -> [u8; 6] {
    let mut random = octets;
    if let Some(top) = random.last_mut() {
        *top &= 0x3F;
    }
    if (random == [0; 6] || random == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F])
        && let Some(first) = octets.first_mut()
    {
        *first ^= 1;
    }
    if let Some(top) = octets.last_mut() {
        *top |= 0xC0;
    }
    octets
}

#[cfg(test)] mod tests;
