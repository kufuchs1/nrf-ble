//! A minimal Bluetooth LE host for Linux and BlueZ.
//!
//! The host is to serve one connection as a peripheral: L2CAP with the fixed
//! channels for ATT, signalling and the security manager, a GATT server over
//! a constant attribute table, LE Secure Connections pairing as responder
//! (Just Works) with bonding, and connectable advertising. It talks to the
//! link layer through the typed API of [`crate::link`], not through HCI.
//!
//! So far the AES seam ([`Aes`] and [`Ecb`]), the security manager
//! ([`smp`], with its cryptography in [`smp::toolbox`] and [`smp::ecc`]),
//! the L2CAP fixed channels ([`l2cap`]), LE signalling ([`signal`]), the ATT
//! server ([`att`]), the GATT table with the Spotlight's ([`gatt`]), our
//! identity ([`identity`]), the advertising data, modes and their setup of
//! the link layer ([`adv`]) and the bond with its stored form ([`bond`])
//! exist, but nothing calls them on a running connection yet: that is the
//! engine stage. The other modules
//! describe what the next stages put into them. The protocol core ([`l2cap`],
//! [`signal`], [`att`], [`gatt`], [`smp`] and [`engine`]) is to hold no
//! futures and touch no peripheral, so it runs in the host tests on the PC;
//! only the async glue around the [`engine`] uses the link layer. Every buffer
//! is to be a fixed array: no heap and no allocation.
//!
//! Every call into the host is to come from thread mode, as its state sits
//! behind a thread mode mutex rather than a critical section, which would
//! hold off the link layer for the whole of the longer AES computations of
//! pairing. Each AES block on the ECB still holds a critical section for that
//! one block, as [`crate::encrypt_block`] shares the ECB with the link layer:
//! f5, which runs three CMACs, takes 13 AES blocks and so holds interrupts
//! off 13 times, each for about 7 us on the nRF52832.

/// Connectable advertising and the advertising data writer.
pub mod adv;
/// The attribute protocol: requests, responses, notifications, indications.
pub mod att;
/// The bond with the one central and its stored form.
pub mod bond;
/// The protocol engine, without input or output of its own.
pub mod engine;
/// The GATT server's attribute table.
pub mod gatt;
/// The device's own identity address and identity resolving key.
pub mod identity;
/// The L2CAP fixed channels: demultiplexing, reassembly and fragmenting.
pub mod l2cap;
/// The L2CAP signalling channel.
pub mod signal;
/// The security manager: LE Secure Connections pairing as responder.
pub mod smp;

/// AES-128 encryption of one block, the only block cipher the host needs: the
/// CMAC of pairing, the key derivation of the identity and the resolvable
/// private addresses are all built on it.
///
/// The firmware uses the hardware ECB through [`Ecb`]; the host tests use the
/// software AES of the `aes` crate.
pub trait Aes {
    /// `block` encrypted with `key`, both most significant octet first.
    fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16];
}

/// AES-128 on the hardware ECB, through [`crate::encrypt_block`].
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct Ecb;

impl Aes for Ecb {
    #[inline]
    fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16] { crate::encrypt_block(key, block) }
}

/// Software AES-128 in place of the ECB, for the host tests of every module.
#[cfg(test)]
pub(crate) mod test_aes {
    use super::Aes;
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt as _, KeyInit as _},
    };

    /// Software AES-128 from the `aes` crate.
    pub(crate) struct Software;

    impl Aes for Software {
        fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
            let mut data = block.into();
            Aes128::new(&key.into()).encrypt_block(&mut data);
            data.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Aes as _, test_aes::Software};

    /// The software stand-in gives the AES-128 example of FIPS-197 appendix
    /// C.1.
    #[test]
    fn software_aes_matches_fips_197() {
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let plain = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let cipher = [0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A];
        assert_eq!(Software.encrypt(key, plain), cipher);
    }
}
