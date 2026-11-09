//! A minimal Bluetooth LE host for Linux and BlueZ.
//!
//! The host serves one connection as a peripheral: L2CAP with the fixed
//! channels for ATT, signalling and the security manager, a GATT server over
//! a constant attribute table, LE Secure Connections pairing as responder
//! (Just Works) with bonding, and connectable advertising. It talks to the
//! link layer through the typed API of [`crate::link`], not through HCI.
//!
//! The protocol core ([`l2cap`], [`signal`], [`att`], [`gatt`], [`smp`] and
//! [`engine`]) holds no futures and touches no peripheral, so it runs in the
//! host tests on the PC; only the async glue around the [`engine`] uses the
//! link layer. Every buffer is a fixed array: no heap and no allocation.
//!
//! Every call into the host comes from thread mode, as its state sits behind a
//! thread mode mutex rather than a critical section, which would hold off the
//! link layer during the longer AES computations of pairing.

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

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt as _, KeyInit as _},
    };

    /// Software AES-128 in place of the ECB.
    struct Software;

    impl Aes for Software {
        fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
            let mut data = block.into();
            Aes128::new(&key.into()).encrypt_block(&mut data);
            data.into()
        }
    }

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
