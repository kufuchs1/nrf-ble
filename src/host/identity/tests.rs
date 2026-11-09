//! Tests of the local identity.

use super::*;
use crate::host::test_aes::Software;

/// A device secret with the roots 0 to 15 and 16 to 31.
fn secret() -> DeviceSecret {
    DeviceSecret::new(
        core::array::from_fn(|index| u8::try_from(index).unwrap()),
        core::array::from_fn(|index| u8::try_from(index + 16).unwrap()),
    )
}

#[test]
fn variants_hold_a_slot_and_a_generation() {
    let variant = Variant::new(2, 5);
    assert_eq!(variant.bits(), 0x0502);
    assert_eq!((variant.slot(), variant.generation()), (2, 5));
    assert_eq!(Variant::from_bits(0x0502), variant);
    assert_eq!(variant.block()[..3], [0x02, 0x05, 0x00]);
    assert_eq!(variant.next_generation(), Variant::new(2, 6));
    // The generation wraps and the slot stays.
    assert_eq!(Variant::new(1, 255).next_generation(), Variant::new(1, 0));
}

#[test]
fn ficr_words_are_taken_least_significant_octet_first() {
    let from_words = DeviceSecret::from_words([0x0302_0100, 0x0706_0504, 0x0B0A_0908, 0x0F0E_0D0C], [
        0x1312_1110,
        0x1716_1514,
        0x1B1A_1918,
        0x1F1E_1D1C,
    ]);
    let expected = secret();
    assert_eq!((from_words.er, from_words.ir), (expected.er, expected.ir));
}

#[test]
fn the_identity_is_the_roots_encrypting_the_variant() {
    let variant = Variant::new(0, 1);
    let identity = LocalIdentity::derive(&Software, &secret(), variant);
    let block = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut address = *Software.encrypt(secret().er, block).first_chunk::<6>().unwrap();
    address[5] |= 0xC0;
    assert_eq!(identity.address(), address);
    assert_eq!(identity.irk(), Software.encrypt(secret().ir, block));
    assert_eq!(identity.variant(), variant);
    assert!(identity.peer() == Peer::new(address, true));
}

/// The address [`the_derivation_is_pinned`] expects, computed with another
/// AES implementation (Python's `cryptography`): its top two bits happen to
/// be set already.
const PINNED_ADDRESS: [u8; 6] = [0x9E, 0xB1, 0xB6, 0x3C, 0x7E, 0xFE];
/// The key [`the_derivation_is_pinned`] expects, computed the same way.
const PINNED_IRK: [u8; 16] =
    [0xFC, 0x62, 0xD8, 0x0E, 0x67, 0x73, 0xA8, 0x77, 0x1A, 0xD0, 0xF2, 0xB6, 0x9E, 0x53, 0xB8, 0xD2];

#[test]
fn the_derivation_is_pinned() {
    // The values of the scheme for these roots: a change here changes every
    // device's address and orphans its bonds.
    let identity = LocalIdentity::derive(&Software, &secret(), Variant::new(0, 1));
    assert_eq!(identity.address(), PINNED_ADDRESS);
    assert_eq!(identity.irk(), PINNED_IRK);
}

#[test]
fn every_variant_gives_a_static_random_identity_of_its_own() {
    let secret = secret();
    let mut seen = [([0; 6], [0; 16]); 64];
    for (index, entry) in seen.iter_mut().enumerate() {
        let index = u8::try_from(index).unwrap();
        let identity = LocalIdentity::derive(&Software, &secret, Variant::new(index % 4, index / 4));
        assert_eq!(identity.address()[5] & 0xC0, 0xC0);
        assert_ne!(identity.irk(), [0; 16]);
        *entry = (identity.address(), identity.irk());
    }
    for (index, entry) in seen.iter().enumerate() {
        assert!(seen[index + 1..].iter().all(|other| other.0 != entry.0 && other.1 != entry.1));
    }
}

#[test]
fn a_new_pairing_gives_a_new_identity() {
    let secret = secret();
    let first = LocalIdentity::derive(&Software, &secret, Variant::new(0, 0));
    let second = LocalIdentity::derive(&Software, &secret, Variant::new(0, 0).next_generation());
    assert_ne!(first.address(), second.address());
    assert_ne!(first.irk(), second.irk());
    // The same variant gives the same identity again.
    assert!(first == LocalIdentity::derive(&Software, &secret, Variant::new(0, 0)));
}

#[test]
fn static_random_addresses_have_the_type_bits_and_a_random_part() {
    assert_eq!(static_random([1, 2, 3, 4, 5, 6]), [1, 2, 3, 4, 5, 0xC6]);
    assert_eq!(static_random([0, 0, 0, 0, 0, 0xC0]), [1, 0, 0, 0, 0, 0xC0]);
    assert_eq!(static_random([0xFF; 6]), [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(static_random([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]), [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}
