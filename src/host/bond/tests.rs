//! Tests of the bond and its stored form.

use super::*;
use crate::host::{example, gatt::Value};

crate::gatt! {
    /// A table with Service Changed and one more descriptor.
    const CHANGED_DB;
    service 0x1801 {
        char 0x2A05 [indicate] = Value::Empty;
        ccc;
    }
    service 0x180F {
        char 0x2A19 [read, notify] = Value::Const(&[50]);
        ccc;
    }
}

/// The long term key of the tests.
const LTK: [u8; 16] = [0x11; 16];
/// A central's identity resolving key.
const IRK: [u8; 16] = [0x22; 16];

/// A bond with `BlueZ`'s public identity and no key of its, on the example
/// table.
fn example_bond() -> Bond {
    Bond::new(IdentityAddress::valid(Peer::new([1, 2, 3, 4, 5, 6], false)), None, LTK, Variant::new(0, 3), &example::DB)
}

#[test]
fn the_stored_form_has_the_documented_layout() {
    let mut bond = example_bond();
    bond.cccd = 0x0000_0155;
    let bytes = bond.to_bytes();
    assert_eq!(bytes.len(), BOND_LEN);
    assert_eq!(bytes[..8], [BOND_VERSION, 0x00, 1, 2, 3, 4, 5, 6]);
    assert_eq!(bytes[8..24], [0; 16]);
    assert_eq!(bytes[24..40], LTK);
    assert_eq!(bytes[40..42], [0x00, 0x03]);
    assert_eq!(bytes[42..46], [0x55, 0x01, 0x00, 0x00]);
    assert_eq!(bytes[46..], [0; 4]);
    assert!(Bond::from_bytes(&bytes) == Some(bond));
}

#[test]
fn every_field_survives_the_round_trip() {
    let mut bond = Bond::new(
        IdentityAddress::valid(Peer::new([9, 8, 7, 6, 5, 0xC4], true)),
        Some(IRK),
        LTK,
        Variant::new(2, 255),
        &CHANGED_DB,
    );
    bond.authenticated = true;
    bond.cccd = 0b10_01;
    let bytes = bond.to_bytes();
    assert_eq!(bytes[1], 0x0F);
    assert_eq!(bytes[8..24], IRK);
    assert_eq!(bytes[46..], CHANGED_DB.hash()[..4]);
    let decoded = Bond::from_bytes(&bytes).unwrap();
    assert!(decoded == bond);
    assert!(decoded.peer.peer() == Peer::new([9, 8, 7, 6, 5, 0xC4], true));
    assert_eq!(decoded.peer_irk, Some(IRK));
    assert_eq!(decoded.ltk, LTK);
    assert_eq!(decoded.local, Variant::new(2, 255));
    assert!(decoded.authenticated);
    assert_eq!(decoded.cccd, 0b10_01);
    assert_eq!(decoded.layout, Some(u32::from_le_bytes(CHANGED_DB.hash()[..4].try_into().unwrap())));
    assert!(decoded.directed_works);
}

#[test]
fn directed_advertising_that_went_unanswered_is_stored_in_bit_4() {
    let mut bond = example_bond();
    assert!(bond.directed_works);
    bond.directed_works = false;
    let bytes = bond.to_bytes();
    assert_eq!(bytes[1], 0x10);
    let decoded = Bond::from_bytes(&bytes).unwrap();
    assert!(!decoded.directed_works);
    assert!(decoded == bond);
    // A record with the bit clear: directed advertising works, as for a new
    // bond.
    let mut clear = bytes;
    clear[1] = 0;
    assert!(Bond::from_bytes(&clear).unwrap().directed_works);
}

#[test]
fn the_stored_form_keeps_its_length_and_version() {
    assert_eq!(BOND_LEN, 50);
    assert_eq!(BOND_VERSION, 1);
}

#[test]
fn client_features_are_stored_in_bits_5_to_7() {
    for features in 0..=CLIENT_FEATURES {
        let mut bond = example_bond();
        bond.client_features = features;
        let bytes = bond.to_bytes();
        assert_eq!(bytes[1], features.strict_mul(0x20));
        let decoded = Bond::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.client_features, features);
        assert!(decoded == bond);
        // The other flags keep their bits beside them.
        let mut other = Bond::new(
            IdentityAddress::valid(Peer::new([9, 8, 7, 6, 5, 0xC4], true)),
            Some(IRK),
            LTK,
            Variant::new(1, 2),
            &CHANGED_DB,
        );
        other.authenticated = true;
        other.directed_works = false;
        other.client_features = features;
        let bytes = other.to_bytes();
        assert_eq!(bytes[1], 0x1F | features.strict_mul(0x20));
        assert!(Bond::from_bytes(&bytes) == Some(other));
    }
}

#[test]
fn client_features_past_bit_2_are_not_stored() {
    let mut bond = example_bond();
    bond.client_features = 0xFF;
    let bytes = bond.to_bytes();
    assert_eq!(bytes[1], 0xE0);
    assert_eq!(Bond::from_bytes(&bytes).unwrap().client_features, 0x07);
    bond.client_features = 0xF8;
    assert_eq!(bond.to_bytes()[1], 0x00);
}

#[test]
fn a_record_from_before_client_features_reads_none() {
    // A record with bits 5 to 7 clear and every other flag set: a static
    // random identity, an identity resolving key, an authenticated pairing,
    // a layout and directed advertising unanswered.
    let mut record = [0; BOND_LEN];
    record[0] = BOND_VERSION;
    record[1] = 0x1F;
    record[2..8].copy_from_slice(&[9, 8, 7, 6, 5, 0xC4]);
    record[8..24].copy_from_slice(&IRK);
    record[24..40].copy_from_slice(&LTK);
    record[40..42].copy_from_slice(&[0x02, 0x01]);
    record[42..46].copy_from_slice(&[0x05, 0, 0, 0]);
    record[46..].copy_from_slice(&[0xA1, 0xB2, 0xC3, 0xD4]);
    let decoded = Bond::from_bytes(&record).unwrap();
    assert_eq!(decoded.client_features, 0);
    assert!(decoded.peer.peer() == Peer::new([9, 8, 7, 6, 5, 0xC4], true));
    assert_eq!(decoded.peer_irk, Some(IRK));
    assert!(decoded.authenticated && !decoded.directed_works);
    assert_eq!(decoded.layout, Some(0xD4C3_B2A1));
    assert_eq!(decoded.cccd, 5);
    // It is stored again as it was.
    assert_eq!(decoded.to_bytes(), record);
}

#[test]
fn a_build_from_before_client_features_refuses_a_record_with_them() {
    // Bits 0 to 4: a bond with Client Supported Features bits sets a flag
    // beyond them, a bond without them does not.
    const FLAGS_0_TO_4: u8 = 0x1F;
    for features in 0..=CLIENT_FEATURES {
        let mut bond = example_bond();
        bond.directed_works = false;
        bond.client_features = features;
        let flags = bond.to_bytes()[1];
        assert_eq!(flags & !FLAGS_0_TO_4 != 0, features != 0);
    }
}

#[test]
fn erased_flash_zeros_and_other_versions_are_refused() {
    assert!(Bond::from_bytes(&[0xFF; BOND_LEN]).is_none());
    assert!(Bond::from_bytes(&[0; BOND_LEN]).is_none());
    let mut bytes = example_bond().to_bytes();
    bytes[0] = BOND_VERSION + 1;
    assert!(Bond::from_bytes(&bytes).is_none());
}

#[test]
fn contradicting_fields_are_refused() {
    let good = example_bond().to_bytes();
    let refused = |change: &dyn Fn(&mut [u8; BOND_LEN])| {
        let mut bytes = good;
        change(&mut bytes);
        Bond::from_bytes(&bytes).is_none()
    };
    // A key without its flag, and the flag without a key.
    assert!(refused(&|bytes| bytes[8] = 1));
    assert!(refused(&|bytes| bytes[1] |= FLAG_IRK));
    // A layout without its flag.
    assert!(refused(&|bytes| bytes[49] = 1));
    // No long term key.
    assert!(refused(&|bytes| bytes[24..40].fill(0)));
    // No address, and a random identity address that is not static.
    assert!(refused(&|bytes| bytes[2..8].fill(0)));
    assert!(refused(&|bytes| {
        bytes[1] |= FLAG_RANDOM;
        bytes[7] = 0x46;
    }));
    // A static random one is an identity.
    assert!(!refused(&|bytes| {
        bytes[1] |= FLAG_RANDOM;
        bytes[7] = 0xC6;
    }));
    // A layout flagged with zeros is a layout of zero.
    let mut bytes = good;
    bytes[1] |= FLAG_LAYOUT;
    assert_eq!(Bond::from_bytes(&bytes).unwrap().layout, Some(0));
}

#[test]
fn the_example_bond_keeps_no_layout() {
    let bond = example_bond();
    assert_eq!(example::DB.service_changed(), None);
    assert_eq!(bond.layout, None);
    assert!(bond.layout_known(&example::DB));
    // Even a bond with a layout knows a table without Service Changed.
    let mut other = example_bond();
    other.layout = Some(7);
    assert!(other.layout_known(&example::DB));
}

#[test]
fn a_table_with_service_changed_compares_the_layout() {
    let mut bond =
        Bond::new(IdentityAddress::valid(Peer::new([1; 6], false)), None, LTK, Variant::new(0, 0), &CHANGED_DB);
    assert!(bond.layout_known(&CHANGED_DB));
    bond.layout = bond.layout.map(|layout| layout ^ 1);
    assert!(!bond.layout_known(&CHANGED_DB));
    // A bond from a table without Service Changed has none to compare.
    bond.layout = None;
    assert!(!bond.layout_known(&CHANGED_DB));
}

#[test]
fn subscriptions_past_the_tables_descriptors_are_left_out() {
    let mut bond = example_bond();
    bond.cccd = u32::MAX;
    let cccds = u32::from(example::DB.cccds());
    assert_eq!(bond.subscriptions(&example::DB).bits(), 1_u32.unbounded_shl(2 * cccds).wrapping_sub(1));
    bond.cccd = 0b01_00_01;
    assert_eq!(bond.subscriptions(&example::DB).bits(), 0b01_00_01);
    assert!(bond.subscriptions(&example::DB).notifying(2));
    assert_eq!(bond.subscriptions(&CHANGED_DB).bits(), 0b00_01);
}
