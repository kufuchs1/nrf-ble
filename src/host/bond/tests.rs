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
    Bond::new(Peer::new([1, 2, 3, 4, 5, 6], false), None, LTK, Variant::new(0, 3), &example::DB)
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
    let mut bond = Bond::new(Peer::new([9, 8, 7, 6, 5, 0xC4], true), Some(IRK), LTK, Variant::new(2, 255), &CHANGED_DB);
    bond.authenticated = true;
    bond.cccd = 0b10_01;
    let bytes = bond.to_bytes();
    assert_eq!(bytes[1], 0x0F);
    assert_eq!(bytes[8..24], IRK);
    assert_eq!(bytes[46..], CHANGED_DB.hash()[..4]);
    let decoded = Bond::from_bytes(&bytes).unwrap();
    assert!(decoded == bond);
    assert!(decoded.peer == Peer::new([9, 8, 7, 6, 5, 0xC4], true));
    assert_eq!(decoded.peer_irk, Some(IRK));
    assert_eq!(decoded.ltk, LTK);
    assert_eq!(decoded.local, Variant::new(2, 255));
    assert!(decoded.authenticated);
    assert_eq!(decoded.cccd, 0b10_01);
    assert_eq!(decoded.layout, Some(u32::from_le_bytes(CHANGED_DB.hash()[..4].try_into().unwrap())));
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
    // An unknown flag.
    assert!(refused(&|bytes| bytes[1] |= 0x10));
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
    let mut bond = Bond::new(Peer::new([1; 6], false), None, LTK, Variant::new(0, 0), &CHANGED_DB);
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
    assert_eq!(bond.subscriptions(&example::DB).bits(), (1 << (2 * cccds)) - 1);
    bond.cccd = 0b01_00_01;
    assert_eq!(bond.subscriptions(&example::DB).bits(), 0b01_00_01);
    assert!(bond.subscriptions(&example::DB).notifying(2));
    assert_eq!(bond.subscriptions(&CHANGED_DB).bits(), 0b00_01);
}
