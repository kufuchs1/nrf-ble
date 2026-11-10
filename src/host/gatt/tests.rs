//! Tests of the table builder, the example table and the layout hash.

use super::*;
use crate::host::example::{self, DB, PARAMS, REPORT_MAP, REPORT_MAP_LEN};

/// The example table again, with `$map` as its Report Map.
macro_rules! example_with {
    ($name:ident, $map:expr) => {
        crate::gatt! {
            const $name;
            service 0x1800 {
                char 0x2A00 [read] = Value::Const(example::NAME);
                char 0x2A01 [read] = Value::Const(&example::APPEARANCE);
                char 0x2A04 [read] = Value::Const(&ppcp(PARAMS));
            }
            service 0x1801 {
                char 0x2B2A [read] = Value::Hash;
            }
            service 0x180F {
                char 0x2A19 [read, notify] = Value::Dynamic(example::BATTERY_LEVEL_VALUE);
                ccc;
            }
            service 0x180A {
                char 0x2A50 [read] = Value::Const(&example::PNP_ID);
            }
            service 0x1812 {
                char 0x2A4A [read] = Value::Const(&example::HID_INFORMATION);
                char 0x2A4B [read] = Value::Const(&$map);
                char 0x2A4C [write_without_response] = Value::Sink;
                char 0x2A4D [read, notify; encrypted] = Value::Zeros(8);
                ccc;
                desc 0x2908 [read] = Value::Const(&[1, 1]);
                char 0x2A4D [read, notify; encrypted] = Value::Zeros(2);
                ccc;
                desc 0x2908 [read] = Value::Const(&[2, 1]);
                char 0x2A4D [read, notify; encrypted] = Value::Zeros(5);
                ccc;
                desc 0x2908 [read] = Value::Const(&[3, 1]);
            }
        }
    };
}

/// The Report Map with one octet changed.
const ALTERED_MAP: [u8; REPORT_MAP_LEN] = {
    let mut map = REPORT_MAP;
    map[60] ^= 0x01;
    map
};

example_with!(SAME, REPORT_MAP);
example_with!(ALTERED, ALTERED_MAP);

#[test]
fn the_example_table_has_its_handles() {
    assert_eq!(DB.last_handle(), 36);
    assert_eq!(DB.attrs().len(), 36);
    assert_eq!(DB.cccds(), 4);
    assert_eq!(DB.service_changed(), None);
    assert_eq!(example::BATTERY_LEVEL.handle(), 13);
    assert_eq!(example::BATTERY_LEVEL.cccd(), Some(0));
    assert_eq!(example::BATTERY_LEVEL.sec(), Sec::Open);
    assert_eq!(example::KEYBOARD.handle(), 26);
    assert_eq!(example::KEYBOARD.cccd(), Some(1));
    assert_eq!(example::KEYBOARD.sec(), Sec::Encrypted);
    assert_eq!(example::KEYBOARD.props(), PROP_READ | PROP_NOTIFY);
    assert_eq!(example::CONSUMER.handle(), 30);
    assert_eq!(example::CONSUMER.cccd(), Some(2));
    assert_eq!(example::MOUSE.handle(), 34);
    assert_eq!(example::MOUSE.cccd(), Some(3));
    let services: [u16; 5] = [1, 8, 11, 15, 18];
    let ends: [u16; 5] = [7, 10, 14, 17, 36];
    for (start, end) in services.into_iter().zip(ends) {
        assert_eq!(DB.attr(start).unwrap().kind(), Kind::Service);
        assert_eq!(DB.group_end(start), end);
    }
    assert!(DB.attr(0).is_none());
    assert!(DB.attr(37).is_none());
}

#[test]
fn the_example_values_are_as_given() {
    assert_eq!(ppcp(PARAMS), [0x0C, 0x00, 0x0C, 0x00, 0x1E, 0x00, 0x58, 0x02]);
    assert_eq!(example::PNP_ID, [0x02, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01]);
    assert_eq!(example::HID_INFORMATION, [0x11, 0x01, 0x00, 0x03]);
    assert_eq!(example::APPEARANCE, 0x03C1_u16.to_le_bytes());
    assert_eq!(REPORT_MAP.len(), 126);
    let ppcp_value = ppcp(PARAMS);
    let Value::Const(bytes) = DB.attr(7).unwrap().value_source() else { panic!("the PPCP is no constant") };
    assert_eq!(bytes, ppcp_value);
}

/// Checks that the collections of `map` are balanced and returns the
/// report IDs it declares with the bits of input each report carries.
fn input_reports(map: &[u8]) -> [(u8, u32); 3] {
    let mut reports = [(0_u8, 0_u32); 3];
    let mut current = None;
    let (mut size, mut count, mut depth) = (0_u32, 0_u32, 0_i32);
    let mut rest = map;
    while let [prefix, tail @ ..] = rest {
        let len = match prefix & 0x03 {
            3 => 4,
            other => usize::from(other),
        };
        let data = &tail[..len];
        let value = data.iter().rev().fold(0_u32, |value, &byte| value << 8 | u32::from(byte));
        match prefix & 0xFC {
            0x84 => {
                let slot = reports.iter().position(|&(id, _)| id == 0).unwrap();
                reports[slot].0 = u8::try_from(value).unwrap();
                current = Some(slot);
            },
            0x74 => size = value,
            0x94 => count = value,
            0x80 => reports[current.unwrap()].1 += size * count,
            0xA0 => depth += 1,
            0xC0 => depth -= 1,
            _ => {},
        }
        rest = &tail[len..];
    }
    assert_eq!(depth, 0);
    reports
}

#[test]
fn the_report_map_declares_the_three_input_reports_with_their_lengths() {
    let reports = input_reports(&REPORT_MAP);
    assert_eq!(reports, [
        (example::KEYBOARD_REPORT_ID, u32::from(example::KEYBOARD_REPORT_LEN) * 8),
        (example::CONSUMER_REPORT_ID, u32::from(example::CONSUMER_REPORT_LEN) * 8),
        (example::MOUSE_REPORT_ID, u32::from(example::MOUSE_REPORT_LEN) * 8),
    ]);
}

#[test]
fn the_hash_follows_the_table_and_one_report_map_octet() {
    assert_eq!(SAME.hash(), DB.hash());
    assert_ne!(ALTERED.hash(), DB.hash());
    assert_ne!(DB.hash(), [0; 16]);
}

#[test]
fn the_hash_follows_the_layout() {
    crate::gatt! {
        const ONE;
        service 0x180F {
            char 0x2A19 [read] = Value::Const(&[50]);
        }
    }
    crate::gatt! {
        const OTHER_UUID;
        service 0x180F {
            char 0x2A1A [read] = Value::Const(&[50]);
        }
    }
    crate::gatt! {
        const OTHER_PROPS;
        service 0x180F {
            char 0x2A19 [read, write] = Value::Const(&[50]);
        }
    }
    crate::gatt! {
        const OTHER_SECURITY;
        service 0x180F {
            char 0x2A19 [read; encrypted] = Value::Const(&[50]);
        }
    }
    crate::gatt! {
        const EXTRA_DESCRIPTOR;
        service 0x180F {
            char 0x2A19 [read] = Value::Const(&[50]);
            desc 0x2901 [read] = Value::Const(b"level");
        }
    }
    let hashes = [ONE.hash(), OTHER_UUID.hash(), OTHER_PROPS.hash(), OTHER_SECURITY.hash(), EXTRA_DESCRIPTOR.hash()];
    for (index, hash) in hashes.iter().enumerate() {
        for other in &hashes[index + 1..] {
            assert_ne!(hash, other);
        }
    }
}

#[test]
fn notify_and_indicate_only_characteristics_keep_their_security() {
    crate::gatt! {
        const SILENT;
        service 0x1812 {
            char SECRET_NOTIFY: 0x2A4D [notify; encrypted] = Value::Zeros(8);
            ccc;
            char SECRET_INDICATE: 0x2A4D [indicate; encrypted] = Value::Empty;
            ccc;
            char OPEN_NOTIFY: 0x2A4D [notify] = Value::Zeros(8);
            ccc;
        }
    }
    crate::gatt! {
        const OPEN;
        service 0x1812 {
            char 0x2A4D [notify] = Value::Zeros(8);
            ccc;
            char 0x2A4D [indicate; encrypted] = Value::Empty;
            ccc;
            char 0x2A4D [notify] = Value::Zeros(8);
            ccc;
        }
    }
    assert_eq!(SECRET_NOTIFY.sec(), Sec::Encrypted);
    assert_eq!(SECRET_INDICATE.sec(), Sec::Encrypted);
    assert_eq!(OPEN_NOTIFY.sec(), Sec::Open);
    let value = SILENT.attr(SECRET_NOTIFY.handle()).unwrap();
    assert_eq!(value.kind(), Kind::Value(Access { read: None, write: None }, Sec::Encrypted));
    let descriptor = SILENT.attr(SECRET_NOTIFY.handle() + 1).unwrap();
    assert_eq!(descriptor.access(), Access { read: Some(Sec::Encrypted), write: Some(Sec::Encrypted) });
    // The tables differ only in the level of the first characteristic, and
    // their first three attributes only in that of its value, which can
    // be neither read nor written: the hash follows it all the same.
    assert_ne!(SILENT.hash(), OPEN.hash());
    assert_ne!(
        hash::layout(&[SILENT.attrs()[0], SILENT.attrs()[1], SILENT.attrs()[2]]),
        hash::layout(&[OPEN.attrs()[0], OPEN.attrs()[1], OPEN.attrs()[2]]),
    );
}

#[test]
fn subscriptions_keep_the_allowed_bits_and_what_this_link_wrote() {
    let mut subscriptions = Subscriptions::new();
    subscriptions.set(1, 0x0003, PROP_NOTIFY | PROP_READ);
    assert_eq!(subscriptions.value(1), CCC_NOTIFY);
    assert!(subscriptions.notifying(1));
    assert!(!subscriptions.indicating(1));
    assert!(subscriptions.is_written(1));
    assert!(!subscriptions.is_written(0));
    subscriptions.set(15, 0xFFFF, PROP_INDICATE);
    assert_eq!(subscriptions.value(15), CCC_INDICATE);
    subscriptions.set(16, 0x0001, PROP_NOTIFY);
    assert_eq!(subscriptions.value(16), 0);
    let restored = Subscriptions::from_bits(subscriptions.bits());
    assert_eq!(restored.value(1), CCC_NOTIFY);
    assert!(!restored.is_written(1));
    subscriptions.set(1, 0x0000, PROP_NOTIFY);
    assert!(!subscriptions.notifying(1));
}

#[test]
fn uuids_match_their_short_and_long_forms() {
    let short = Uuid::U16(0x2803);
    assert!(short.matches(&[0x03, 0x28]));
    assert!(!short.matches(&[0x03, 0x28, 0x00]));
    let mut long = BASE_UUID;
    long[12] = 0x03;
    long[13] = 0x28;
    assert!(short.matches(&long));
    assert_eq!(short.to_u128(), long);
    static CUSTOM: [u8; 16] = [7; 16];
    assert!(Uuid::U128(&CUSTOM).matches(&[7; 16]));
    assert!(!Uuid::U128(&CUSTOM).matches(&[7, 7]));
    assert_eq!(Uuid::U128(&CUSTOM).wire_len(), 16);
}

#[test]
fn security_levels_are_ordered() {
    assert!(Sec::Open.met_by(Sec::Open));
    assert!(!Sec::Encrypted.met_by(Sec::Open));
    assert!(Sec::Encrypted.met_by(Sec::Authenticated));
    assert!(!Sec::Authenticated.met_by(Sec::Encrypted));
    assert_eq!(AttError::application(0x85).code(), 0x85);
    assert_eq!(AttError::application(0x05).code(), 0x80);
}
