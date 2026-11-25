//! Tests of the table builder, the example table and the layout hash.

extern crate alloc;
#[cfg(feature = "eatt")] extern crate std;

use super::*;
use crate::host::example::{self, DB, EATT_SHIFT, PARAMS, REPORT_MAP, REPORT_MAP_LEN};
use alloc::vec::Vec;
#[cfg(feature = "eatt")]
use std::panic::catch_unwind;

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
                #[cfg(feature = "eatt")]
                char 0x2B29 [read, write] = Value::ClientFeatures;
                #[cfg(feature = "eatt")]
                char 0x2B3A [read] = Value::ServerFeatures;
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

/// The Client and Server Supported Features as `eatt` takes them.
#[cfg(feature = "eatt")]
const FEATURES: [Characteristic; 2] = [
    (CLIENT_SUPPORTED_FEATURES, PROP_READ | PROP_WRITE, Sec::Open, Value::ClientFeatures),
    (SERVER_SUPPORTED_FEATURES, PROP_READ, Sec::Open, Value::ServerFeatures),
];

example_with!(SAME, REPORT_MAP);
example_with!(ALTERED, ALTERED_MAP);

/// A characteristic of [`features_table`]: its UUID, properties and security
/// and the value it holds.
type Characteristic = (u16, u8, Sec, Value);

#[cfg(feature = "eatt")]
#[test]
fn with_eatt_the_features_are_found_once_each_in_the_gatt_service() {
    assert!(features_table(GATT_SERVICE, &FEATURES).has_features());
    assert!(!features_table(GATT_SERVICE, &FEATURES[..1]).has_features());
    assert!(!features_table(GATT_SERVICE, &FEATURES[1..]).has_features());
    assert!(!features_table(GATT_SERVICE, &[]).has_features());
    assert!(!example::DB.attrs().is_empty() && example::DB.has_features());
}

#[test]
fn the_example_table_has_its_handles() {
    // With `eatt`, 4 more after the Database Hash.
    let shift = EATT_SHIFT;
    assert_eq!(DB.last_handle(), 36 + shift);
    assert_eq!(DB.attrs().len(), usize::from(36 + shift));
    assert_eq!(DB.cccds(), 4);
    assert_eq!(DB.service_changed(), None);
    assert_eq!(example::BATTERY_LEVEL.handle(), 13 + shift);
    assert_eq!(example::BATTERY_LEVEL.cccd(), Some(0));
    assert_eq!(example::BATTERY_LEVEL.sec(), Sec::Open);
    assert_eq!(example::KEYBOARD.handle(), 26 + shift);
    assert_eq!(example::KEYBOARD.cccd(), Some(1));
    assert_eq!(example::KEYBOARD.sec(), Sec::Encrypted);
    assert_eq!(example::KEYBOARD.props(), PROP_READ | PROP_NOTIFY);
    assert_eq!(example::CONSUMER.handle(), 30 + shift);
    assert_eq!(example::CONSUMER.cccd(), Some(2));
    assert_eq!(example::MOUSE.handle(), 34 + shift);
    assert_eq!(example::MOUSE.cccd(), Some(3));
    let services: [u16; 5] = [1, 8, 11 + shift, 15 + shift, 18 + shift];
    let ends: [u16; 5] = [7, 10 + shift, 14 + shift, 17 + shift, 36 + shift];
    for (start, end) in services.into_iter().zip(ends) {
        assert_eq!(assert_some!(DB.attr(start)).kind(), Kind::Service);
        assert_eq!(DB.group_end(start), end);
    }
    assert!(DB.attr(0).is_none());
    assert!(DB.attr(37 + shift).is_none());
    #[cfg(feature = "eatt")]
    {
        assert!(DB.has_features());
        for (handle, uuid, props, value) in [
            (example::CLIENT_FEATURES, CLIENT_SUPPORTED_FEATURES, PROP_READ | PROP_WRITE, Value::ClientFeatures),
            (example::SERVER_FEATURES, SERVER_SUPPORTED_FEATURES, PROP_READ, Value::ServerFeatures),
        ] {
            assert_eq!(assert_some!(DB.attr(handle - 1)).kind(), Kind::Characteristic(props));
            let attr = assert_some!(DB.attr(handle));
            assert_eq!((attr.uuid(), attr.value_source()), (Uuid::U16(uuid), value));
            assert_eq!(attr.access(), Access::from_props(props, Sec::Open));
        }
    }
}

#[test]
fn the_example_values_are_as_given() {
    assert_eq!(ppcp(PARAMS), [0x0C, 0x00, 0x0C, 0x00, 0x1E, 0x00, 0x58, 0x02]);
    assert_eq!(example::PNP_ID, [0x02, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01]);
    assert_eq!(example::HID_INFORMATION, [0x11, 0x01, 0x00, 0x03]);
    assert_eq!(example::APPEARANCE, 0x03C1_u16.to_le_bytes());
    assert_eq!(REPORT_MAP.len(), 126);
    let ppcp_value = ppcp(PARAMS);
    let Value::Const(bytes) = ({
        let value = assert_some!(DB.attr(7)).value_source();
        assert!(matches!(value, Value::Const(_)), "the PPCP is no constant");
        value
    }) else {
        return;
    };
    assert_eq!(bytes, ppcp_value);
}

/// Checks that the collections of `map` are balanced and returns the
/// report IDs it declares with the bits of input each report carries.
fn input_reports(map: &[u8]) -> [(u8, u32); 3] {
    let mut reports = [(0_u8, 0_u32); 3];
    let mut current = None;
    let (mut size, mut count, mut depth) = (0_u32, 0_u32, 0_i32);
    let mut rest = map;
    while let Some((&prefix, tail)) = rest.split_first() {
        let len = match prefix & 0x03 {
            3 => 4,
            other => usize::from(other),
        };
        // The item's data, 0 to 4 octets, least significant first.
        let data = tail.get(..len);
        assert!(data.is_some(), "the data of item {prefix:#04X}");
        let mut octets = [0_u8; 4];
        octets.get_mut(..len).unwrap_or_default().copy_from_slice(data.unwrap_or_default());
        let value = u32::from_le_bytes(octets);
        match prefix & 0xFC {
            0x84 => {
                current = reports.iter().position(|&(id, _)| id == 0);
                assert!(current.is_some(), "at most three report IDs");
                if let Some(report) = current.and_then(|slot| reports.get_mut(slot)) {
                    report.0 = value.strict_cast();
                }
            },
            0x74 => size = value,
            0x94 => count = value,
            0x80 => {
                assert!(current.is_some(), "an input item after a report ID");
                if let Some(report) = current.and_then(|slot| reports.get_mut(slot)) {
                    report.1 = report.1.strict_add(size.strict_mul(count));
                }
            },
            0xA0 => depth = depth.strict_add(1),
            0xC0 => depth = depth.strict_sub(1),
            _ => {},
        }
        rest = tail.get(len..).unwrap_or_default();
    }
    assert_eq!(depth, 0_i32);
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
        for other in hashes.get(index.strict_add(1)..).unwrap_or_default() {
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
    let value = assert_some!(SILENT.attr(SECRET_NOTIFY.handle()));
    assert_eq!(value.kind(), Kind::Value(Access { read: None, write: None }, Sec::Encrypted));
    let descriptor = assert_some!(SILENT.attr(SECRET_NOTIFY.handle().strict_add(1)));
    assert_eq!(descriptor.access(), Access { read: Some(Sec::Encrypted), write: Some(Sec::Encrypted) });
    // The tables differ only in the level of the first characteristic, and
    // their first three attributes only in that of its value, which can
    // be neither read nor written: the hash follows it all the same.
    assert_ne!(SILENT.hash(), OPEN.hash());
    assert_ne!(hash::layout(assert_some!(SILENT.attrs().get(..3))), hash::layout(assert_some!(OPEN.attrs().get(..3))),);
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
    static CUSTOM: [u8; 16] = [7; 16];

    let short = Uuid::U16(0x2803);
    assert!(short.matches(&[0x03, 0x28]));
    assert!(!short.matches(&[0x03, 0x28, 0x00]));
    let mut long = BASE_UUID;
    long[12] = 0x03;
    long[13] = 0x28;
    assert!(short.matches(&long));
    assert_eq!(short.to_u128(), long);
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

#[test]
fn a_characteristic_under_cfg_is_in_the_table_only_where_the_condition_holds() {
    crate::gatt! {
        const CONDITIONAL;
        service 0x180F {
            /// Documented before the condition.
            #[cfg(all())]
            char KEPT: 0x2A19 [read] = Value::Const(&[50]);
            #[cfg(any())]
            /// Documented after it.
            char DROPPED: 0x2A1A [read] = Value::Const(&[1]);
            #[cfg(any())]
            char 0x2A1B [read] = Value::Const(&[2]);
            #[cfg(all())]
            char 0x2A1C [read] = Value::Const(&[3]);
            char AFTER: 0x2A1D [read, notify] = Value::Const(&[4]);
            ccc;
        }
    }
    crate::gatt! {
        const PLAIN;
        service 0x180F {
            char 0x2A19 [read] = Value::Const(&[50]);
            char 0x2A1C [read] = Value::Const(&[3]);
            char 0x2A1D [read, notify] = Value::Const(&[4]);
            ccc;
        }
    }
    // The characteristics whose condition fails take no handles: the
    // table is the one without them.
    assert_eq!(CONDITIONAL.last_handle(), 8);
    assert_eq!(CONDITIONAL.hash(), PLAIN.hash());
    assert_eq!((KEPT.handle(), KEPT.cccd()), (3, None));
    assert_eq!((AFTER.handle(), AFTER.cccd()), (7, Some(0)));
    let Value::Const(bytes) = ({
        let value = assert_some!(CONDITIONAL.attr(5)).value_source();
        assert!(matches!(value, Value::Const(_)), "not the kept value");
        value
    }) else {
        return;
    };
    assert_eq!(bytes, [3]);
}

#[test]
fn the_hash_follows_the_feature_characteristics() {
    // Built by hand, as a table may hold them only with `eatt`.
    let gatt = Uuid::U16(GATT_SERVICE);
    let hash = [
        Attr::service(gatt),
        Attr::characteristic(Uuid::U16(DATABASE_HASH), PROP_READ),
        Attr::value(Uuid::U16(DATABASE_HASH), PROP_READ, Sec::Open, Value::Hash),
    ];
    let with = [
        Attr::characteristic(Uuid::U16(SERVER_SUPPORTED_FEATURES), PROP_READ),
        Attr::value(Uuid::U16(SERVER_SUPPORTED_FEATURES), PROP_READ, Sec::Open, Value::Const(&[1])),
    ];
    assert_ne!(hash::layout(&hash), hash::layout(&[&hash[..], &with[..]].concat()));
    assert_ne!(hash::layout(&[&hash[..], &with[..]].concat()), [0; 16]);
}

/// The table of a GATT service (`service` 0x1801) or another, with the
/// Database Hash and then `features`, each a characteristic declared with
/// its UUID, properties and security and holding a value.
fn features_table(service: u16, features: &[Characteristic]) -> Db {
    let mut attrs: Vec<Attr> = Vec::from([
        Attr::service(Uuid::U16(service)),
        Attr::characteristic(Uuid::U16(DATABASE_HASH), PROP_READ),
        Attr::value(Uuid::U16(DATABASE_HASH), PROP_READ, Sec::Open, Value::Hash),
    ]);
    for &(uuid, props, sec, value) in features {
        attrs.push(Attr::characteristic(Uuid::U16(uuid), props));
        attrs.push(Attr::value(Uuid::U16(uuid), props, sec, value));
    }
    Db::new(attrs.leak())
}

/// The Server Supported Features as a table without `eatt` can only give
/// them: a constant.
#[cfg(not(feature = "eatt"))]
#[test]
#[should_panic(expected = "the Client and Server Supported Features characteristics need the feature eatt")]
fn without_eatt_the_server_supported_features_are_refused() {
    features_table(GATT_SERVICE, &[(SERVER_SUPPORTED_FEATURES, PROP_READ, Sec::Open, Value::Const(&[1]))]);
}

#[cfg(not(feature = "eatt"))]
#[test]
#[should_panic(expected = "the Client and Server Supported Features characteristics need the feature eatt")]
fn without_eatt_the_client_supported_features_are_refused() {
    features_table(GATT_SERVICE, &[(CLIENT_SUPPORTED_FEATURES, PROP_READ | PROP_WRITE, Sec::Open, Value::Sink)]);
}

/// Each way the feature characteristics can break the rules, refused.
#[cfg(feature = "eatt")]
#[test]
fn with_eatt_the_features_are_checked() {
    let client = FEATURES[0];
    let server = FEATURES[1];
    let cases: [(u16, Vec<Characteristic>, &str); 8] = [
        (0x180F, Vec::from(FEATURES), "the Client Supported Features are declared once"),
        (GATT_SERVICE, Vec::from([client, client]), "the Client Supported Features are declared once"),
        (GATT_SERVICE, Vec::from([server, server]), "the Server Supported Features are declared once"),
        (GATT_SERVICE, Vec::from([(client.0, PROP_READ, client.2, client.3)]), "the Client Supported Features"),
        (GATT_SERVICE, Vec::from([(server.0, PROP_READ | PROP_WRITE, server.2, server.3)]), "the Server Supported"),
        (GATT_SERVICE, Vec::from([(client.0, client.1, Sec::Encrypted, client.3)]), "are open, with their own values"),
        (GATT_SERVICE, Vec::from([(client.0, client.1, client.2, Value::ServerFeatures)]), "are open, with their own"),
        (GATT_SERVICE, Vec::from([(0x2A19, PROP_READ, Sec::Open, Value::ServerFeatures)]), "belong to their own"),
    ];
    for (service, features, expected) in cases {
        let caught = catch_unwind(|| features_table(service, &features));
        let message = caught.err().and_then(|payload| payload.downcast_ref::<&str>().copied());
        assert!(message.is_some_and(|text| text.contains(expected)), "{features:?}: {message:?}");
    }
    // A descriptor cannot hold them either.
    let attrs = Vec::from([
        Attr::service(Uuid::U16(GATT_SERVICE)),
        Attr::characteristic(Uuid::U16(0x2A19), PROP_READ),
        Attr::value(Uuid::U16(0x2A19), PROP_READ, Sec::Open, Value::Const(&[1])),
        Attr::descriptor(Uuid::U16(0x2901), PROP_READ, Sec::Open, Value::ClientFeatures),
    ]);
    assert!(catch_unwind(|| Db::new(attrs.leak())).err().is_some());
}
