//! Tests of the attribute server: the whole `BlueZ` first connection as golden
//! PDUs against the example table, and the error cases.
//!
//! The example table gains the Client and Server Supported Features with the
//! feature `eatt`, which moves its later handles; these tests run on its
//! layout without them ([`DB`]), so that their PDUs hold in every build, and
//! test the requests of `eatt` on a table of their own.

extern crate alloc;

use super::*;
use crate::host::{
    example::{self, BATTERY_LEVEL_VALUE, PARAMS, REPORT_MAP},
    gatt::{Value, ValueId, ppcp},
};
use alloc::vec::Vec;
use core::cell::Cell;

/// The application's side of the dynamic values in the tests.
struct App {
    /// The battery level.
    level:   u8,
    /// The last value written, with its length and whether a response was
    /// asked for.
    written: Cell<Option<([u8; 4], usize, bool)>>,
}

impl App {
    /// An application with a battery level of 90 %.
    const fn new() -> Self { Self { level: 90, written: Cell::new(None) } }
}

impl Handler for App {
    fn read(&self, id: ValueId, out: &mut [u8]) -> Result<usize, AttError> {
        match id.index() {
            0 => {
                out[0] = self.level;
                Ok(1)
            },
            1 => {
                out[..4].copy_from_slice(&[1, 2, 3, 4]);
                Ok(4)
            },
            _ => Err(AttError::UNLIKELY_ERROR),
        }
    }

    fn write(&self, id: ValueId, data: &[u8], with_response: bool) -> Result<(), AttError> {
        if id.index() != 1 || data.len() > 4 {
            return Err(AttError::application(0x80));
        }
        let mut value = [0; 4];
        value[..data.len()].copy_from_slice(data);
        self.written.set(Some((value, data.len(), with_response)));
        Ok(())
    }
}

crate::gatt! {
    /// The example table without the Client and Server Supported Features:
    /// [`example::DB`] in a build without the feature `eatt`.
    const DB;
    service 0x1800 {
        char 0x2A00 [read] = Value::Const(example::NAME);
        char 0x2A01 [read] = Value::Const(&example::APPEARANCE);
        char 0x2A04 [read] = Value::Const(&ppcp(PARAMS));
    }
    service 0x1801 {
        char 0x2B2A [read] = Value::Hash;
    }
    service 0x180F {
        /// The Battery Level.
        char BATTERY_LEVEL: 0x2A19 [read, notify] = Value::Dynamic(BATTERY_LEVEL_VALUE);
        ccc;
    }
    service 0x180A {
        char 0x2A50 [read] = Value::Const(&example::PNP_ID);
    }
    service 0x1812 {
        char 0x2A4A [read] = Value::Const(&example::HID_INFORMATION);
        char 0x2A4B [read] = Value::Const(&REPORT_MAP);
        char 0x2A4C [write_without_response] = Value::Sink;
        /// The keyboard input report.
        char KEYBOARD: 0x2A4D [read, notify; encrypted] = Value::Zeros(example::KEYBOARD_REPORT_LEN);
        ccc;
        desc 0x2908 [read] = Value::Const(&[example::KEYBOARD_REPORT_ID, example::INPUT_REPORT]);
        /// The consumer control input report.
        char CONSUMER: 0x2A4D [read, notify; encrypted] = Value::Zeros(example::CONSUMER_REPORT_LEN);
        ccc;
        desc 0x2908 [read] = Value::Const(&[example::CONSUMER_REPORT_ID, example::INPUT_REPORT]);
        /// The mouse input report.
        char MOUSE: 0x2A4D [read, notify; encrypted] = Value::Zeros(example::MOUSE_REPORT_LEN);
        ccc;
        desc 0x2908 [read] = Value::Const(&[example::MOUSE_REPORT_ID, example::INPUT_REPORT]);
    }
}

#[test]
fn the_table_is_the_example_s_without_the_features() {
    let full = example::DB.attrs();
    let shift = usize::from(example::EATT_SHIFT);
    assert_eq!(DB.attrs().len() + shift, full.len());
    // The same attributes, but for the four after the Database Hash, handle
    // 10.
    for (index, attr) in DB.attrs().iter().enumerate() {
        let other = &full[if index < 10 { index } else { index + shift }];
        assert_eq!((attr.kind(), attr.uuid(), attr.value_source()), (other.kind(), other.uuid(), other.value_source()));
    }
    assert_eq!(
        (BATTERY_LEVEL.handle() + example::EATT_SHIFT, BATTERY_LEVEL.cccd()),
        (example::BATTERY_LEVEL.handle(), example::BATTERY_LEVEL.cccd())
    );
    for (ours, theirs) in [(KEYBOARD, example::KEYBOARD), (CONSUMER, example::CONSUMER), (MOUSE, example::MOUSE)] {
        assert_eq!(ours.handle() + example::EATT_SHIFT, theirs.handle());
        assert_eq!((ours.cccd(), ours.props(), ours.sec()), (theirs.cccd(), theirs.props(), theirs.sec()));
    }
    if !cfg!(feature = "eatt") {
        assert_eq!(DB.hash(), example::DB.hash());
    }
}

/// An octet a slot holds where no response was written.
const UNWRITTEN: u8 = 0xA5;

/// Sends `request` at `level` and returns the response, if any.
///
/// A copy of the server takes the same request through
/// [`Server::handle_on`] on the fixed channel, into a slot twice as long as
/// [`ATT_MAX`]: it must give the same answer and end in the same state, and
/// leave the octets after its answer as they were.
fn exchange(server: &mut Server, app: &App, request: &[u8], level: Sec) -> Option<Vec<u8>> {
    let mut twin = *server;
    let mut long = [UNWRITTEN; 2 * ATT_MAX];
    let twin_len = twin.handle_on(Bearer::Fixed, request, level, app, &mut long);
    assert!(long[twin_len.unwrap_or(0)..].iter().all(|&octet| octet == UNWRITTEN), "request {request:02X?}");
    let mut out = [0_u8; ATT_MAX];
    let len = server.handle(request, level, app, &mut out);
    assert_eq!(twin_len, len, "request {request:02X?}");
    assert_eq!(twin.subscriptions(), server.subscriptions(), "request {request:02X?}");
    #[cfg(feature = "att-mtu")]
    assert_eq!(twin.mtu, server.mtu, "request {request:02X?}");
    #[cfg(feature = "eatt")]
    {
        assert_eq!(twin.client_features, server.client_features, "request {request:02X?}");
        assert_eq!(
            (twin.prepared.handle, twin.prepared.offset, twin.prepared.value()),
            (server.prepared.handle, server.prepared.offset, server.prepared.value()),
            "request {request:02X?}"
        );
    }
    let len = len?;
    assert_eq!(long[..len], out[..len], "request {request:02X?}");
    Some(out[..len].to_vec())
}

/// Sends `request` on an encrypted link and checks the response against
/// `expected`.
fn golden(server: &mut Server, app: &App, request: &[u8], expected: &[u8]) {
    let response = exchange(server, app, request, Sec::Encrypted);
    assert_eq!(response.as_deref(), Some(expected), "request {request:02X?}");
}

/// The answer to `BlueZ`'s Exchange MTU Request, which offers 517: 23, or
/// with `att-mtu` 65.
#[cfg(not(feature = "att-mtu"))]
const MTU_517: [u8; 3] = [0x03, 0x17, 0x00];
/// The answer to `BlueZ`'s Exchange MTU Request, which offers 517: 23, or
/// with `att-mtu` 65.
#[cfg(feature = "att-mtu")]
const MTU_517: [u8; 3] = [0x03, 0x41, 0x00];

/// The whole first connection of `BlueZ` (research-bluez.md, section 1.1),
/// after pairing: MTU, server features, primary, secondary and include
/// discovery, characteristics, descriptors, the hash, then the profiles'
/// reads and configuration writes. Every response is checked octet by octet.
///
/// With `att-mtu` the client offers 23 here, as one without a larger MTU
/// does, and every answer is the same; `BlueZ`'s connection at 65 is
/// [`the_bluez_first_connection_at_mtu_65_gets_these_answers`].
#[test]
fn the_bluez_first_connection_gets_these_answers() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let s = &mut server;

    // Exchange MTU with 517: the answer is 23.
    #[cfg(not(feature = "att-mtu"))]
    golden(s, &app, &[0x02, 0x05, 0x02], &MTU_517);
    // With `att-mtu`: Exchange MTU with 23, the answer is 65, and the MTU
    // stays 23.
    #[cfg(feature = "att-mtu")]
    golden(s, &app, &[0x02, 0x17, 0x00], &MTU_517);
    #[cfg(feature = "att-mtu")]
    assert_eq!(s.mtu, 23);
    // Server Supported Features: none.
    golden(s, &app, &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x3A, 0x2B], &[0x01, 0x08, 0x01, 0x00, 0x0A]);

    // Primary services, from 1 on, then after the last end, until not found.
    golden(s, &app, &[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &[
        0x11, 0x06, //
        0x01, 0x00, 0x07, 0x00, 0x00, 0x18, //
        0x08, 0x00, 0x0A, 0x00, 0x01, 0x18, //
        0x0B, 0x00, 0x0E, 0x00, 0x0F, 0x18,
    ]);
    golden(s, &app, &[0x10, 0x0F, 0x00, 0xFF, 0xFF, 0x00, 0x28], &[
        0x11, 0x06, //
        0x0F, 0x00, 0x11, 0x00, 0x0A, 0x18, //
        0x12, 0x00, 0x24, 0x00, 0x12, 0x18,
    ]);
    // The last service ends at its real end, 0x0024, so BlueZ asks once
    // more.
    golden(s, &app, &[0x10, 0x25, 0x00, 0xFF, 0xFF, 0x00, 0x28], &[0x01, 0x10, 0x25, 0x00, 0x0A]);
    // Secondary services: none.
    golden(s, &app, &[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x01, 0x28], &[0x01, 0x10, 0x01, 0x00, 0x0A]);

    // Includes, over each service's range: none.
    for (start, end) in [(0x01_u8, 0x07_u8), (0x08, 0x0A), (0x0B, 0x0E), (0x0F, 0x11), (0x12, 0x24)] {
        golden(s, &app, &[0x08, start, 0x00, end, 0x00, 0x02, 0x28], &[0x01, 0x08, start, 0x00, 0x0A]);
    }

    // Characteristics, over each service's range, from the last value
    // handle on until not found.
    golden(s, &app, &[0x08, 0x01, 0x00, 0x07, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x02, 0x00, 0x02, 0x03, 0x00, 0x00, 0x2A, //
        0x04, 0x00, 0x02, 0x05, 0x00, 0x01, 0x2A, //
        0x06, 0x00, 0x02, 0x07, 0x00, 0x04, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x07, 0x00, 0x07, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x07, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x08, 0x00, 0x0A, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x09, 0x00, 0x02, 0x0A, 0x00, 0x2A, 0x2B,
    ]);
    golden(s, &app, &[0x08, 0x0A, 0x00, 0x0A, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x0A, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x0B, 0x00, 0x0E, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x0C, 0x00, 0x12, 0x0D, 0x00, 0x19, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x0D, 0x00, 0x0E, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x0D, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x0F, 0x00, 0x11, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x10, 0x00, 0x02, 0x11, 0x00, 0x50, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x11, 0x00, 0x11, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x11, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x12, 0x00, 0x24, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x13, 0x00, 0x02, 0x14, 0x00, 0x4A, 0x2A, //
        0x15, 0x00, 0x02, 0x16, 0x00, 0x4B, 0x2A, //
        0x17, 0x00, 0x04, 0x18, 0x00, 0x4C, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x18, 0x00, 0x24, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x19, 0x00, 0x12, 0x1A, 0x00, 0x4D, 0x2A, //
        0x1D, 0x00, 0x12, 0x1E, 0x00, 0x4D, 0x2A, //
        0x21, 0x00, 0x12, 0x22, 0x00, 0x4D, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x22, 0x00, 0x24, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x22, 0x00, 0x0A]);

    // Descriptors: the Battery Level's one handle after its value is taken
    // as its configuration without asking; each report has two.
    for (start, end) in [(0x1B_u8, 0x1C_u8), (0x1F, 0x20), (0x23, 0x24)] {
        golden(s, &app, &[0x04, start, 0x00, end, 0x00], &[
            0x05, 0x01, //
            start, 0x00, 0x02, 0x29, //
            end, 0x00, 0x08, 0x29,
        ]);
    }

    // The Database Hash, now that the table has it.
    let hash = DB.hash();
    golden(
        s,
        &app,
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x2A, 0x2B],
        &<[&[u8]]>::concat(&[&[0x09, 0x12, 0x0A, 0x00], &hash]),
    );

    // GAP: the name, the appearance and the preferred parameters.
    golden(s, &app, &[0x0A, 0x03, 0x00], &<[&[u8]]>::concat(&[&[0x0B], example::NAME]));
    golden(s, &app, &[0x0A, 0x05, 0x00], &[0x0B, 0xC1, 0x03]);
    golden(s, &app, &[0x0A, 0x07, 0x00], &<[&[u8]]>::concat(&[&[0x0B], &ppcp(PARAMS)]));
    // Device information: the PnP ID.
    golden(s, &app, &[0x0A, 0x11, 0x00], &[0x0B, 0x02, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01]);
    // Battery: the level, then its configuration.
    golden(s, &app, &[0x0A, 0x0D, 0x00], &[0x0B, 90]);
    golden(s, &app, &[0x12, 0x0E, 0x00, 0x01, 0x00], &[0x13]);

    // HID: the Report Map with Read and Read Blob while a full 22 octets
    // come back, then the HID Information.
    golden(s, &app, &[0x0A, 0x16, 0x00], &<[&[u8]]>::concat(&[&[0x0B], &REPORT_MAP[..22]]));
    for offset in [22_u8, 44, 66, 88] {
        let start = usize::from(offset);
        golden(
            s,
            &app,
            &[0x0C, 0x16, 0x00, offset, 0x00],
            &<[&[u8]]>::concat(&[&[0x0D], &REPORT_MAP[start..start + 22]]),
        );
    }
    golden(s, &app, &[0x0C, 0x16, 0x00, 110, 0x00], &<[&[u8]]>::concat(&[&[0x0D], &REPORT_MAP[110..]]));
    // A value whose length is a multiple of 22 ends with an empty blob.
    golden(s, &app, &[0x0C, 0x16, 0x00, 126, 0x00], &[0x0D]);
    golden(s, &app, &[0x0A, 0x14, 0x00], &[0x0B, 0x11, 0x01, 0x00, 0x03]);

    // Each input report: its value, its Report Reference, its
    // configuration read, then written.
    for (value, length, id) in [(0x1A_u8, 8, 1_u8), (0x1E, 2, 2), (0x22, 5, 3)] {
        golden(s, &app, &[0x0A, value, 0x00], &<[&[u8]]>::concat(&[&[0x0B], &[0; 8][..length]]));
        golden(s, &app, &[0x0A, value + 2, 0x00], &[0x0B, id, 0x01]);
        golden(s, &app, &[0x0A, value + 1, 0x00], &[0x0B, 0x00, 0x00]);
        golden(s, &app, &[0x12, value + 1, 0x00, 0x01, 0x00], &[0x13]);
        golden(s, &app, &[0x0A, value + 1, 0x00], &[0x0B, 0x01, 0x00]);
    }

    // The HID Control Point on suspend: a command, never answered.
    assert!(exchange(s, &app, &[0x52, 0x18, 0x00, 0x00], Sec::Encrypted).is_none());

    // Every input report and the battery now notify.
    let mut out = [0_u8; MTU];
    let report = [0, 0, 0x4B, 0, 0, 0, 0, 0];
    let len = s.notify(KEYBOARD, &report, Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &*<[&[u8]]>::concat(&[&[0x1B, 0x1A, 0x00], &report]));
    let len = s.notify(CONSUMER, &[0xE9, 0x00], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x1E, 0x00, 0xE9, 0x00]);
    let len = s.notify(MOUSE, &[0, 1, 0, 0xFF, 0xFF], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x22, 0x00, 0, 1, 0, 0xFF, 0xFF]);
    let len = s.notify(BATTERY_LEVEL, &[89], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x0D, 0x00, 89]);
    assert_eq!(s.subscriptions().bits(), 0b0101_0101);
    assert_eq!(BATTERY_LEVEL_VALUE.index(), 0);
}

/// `BlueZ`'s first connection as
/// [`the_bluez_first_connection_gets_these_answers`] has it, with `att-mtu`:
/// Exchange MTU agrees on 65, so the primary services and the HID service's
/// characteristics each fit one response, the Report Map takes a Read and one
/// Read Blob, and notifications stay within 20 octets.
#[cfg(feature = "att-mtu")]
#[test]
fn the_bluez_first_connection_at_mtu_65_gets_these_answers() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let s = &mut server;

    // Exchange MTU with 517: the answer is 65, and so is the MTU.
    golden(s, &app, &[0x02, 0x05, 0x02], &[0x03, 0x41, 0x00]);
    assert_eq!(s.mtu, 65);
    golden(s, &app, &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x3A, 0x2B], &[0x01, 0x08, 0x01, 0x00, 0x0A]);

    // All five primary services in one response.
    golden(s, &app, &[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &[
        0x11, 0x06, //
        0x01, 0x00, 0x07, 0x00, 0x00, 0x18, //
        0x08, 0x00, 0x0A, 0x00, 0x01, 0x18, //
        0x0B, 0x00, 0x0E, 0x00, 0x0F, 0x18, //
        0x0F, 0x00, 0x11, 0x00, 0x0A, 0x18, //
        0x12, 0x00, 0x24, 0x00, 0x12, 0x18,
    ]);
    golden(s, &app, &[0x10, 0x25, 0x00, 0xFF, 0xFF, 0x00, 0x28], &[0x01, 0x10, 0x25, 0x00, 0x0A]);
    golden(s, &app, &[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x01, 0x28], &[0x01, 0x10, 0x01, 0x00, 0x0A]);
    for (start, end) in [(0x01_u8, 0x07_u8), (0x08, 0x0A), (0x0B, 0x0E), (0x0F, 0x11), (0x12, 0x24)] {
        golden(s, &app, &[0x08, start, 0x00, end, 0x00, 0x02, 0x28], &[0x01, 0x08, start, 0x00, 0x0A]);
    }

    // Characteristics: the services before HID as at 23, then all six of
    // HID's in one response.
    golden(s, &app, &[0x08, 0x01, 0x00, 0x07, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x02, 0x00, 0x02, 0x03, 0x00, 0x00, 0x2A, //
        0x04, 0x00, 0x02, 0x05, 0x00, 0x01, 0x2A, //
        0x06, 0x00, 0x02, 0x07, 0x00, 0x04, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x07, 0x00, 0x07, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x07, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x08, 0x00, 0x0A, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x09, 0x00, 0x02, 0x0A, 0x00, 0x2A, 0x2B,
    ]);
    golden(s, &app, &[0x08, 0x0A, 0x00, 0x0A, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x0A, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x0B, 0x00, 0x0E, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x0C, 0x00, 0x12, 0x0D, 0x00, 0x19, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x0D, 0x00, 0x0E, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x0D, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x0F, 0x00, 0x11, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x10, 0x00, 0x02, 0x11, 0x00, 0x50, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x11, 0x00, 0x11, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x11, 0x00, 0x0A]);
    golden(s, &app, &[0x08, 0x12, 0x00, 0x24, 0x00, 0x03, 0x28], &[
        0x09, 0x07, //
        0x13, 0x00, 0x02, 0x14, 0x00, 0x4A, 0x2A, //
        0x15, 0x00, 0x02, 0x16, 0x00, 0x4B, 0x2A, //
        0x17, 0x00, 0x04, 0x18, 0x00, 0x4C, 0x2A, //
        0x19, 0x00, 0x12, 0x1A, 0x00, 0x4D, 0x2A, //
        0x1D, 0x00, 0x12, 0x1E, 0x00, 0x4D, 0x2A, //
        0x21, 0x00, 0x12, 0x22, 0x00, 0x4D, 0x2A,
    ]);
    golden(s, &app, &[0x08, 0x22, 0x00, 0x24, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x22, 0x00, 0x0A]);
    for (start, end) in [(0x1B_u8, 0x1C_u8), (0x1F, 0x20), (0x23, 0x24)] {
        golden(s, &app, &[0x04, start, 0x00, end, 0x00], &[
            0x05, 0x01, //
            start, 0x00, 0x02, 0x29, //
            end, 0x00, 0x08, 0x29,
        ]);
    }
    golden(
        s,
        &app,
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x2A, 0x2B],
        &<[&[u8]]>::concat(&[&[0x09, 0x12, 0x0A, 0x00], &DB.hash()]),
    );

    // The profiles' reads as at 23.
    golden(s, &app, &[0x0A, 0x03, 0x00], &<[&[u8]]>::concat(&[&[0x0B], example::NAME]));
    golden(s, &app, &[0x0A, 0x05, 0x00], &[0x0B, 0xC1, 0x03]);
    golden(s, &app, &[0x0A, 0x07, 0x00], &<[&[u8]]>::concat(&[&[0x0B], &ppcp(PARAMS)]));
    golden(s, &app, &[0x0A, 0x11, 0x00], &[0x0B, 0x02, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01]);
    golden(s, &app, &[0x0A, 0x0D, 0x00], &[0x0B, 90]);
    golden(s, &app, &[0x12, 0x0E, 0x00, 0x01, 0x00], &[0x13]);

    // The Report Map: a Read gives a full 64 octets, so BlueZ asks for the
    // rest with Read Blob, which gives the last 62, fewer than 64, and ends
    // the read.
    golden(s, &app, &[0x0A, 0x16, 0x00], &<[&[u8]]>::concat(&[&[0x0B], &REPORT_MAP[..64]]));
    golden(s, &app, &[0x0C, 0x16, 0x00, 64, 0x00], &<[&[u8]]>::concat(&[&[0x0D], &REPORT_MAP[64..]]));
    golden(s, &app, &[0x0A, 0x14, 0x00], &[0x0B, 0x11, 0x01, 0x00, 0x03]);
    for (value, length, id) in [(0x1A_u8, 8, 1_u8), (0x1E, 2, 2), (0x22, 5, 3)] {
        golden(s, &app, &[0x0A, value, 0x00], &<[&[u8]]>::concat(&[&[0x0B], &[0; 8][..length]]));
        golden(s, &app, &[0x0A, value + 2, 0x00], &[0x0B, id, 0x01]);
        golden(s, &app, &[0x0A, value + 1, 0x00], &[0x0B, 0x00, 0x00]);
        golden(s, &app, &[0x12, value + 1, 0x00, 0x01, 0x00], &[0x13]);
    }

    // Notifications still carry at most 20 octets.
    let mut out = [0_u8; MTU];
    let report = [0, 0, 0x4B, 0, 0, 0, 0, 0];
    let len = s.notify(KEYBOARD, &report, Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &*<[&[u8]]>::concat(&[&[0x1B, 0x1A, 0x00], &report]));
    assert!(s.notify(KEYBOARD, &[0; 20], Sec::Encrypted, &mut out).is_ok());
    assert_eq!(s.notify(KEYBOARD, &[0; 21], Sec::Encrypted, &mut out), Err(NotifyError::TooLong));
}

/// With `att-mtu`, Exchange MTU always answers 65, and the fixed channel's
/// ATT MTU becomes the smaller of the client's and 65, at least 23, from
/// the next request on.
#[cfg(feature = "att-mtu")]
#[test]
fn exchange_mtu_agrees_on_the_smaller_mtu_at_least_23() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let read = [0x0A, 0x16, 0x00];
    let report_map = |len: usize| <[&[u8]]>::concat(&[&[0x0B], &REPORT_MAP[..len]]);
    // 23 before any exchange.
    golden(&mut server, &app, &read, &report_map(22));
    // A malformed request changes nothing.
    golden(&mut server, &app, &[0x02, 0x1E], &[0x01, 0x02, 0x00, 0x00, 0x04]);
    golden(&mut server, &app, &[0x02, 0x1E, 0x00, 0x00], &[0x01, 0x02, 0x00, 0x00, 0x04]);
    golden(&mut server, &app, &read, &report_map(22));
    // The client's 30.
    golden(&mut server, &app, &[0x02, 0x1E, 0x00], &[0x03, 0x41, 0x00]);
    assert_eq!(server.mtu, 30);
    golden(&mut server, &app, &read, &report_map(29));
    // Less than 23 counts as 23.
    for client in [[0x16, 0x00], [0x00, 0x00]] {
        golden(&mut server, &app, &[0x02, client[0], client[1]], &[0x03, 0x41, 0x00]);
        assert_eq!(server.mtu, 23);
        golden(&mut server, &app, &read, &report_map(22));
    }
    // More than 65 counts as 65; exactly 65 too.
    for client in [[0x05, 0x02], [0xFF, 0xFF], [0x41, 0x00]] {
        golden(&mut server, &app, &[0x02, client[0], client[1]], &[0x03, 0x41, 0x00]);
        assert_eq!(server.mtu, 65);
        golden(&mut server, &app, &read, &report_map(64));
    }
    // A slot of 23 octets is now too short: the request is ignored.
    let mut short = [UNWRITTEN; MTU];
    assert_eq!(server.handle_on(Bearer::Fixed, &read, Sec::Encrypted, &app, &mut short), None);
    assert!(short.iter().all(|&octet| octet == UNWRITTEN));
    // A new link starts at 23 again.
    let mut server = Server::new(&DB);
    golden(&mut server, &app, &read, &report_map(22));
}

/// With `att-mtu` at an MTU of 65, one Find Information Response holds 15
/// entries of 16-bit UUIDs, 2 + 15 * 4 = 62 octets, and one Read By Type
/// Response 9 characteristic declarations, 2 + 9 * 7 = 65.
#[cfg(feature = "att-mtu")]
#[test]
fn discovery_at_mtu_65_fills_each_response() {
    let app = App::new();
    let mut server = Server::new(&DB);
    golden(&mut server, &app, &[0x02, 0x05, 0x02], &[0x03, 0x41, 0x00]);
    golden(&mut server, &app, &[0x04, 0x01, 0x00, 0xFF, 0xFF], &[
        0x05, 0x01, //
        0x01, 0x00, 0x00, 0x28, //
        0x02, 0x00, 0x03, 0x28, //
        0x03, 0x00, 0x00, 0x2A, //
        0x04, 0x00, 0x03, 0x28, //
        0x05, 0x00, 0x01, 0x2A, //
        0x06, 0x00, 0x03, 0x28, //
        0x07, 0x00, 0x04, 0x2A, //
        0x08, 0x00, 0x00, 0x28, //
        0x09, 0x00, 0x03, 0x28, //
        0x0A, 0x00, 0x2A, 0x2B, //
        0x0B, 0x00, 0x00, 0x28, //
        0x0C, 0x00, 0x03, 0x28, //
        0x0D, 0x00, 0x19, 0x2A, //
        0x0E, 0x00, 0x02, 0x29, //
        0x0F, 0x00, 0x00, 0x28,
    ]);
    golden(&mut server, &app, &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28], &[
        0x09, 0x07, //
        0x02, 0x00, 0x02, 0x03, 0x00, 0x00, 0x2A, //
        0x04, 0x00, 0x02, 0x05, 0x00, 0x01, 0x2A, //
        0x06, 0x00, 0x02, 0x07, 0x00, 0x04, 0x2A, //
        0x09, 0x00, 0x02, 0x0A, 0x00, 0x2A, 0x2B, //
        0x0C, 0x00, 0x12, 0x0D, 0x00, 0x19, 0x2A, //
        0x10, 0x00, 0x02, 0x11, 0x00, 0x50, 0x2A, //
        0x13, 0x00, 0x02, 0x14, 0x00, 0x4A, 0x2A, //
        0x15, 0x00, 0x02, 0x16, 0x00, 0x4B, 0x2A, //
        0x17, 0x00, 0x04, 0x18, 0x00, 0x4C, 0x2A,
    ]);
    golden(&mut server, &app, &[0x08, 0x18, 0x00, 0xFF, 0xFF, 0x03, 0x28], &[
        0x09, 0x07, //
        0x19, 0x00, 0x12, 0x1A, 0x00, 0x4D, 0x2A, //
        0x1D, 0x00, 0x12, 0x1E, 0x00, 0x4D, 0x2A, //
        0x21, 0x00, 0x12, 0x22, 0x00, 0x4D, 0x2A,
    ]);
}

/// Read By Type cuts a value longer than an entry holds to the ATT MTU less
/// 4 octets: 19 octets of the Report Map at 23, and with `att-mtu` 61 at
/// 65.
#[test]
fn read_by_type_cuts_a_long_value_to_the_mtu_less_4() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let request = [0x08, 0x12, 0x00, 0x24, 0x00, 0x4B, 0x2A];
    golden(&mut server, &app, &request, &<[&[u8]]>::concat(&[&[0x09, 0x15, 0x16, 0x00], &REPORT_MAP[..19]]));
    #[cfg(feature = "att-mtu")]
    {
        golden(&mut server, &app, &[0x02, 0x05, 0x02], &[0x03, 0x41, 0x00]);
        golden(&mut server, &app, &request, &<[&[u8]]>::concat(&[&[0x09, 0x3F, 0x16, 0x00], &REPORT_MAP[..61]]));
    }
}

/// The reconnection of a bonded central with a cached table: the hash
/// matches, so no discovery follows.
#[test]
fn a_reconnection_reads_the_hash_and_restores_nothing_it_did_not_write() {
    let app = App::new();
    let mut server = Server::new(&DB);
    server.restore(crate::host::gatt::Subscriptions::from_bits(0b0101_0101));
    golden(&mut server, &app, &[0x02, 0x05, 0x02], &MTU_517);
    golden(
        &mut server,
        &app,
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x2A, 0x2B],
        &<[&[u8]]>::concat(&[&[0x09, 0x12, 0x0A, 0x00], &DB.hash()]),
    );
    // The restored bits read back, but count as written on no link.
    golden(&mut server, &app, &[0x0A, 0x1B, 0x00], &[0x0B, 0x01, 0x00]);
    assert!(!server.subscriptions().is_written(1));
}

#[test]
fn an_unencrypted_request_for_a_report_gets_insufficient_encryption() {
    let app = App::new();
    let mut server = Server::new(&DB);
    for request in [&[0x0A, 0x1A, 0x00][..], &[0x0A, 0x1B, 0x00], &[0x0C, 0x1A, 0x00, 0x00, 0x00]] {
        let response = exchange(&mut server, &app, request, Sec::Open).unwrap();
        assert_eq!(*response, [0x01, request[0], request[1], 0x00, 0x0F]);
    }
    let response = exchange(&mut server, &app, &[0x12, 0x1B, 0x00, 0x01, 0x00], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x12, 0x1B, 0x00, 0x0F]);
    // Read By Type names the first report it cannot read.
    let response = exchange(&mut server, &app, &[0x08, 0x18, 0x00, 0x24, 0x00, 0x4D, 0x2A], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x08, 0x1A, 0x00, 0x0F]);
    // The Report Reference and the open values stay readable.
    golden(&mut server, &app, &[0x0A, 0x1C, 0x00], &[0x0B, 0x01, 0x01]);
    assert_eq!(*exchange(&mut server, &app, &[0x0A, 0x0D, 0x00], Sec::Open).unwrap(), [0x0B, 90]);
    // A notification needs the encryption too.
    let mut out = [0_u8; MTU];
    server.restore(crate::host::gatt::Subscriptions::from_bits(0b0101_0101));
    assert_eq!(server.notify(KEYBOARD, &[0; 8], Sec::Open, &mut out), Err(NotifyError::Insecure));
    assert!(server.notify(BATTERY_LEVEL, &[1], Sec::Open, &mut out).is_ok());
}

#[test]
fn the_fixed_channel_answers_within_its_mtu_whatever_the_slot() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let read = [0x0A, 0x16, 0x00];
    // The Report Map is longer than a response: a Read on the fixed
    // channel gives its first 22 octets, in a slot of any length.
    let mut slot = [UNWRITTEN; 64];
    assert_eq!(server.handle_on(Bearer::Fixed, &read, Sec::Encrypted, &app, &mut slot), Some(MTU));
    assert_eq!(slot[..MTU], *<[&[u8]]>::concat(&[&[0x0B], &REPORT_MAP[..MTU - 1]]));
    assert!(slot[MTU..].iter().all(|&octet| octet == UNWRITTEN));
    // So does every discovery response: Find Information over the whole
    // table stops at the fifth entry of 16-bit UUIDs, 2 + 5 * 4 = 22
    // octets, and Read By Type of the characteristics at the third of
    // length 7, 2 + 3 * 7 = 23.
    let mut slot = [UNWRITTEN; 64];
    let len = server.handle_on(Bearer::Fixed, &[0x04, 0x01, 0x00, 0xFF, 0xFF], Sec::Encrypted, &app, &mut slot);
    assert_eq!(len, Some(22));
    assert!(slot[22..].iter().all(|&octet| octet == UNWRITTEN));
    let mut slot = [UNWRITTEN; 64];
    let request = [0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28];
    assert_eq!(server.handle_on(Bearer::Fixed, &request, Sec::Encrypted, &app, &mut slot), Some(MTU));
    assert!(slot[MTU..].iter().all(|&octet| octet == UNWRITTEN));

    // A slot shorter than the bearer's MTU is the caller's mistake: the PDU
    // is ignored, nothing is written into the slot, and a write is not
    // taken.
    let mut short = [UNWRITTEN; MTU - 1];
    assert_eq!(server.handle_on(Bearer::Fixed, &read, Sec::Encrypted, &app, &mut short), None);
    let write = [0x12, 0x1B, 0x00, 0x01, 0x00];
    assert_eq!(server.handle_on(Bearer::Fixed, &write, Sec::Encrypted, &app, &mut short), None);
    assert_eq!(server.handle_on(Bearer::Fixed, &[0x52, 0x1B, 0x00, 0x01, 0x00], Sec::Encrypted, &app, &mut []), None);
    assert!(short.iter().all(|&octet| octet == UNWRITTEN));
    assert_eq!(server.subscriptions(), Subscriptions::new());
    // The same write through a slot of the MTU is taken.
    golden(&mut server, &app, &write, &[0x13]);
    assert_ne!(server.subscriptions(), Subscriptions::new());
}

#[test]
fn read_blob_past_the_end_gets_invalid_offset_never_attribute_not_long() {
    let app = App::new();
    let mut server = Server::new(&DB);
    golden(&mut server, &app, &[0x0C, 0x16, 0x00, 127, 0x00], &[0x01, 0x0C, 0x16, 0x00, 0x07]);
    // A short value: an offset at its end gives an empty response, any
    // offset before it the rest.
    golden(&mut server, &app, &[0x0C, 0x14, 0x00, 0x04, 0x00], &[0x0D]);
    golden(&mut server, &app, &[0x0C, 0x14, 0x00, 0x02, 0x00], &[0x0D, 0x00, 0x03]);
    golden(&mut server, &app, &[0x0C, 0x14, 0x00, 0x05, 0x00], &[0x01, 0x0C, 0x14, 0x00, 0x07]);
    // Zeros and dynamic values as well.
    golden(&mut server, &app, &[0x0C, 0x1A, 0x00, 0x08, 0x00], &[0x0D]);
    golden(&mut server, &app, &[0x0C, 0x1A, 0x00, 0x09, 0x00], &[0x01, 0x0C, 0x1A, 0x00, 0x07]);
    golden(&mut server, &app, &[0x0C, 0x0D, 0x00, 0x01, 0x00], &[0x0D]);
    golden(&mut server, &app, &[0x0C, 0x0D, 0x00, 0x02, 0x00], &[0x01, 0x0C, 0x0D, 0x00, 0x07]);
}

/// With `att-mtu` at an MTU of 65, Read Blob gives up to 64 octets: a full
/// 64 where that many are left, so the client reads on, then the rest, an
/// empty response at the end and Invalid Offset past it.
#[cfg(feature = "att-mtu")]
#[test]
fn read_blob_at_mtu_65_gives_up_to_64_octets() {
    let app = App::new();
    let mut server = Server::new(&DB);
    golden(&mut server, &app, &[0x02, 0x05, 0x02], &[0x03, 0x41, 0x00]);
    let blob = |offset: usize| <[&[u8]]>::concat(&[&[0x0D], &REPORT_MAP[offset..]]);
    golden(&mut server, &app, &[0x0C, 0x16, 0x00, 0x00, 0x00], &blob(0)[..65]);
    golden(&mut server, &app, &[0x0C, 0x16, 0x00, 61, 0x00], &blob(61)[..65]);
    golden(&mut server, &app, &[0x0C, 0x16, 0x00, 62, 0x00], &blob(62));
    assert_eq!(blob(62).len(), 65);
    golden(&mut server, &app, &[0x0C, 0x16, 0x00, 63, 0x00], &blob(63));
    golden(&mut server, &app, &[0x0C, 0x16, 0x00, 126, 0x00], &[0x0D]);
    golden(&mut server, &app, &[0x0C, 0x16, 0x00, 127, 0x00], &[0x01, 0x0C, 0x16, 0x00, 0x07]);
}

#[test]
fn requests_the_server_does_not_serve_get_request_not_supported() {
    let app = App::new();
    let mut server = Server::new(&DB);
    // Read Multiple and an unknown request; without `eatt`, Prepare Write,
    // Execute Write and Read Multiple Variable too.
    let mut requests = Vec::from([&[0x0E, 0x03, 0x00, 0x05, 0x00][..], &[0x3F]]);
    if !cfg!(feature = "eatt") {
        requests.extend([&[0x16, 0x16, 0x00, 0x00, 0x00, 0x01][..], &[0x18, 0x01], &[0x20, 0x03, 0x00, 0x05, 0x00]]);
    }
    for request in requests {
        let response = exchange(&mut server, &app, request, Sec::Encrypted).unwrap();
        assert_eq!(*response, [0x01, request[0], 0x00, 0x00, 0x06]);
    }
}

#[test]
fn commands_responses_and_stray_confirmations_are_never_answered() {
    let app = App::new();
    let mut server = Server::new(&DB);
    for pdu in [
        // Signed Write, an unknown command, Write Commands that fail.
        &[0xD2, 0x0E, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..],
        &[0x7F, 0x01],
        &[0x52, 0x03, 0x00, 0x41],
        &[0x52, 0x0E, 0x00, 0x01],
        &[0x52, 0x1B, 0x00, 0x01, 0x00],
        &[0x52, 0x99, 0x00, 0x01],
        &[0x52],
        // Responses, a notification, an indication, a confirmation.
        &[0x01, 0x0A, 0x01, 0x00, 0x0A],
        &[0x03, 0x17, 0x00],
        &[0x0B, 0x01],
        &[0x13],
        &[0x1B, 0x01, 0x00, 0x00],
        &[0x1D, 0x01, 0x00, 0x00],
        &[0x1E],
        &[],
    ] {
        assert!(exchange(&mut server, &app, pdu, Sec::Open).is_none(), "PDU {pdu:02X?}");
    }
    // A Write Command on an encrypted link configures a report.
    assert!(exchange(&mut server, &app, &[0x52, 0x1B, 0x00, 0x01, 0x00], Sec::Encrypted).is_none());
    assert!(server.subscriptions().notifying(1));
    assert_eq!(server.subscriptions().bits(), 0b0100);
}

#[test]
fn malformed_requests_get_invalid_pdu() {
    let app = App::new();
    let mut server = Server::new(&DB);
    for request in [
        &[0x02, 0x17][..],
        &[0x02, 0x17, 0x00, 0x00],
        &[0x04, 0x01, 0x00, 0xFF],
        &[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00],
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03],
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28, 0x00],
        &[0x0A, 0x03],
        &[0x0A, 0x03, 0x00, 0x00],
        &[0x0C, 0x16, 0x00, 0x00],
        &[0x10, 0x01, 0x00, 0xFF, 0xFF],
        &[0x12, 0x0E],
    ] {
        let response = exchange(&mut server, &app, request, Sec::Encrypted).unwrap();
        assert_eq!(*response, [0x01, request[0], 0x00, 0x00, 0x04], "request {request:02X?}");
    }
}

#[test]
fn bad_handles_get_invalid_handle() {
    let app = App::new();
    let mut server = Server::new(&DB);
    golden(&mut server, &app, &[0x0A, 0x00, 0x00], &[0x01, 0x0A, 0x00, 0x00, 0x01]);
    golden(&mut server, &app, &[0x0A, 0x25, 0x00], &[0x01, 0x0A, 0x25, 0x00, 0x01]);
    golden(&mut server, &app, &[0x0C, 0x25, 0x00, 0x00, 0x00], &[0x01, 0x0C, 0x25, 0x00, 0x01]);
    golden(&mut server, &app, &[0x12, 0x25, 0x00, 0x01], &[0x01, 0x12, 0x25, 0x00, 0x01]);
    golden(&mut server, &app, &[0x04, 0x00, 0x00, 0xFF, 0xFF], &[0x01, 0x04, 0x00, 0x00, 0x01]);
    golden(&mut server, &app, &[0x04, 0x05, 0x00, 0x04, 0x00], &[0x01, 0x04, 0x05, 0x00, 0x01]);
    golden(&mut server, &app, &[0x08, 0x05, 0x00, 0x04, 0x00, 0x03, 0x28], &[0x01, 0x08, 0x05, 0x00, 0x01]);
    golden(&mut server, &app, &[0x10, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x28], &[0x01, 0x10, 0x00, 0x00, 0x01]);
    golden(&mut server, &app, &[0x06, 0x02, 0x00, 0x01, 0x00, 0x00, 0x28, 0x0F, 0x18], &[0x01, 0x06, 0x02, 0x00, 0x01]);
    // A range past the table finds nothing.
    golden(&mut server, &app, &[0x04, 0x25, 0x00, 0xFF, 0xFF], &[0x01, 0x04, 0x25, 0x00, 0x0A]);
}

#[test]
fn permissions_and_lengths_are_checked() {
    let app = App::new();
    let mut server = Server::new(&DB);
    // The name cannot be written, the Control Point not read.
    golden(&mut server, &app, &[0x12, 0x03, 0x00, 0x41], &[0x01, 0x12, 0x03, 0x00, 0x03]);
    golden(&mut server, &app, &[0x0A, 0x18, 0x00], &[0x01, 0x0A, 0x18, 0x00, 0x02]);
    // A Write Request to the Control Point, which only takes commands.
    golden(&mut server, &app, &[0x12, 0x18, 0x00, 0x00], &[0x13]);
    // A configuration write of another length than 2.
    golden(&mut server, &app, &[0x12, 0x0E, 0x00, 0x01], &[0x01, 0x12, 0x0E, 0x00, 0x0D]);
    golden(&mut server, &app, &[0x12, 0x0E, 0x00, 0x01, 0x00, 0x00], &[0x01, 0x12, 0x0E, 0x00, 0x0D]);
    // Lenient: indications on a characteristic that only notifies are not
    // kept, any other value is taken.
    golden(&mut server, &app, &[0x12, 0x0E, 0x00, 0x03, 0x00], &[0x13]);
    golden(&mut server, &app, &[0x0A, 0x0E, 0x00], &[0x0B, 0x01, 0x00]);
    golden(&mut server, &app, &[0x12, 0x0E, 0x00, 0x02, 0x80], &[0x13]);
    golden(&mut server, &app, &[0x0A, 0x0E, 0x00], &[0x0B, 0x00, 0x00]);
    // Only primary services group, secondary ones are not found.
    golden(&mut server, &app, &[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28], &[0x01, 0x10, 0x01, 0x00, 0x10]);
    // Primary services by UUID, short and long.
    golden(&mut server, &app, &[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28, 0x0F, 0x18], &[0x07, 0x0B, 0x00, 0x0E, 0x00]);
    let mut long = [0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x12, 0x18, 0x00, 0x00];
    let request = <[&[u8]]>::concat(&[&[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &long]);
    golden(&mut server, &app, &request, &[0x07, 0x12, 0x00, 0x24, 0x00]);
    long[12] = 0x13;
    let request = <[&[u8]]>::concat(&[&[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &long]);
    golden(&mut server, &app, &request, &[0x01, 0x06, 0x01, 0x00, 0x0A]);
    golden(&mut server, &app, &[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28, 0x19, 0x2A], &[0x01, 0x06, 0x01, 0x00, 0x0A]);
    // Read By Type with a 128-bit type.
    long[12] = 0x19;
    long[13] = 0x2A;
    let request = <[&[u8]]>::concat(&[&[0x08, 0x01, 0x00, 0xFF, 0xFF], &long]);
    golden(&mut server, &app, &request, &[0x09, 0x03, 0x0D, 0x00, 90]);
}

#[test]
fn notifications_need_a_subscription_and_fit_the_mtu() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let mut out = [0_u8; MTU];
    assert_eq!(server.notify(KEYBOARD, &[0; 8], Sec::Encrypted, &mut out), Err(NotifyError::NotSubscribed));
    golden(&mut server, &app, &[0x12, 0x1B, 0x00, 0x01, 0x00], &[0x13]);
    assert!(server.notify(KEYBOARD, &[0; 8], Sec::Encrypted, &mut out).is_ok());
    assert!(server.notify(KEYBOARD, &[0; 20], Sec::Encrypted, &mut out).is_ok());
    assert_eq!(server.notify(KEYBOARD, &[0; 21], Sec::Encrypted, &mut out), Err(NotifyError::TooLong));
}

/// A 128-bit UUID of a service in the tests.
const LONG_SERVICE: [u8; 16] =
    [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
/// A 128-bit UUID of a characteristic in the tests.
const LONG_CHAR: [u8; 16] =
    [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];
/// A value the application keeps, which needs encryption.
const SECRET: ValueId = ValueId::new(1);

crate::gatt! {
    /// A table with Service Changed, 128-bit UUIDs and a dynamic value that
    /// needs encryption.
    const TEST_DB;
    service 0x1801 {
        char CHANGED: 0x2A05 [indicate] = Value::Empty;
        ccc;
    }
    service (Uuid::U128(&LONG_SERVICE)) {
        char 0x2A00 [read] = Value::Const(b"x");
        char (Uuid::U128(&LONG_CHAR)) [read, write, write_without_response; encrypted] =
            Value::Dynamic(SECRET);
        desc 0x2901 [read] = Value::Const(b"description");
    }
}

#[test]
fn a_confirmation_is_ignored() {
    let app = App::new();
    let mut server = Server::new(&TEST_DB);
    assert_eq!(TEST_DB.service_changed(), Some(CHANGED));
    // No indication is sent, Service Changed's included: a confirmation
    // gets no answer, and no error either.
    golden(&mut server, &app, &[0x12, 0x04, 0x00, 0x02, 0x00], &[0x13]);
    assert!(exchange(&mut server, &app, &[0x1E], Sec::Encrypted).is_none());
}

#[test]
fn discovery_groups_entries_by_uuid_size_and_reports_real_ends() {
    let app = App::new();
    let mut server = Server::new(&TEST_DB);
    golden(&mut server, &app, &[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &[
        0x11, 0x06, 0x01, 0x00, 0x04, 0x00, 0x01, 0x18,
    ]);
    golden(
        &mut server,
        &app,
        &[0x10, 0x05, 0x00, 0xFF, 0xFF, 0x00, 0x28],
        &<[&[u8]]>::concat(&[&[0x11, 0x14, 0x05, 0x00, 0x0A, 0x00], &LONG_SERVICE]),
    );
    // Characteristic declarations: 7 octets, then 21 in the next response.
    golden(&mut server, &app, &[0x08, 0x05, 0x00, 0x0A, 0x00, 0x03, 0x28], &[
        0x09, 0x07, 0x06, 0x00, 0x02, 0x07, 0x00, 0x00, 0x2A,
    ]);
    golden(
        &mut server,
        &app,
        &[0x08, 0x07, 0x00, 0x0A, 0x00, 0x03, 0x28],
        &<[&[u8]]>::concat(&[&[0x09, 0x15, 0x08, 0x00, 0x0E, 0x09, 0x00], &LONG_CHAR]),
    );
    // Find Information: 16-bit types, then a response of the 128-bit one.
    golden(&mut server, &app, &[0x04, 0x01, 0x00, 0xFF, 0xFF], &[
        0x05, 0x01, //
        0x01, 0x00, 0x00, 0x28, //
        0x02, 0x00, 0x03, 0x28, //
        0x03, 0x00, 0x05, 0x2A, //
        0x04, 0x00, 0x02, 0x29, //
        0x05, 0x00, 0x00, 0x28,
    ]);
    golden(&mut server, &app, &[0x04, 0x06, 0x00, 0xFF, 0xFF], &[
        0x05, 0x01, //
        0x06, 0x00, 0x03, 0x28, //
        0x07, 0x00, 0x00, 0x2A, //
        0x08, 0x00, 0x03, 0x28,
    ]);
    golden(
        &mut server,
        &app,
        &[0x04, 0x09, 0x00, 0xFF, 0xFF],
        &<[&[u8]]>::concat(&[&[0x05, 0x02, 0x09, 0x00], &LONG_CHAR]),
    );
    golden(&mut server, &app, &[0x04, 0x0A, 0x00, 0xFF, 0xFF], &[0x05, 0x01, 0x0A, 0x00, 0x01, 0x29]);
    // An indicate-only value cannot be read.
    golden(&mut server, &app, &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x05, 0x2A], &[0x01, 0x08, 0x03, 0x00, 0x02]);
    // The descriptor is longer than a Read By Type entry holds: cut.
    golden(
        &mut server,
        &app,
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x01, 0x29],
        &<[&[u8]]>::concat(&[&[0x09, 0x0D, 0x0A, 0x00], b"description"]),
    );
}

#[test]
fn a_dynamic_value_that_needs_encryption_is_served_only_encrypted() {
    let app = App::new();
    let mut server = Server::new(&TEST_DB);
    let response = exchange(&mut server, &app, &[0x0A, 0x09, 0x00], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x0A, 0x09, 0x00, 0x0F]);
    let response = exchange(&mut server, &app, &[0x12, 0x09, 0x00, 0xAA, 0xBB], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x12, 0x09, 0x00, 0x0F]);
    // A command is dropped unanswered.
    assert!(exchange(&mut server, &app, &[0x52, 0x09, 0x00, 9], Sec::Open).is_none());
    assert_eq!(app.written.get(), None);
    let response = exchange(&mut server, &app, &[0x0A, 0x09, 0x00], Sec::Encrypted).unwrap();
    assert_eq!(*response, [0x0B, 1, 2, 3, 4]);
    let response = exchange(&mut server, &app, &[0x12, 0x09, 0x00, 0xAA, 0xBB], Sec::Encrypted).unwrap();
    assert_eq!(*response, [0x13]);
    assert_eq!(app.written.get(), Some(([0xAA, 0xBB, 0, 0], 2, true)));
    // The application's error is the answer to a request, and dropped for
    // a command.
    let response = exchange(&mut server, &app, &[0x12, 0x09, 0x00, 1, 2, 3, 4, 5], Sec::Encrypted).unwrap();
    assert_eq!(*response, [0x01, 0x12, 0x09, 0x00, 0x80]);
    assert!(exchange(&mut server, &app, &[0x52, 0x09, 0x00, 1, 2, 3, 4, 5], Sec::Encrypted).is_none());
    assert!(exchange(&mut server, &app, &[0x52, 0x09, 0x00, 7], Sec::Encrypted).is_none());
    assert_eq!(app.written.get(), Some(([7, 0, 0, 0], 1, false)));
}

crate::gatt! {
    /// A table whose characteristics only notify or indicate, so their
    /// security is that of the declaration alone.
    const SILENT_DB;
    service 0x1812 {
        char SECRET_NOTIFY: 0x2A4D [notify; encrypted] = Value::Zeros(8);
        ccc;
        char SECRET_INDICATE: 0x2A4D [indicate; encrypted] = Value::Empty;
        ccc;
        char OPEN_NOTIFY: 0x2A4D [notify] = Value::Zeros(8);
        ccc;
    }
}

#[test]
fn notify_and_indicate_only_values_keep_their_security() {
    let app = App::new();
    let mut server = Server::new(&SILENT_DB);
    let mut out = [0_u8; MTU];
    // As a bond restores them: every descriptor with both bits.
    server.restore(crate::host::gatt::Subscriptions::from_bits(0b11_1111));
    assert_eq!(server.notify(SECRET_NOTIFY, &[1; 8], Sec::Open, &mut out), Err(NotifyError::Insecure));
    assert!(server.notify(OPEN_NOTIFY, &[1; 8], Sec::Open, &mut out).is_ok());
    let len = server.notify(SECRET_NOTIFY, &[1; 8], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x03, 0x00, 1, 1, 1, 1, 1, 1, 1, 1]);
    // An indicate-only value is never notified.
    assert_eq!(server.notify(SECRET_INDICATE, &[1], Sec::Encrypted, &mut out), Err(NotifyError::NotSubscribed));
    // Their configuration descriptors need the same.
    let response = exchange(&mut server, &app, &[0x0A, 0x04, 0x00], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x0A, 0x04, 0x00, 0x0F]);
    let response = exchange(&mut server, &app, &[0x12, 0x07, 0x00, 0x02, 0x00], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x12, 0x07, 0x00, 0x0F]);
}

/// The requests and notifications of the feature `eatt`.
#[cfg(feature = "eatt")]
mod eatt;
