//! Tests of the attribute server: the whole BlueZ first connection as golden
//! PDUs against the example table, and the error cases.

use super::*;
use crate::host::{
    example::{self, BATTERY_LEVEL_VALUE, DB, PARAMS, REPORT_MAP},
    gatt::{Value, ValueId, ppcp},
};
use core::{cell::Cell, ops::Deref};

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

/// Bytes of a PDU, without a heap.
struct Bytes {
    /// The bytes, of which the first `len` count.
    data: [u8; 64],
    /// Their number.
    len:  usize,
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] { &self.data[..self.len] }
}

/// Sends `request` at `level` and returns the response, if any.
fn exchange(server: &mut Server, app: &App, request: &[u8], level: Sec) -> Option<Bytes> {
    let mut out = [0_u8; MTU];
    let len = server.handle(request, level, app, &mut out)?;
    let mut data = [0; 64];
    data[..len].copy_from_slice(&out[..len]);
    Some(Bytes { data, len })
}

/// Sends `request` on an encrypted link and checks the response against
/// `expected`.
fn golden(server: &mut Server, app: &App, request: &[u8], expected: &[u8]) {
    let response = exchange(server, app, request, Sec::Encrypted);
    assert_eq!(response.as_deref(), Some(expected), "request {request:02X?}");
}

/// Concatenates byte slices.
fn join(parts: &[&[u8]]) -> Bytes {
    let mut bytes = Bytes { data: [0; 64], len: 0 };
    for part in parts {
        bytes.data[bytes.len..bytes.len + part.len()].copy_from_slice(part);
        bytes.len += part.len();
    }
    bytes
}

/// The whole first connection of BlueZ (research-bluez.md, section 1.1),
/// after pairing: MTU, server features, primary, secondary and include
/// discovery, characteristics, descriptors, the hash, then the profiles'
/// reads and configuration writes. Every response is checked octet by octet.
#[test]
fn the_bluez_first_connection_gets_these_answers() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let s = &mut server;

    // Exchange MTU with 517: the answer is 23.
    golden(s, &app, &[0x02, 0x05, 0x02], &[0x03, 0x17, 0x00]);
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
    golden(s, &app, &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x2A, 0x2B], &join(&[&[0x09, 0x12, 0x0A, 0x00], &hash]));

    // GAP: the name, the appearance and the preferred parameters.
    golden(s, &app, &[0x0A, 0x03, 0x00], &join(&[&[0x0B], example::NAME]));
    golden(s, &app, &[0x0A, 0x05, 0x00], &[0x0B, 0xC1, 0x03]);
    golden(s, &app, &[0x0A, 0x07, 0x00], &join(&[&[0x0B], &ppcp(PARAMS)]));
    // Device information: the PnP ID.
    golden(s, &app, &[0x0A, 0x11, 0x00], &[0x0B, 0x02, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01]);
    // Battery: the level, then its configuration.
    golden(s, &app, &[0x0A, 0x0D, 0x00], &[0x0B, 90]);
    golden(s, &app, &[0x12, 0x0E, 0x00, 0x01, 0x00], &[0x13]);

    // HID: the Report Map with Read and Read Blob while a full 22 octets
    // come back, then the HID Information.
    golden(s, &app, &[0x0A, 0x16, 0x00], &join(&[&[0x0B], &REPORT_MAP[..22]]));
    for offset in [22_u8, 44, 66, 88] {
        let start = usize::from(offset);
        golden(s, &app, &[0x0C, 0x16, 0x00, offset, 0x00], &join(&[&[0x0D], &REPORT_MAP[start..start + 22]]));
    }
    golden(s, &app, &[0x0C, 0x16, 0x00, 110, 0x00], &join(&[&[0x0D], &REPORT_MAP[110..]]));
    // A value whose length is a multiple of 22 ends with an empty blob.
    golden(s, &app, &[0x0C, 0x16, 0x00, 126, 0x00], &[0x0D]);
    golden(s, &app, &[0x0A, 0x14, 0x00], &[0x0B, 0x11, 0x01, 0x00, 0x03]);

    // Each input report: its value, its Report Reference, its
    // configuration read, then written.
    for (value, length, id) in [(0x1A_u8, 8, 1_u8), (0x1E, 2, 2), (0x22, 5, 3)] {
        golden(s, &app, &[0x0A, value, 0x00], &join(&[&[0x0B], &[0; 8][..length]]));
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
    let len = s.notify(example::KEYBOARD, &report, Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &*join(&[&[0x1B, 0x1A, 0x00], &report]));
    let len = s.notify(example::CONSUMER, &[0xE9, 0x00], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x1E, 0x00, 0xE9, 0x00]);
    let len = s.notify(example::MOUSE, &[0, 1, 0, 0xFF, 0xFF], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x22, 0x00, 0, 1, 0, 0xFF, 0xFF]);
    let len = s.notify(example::BATTERY_LEVEL, &[89], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x0D, 0x00, 89]);
    assert_eq!(s.subscriptions().bits(), 0b0101_0101);
    assert_eq!(BATTERY_LEVEL_VALUE.index(), 0);
}

/// The reconnection of a bonded central with a cached table: the hash
/// matches, so no discovery follows.
#[test]
fn a_reconnection_reads_the_hash_and_restores_nothing_it_did_not_write() {
    let app = App::new();
    let mut server = Server::new(&DB);
    server.restore(crate::host::gatt::Subscriptions::from_bits(0b0101_0101));
    golden(&mut server, &app, &[0x02, 0x05, 0x02], &[0x03, 0x17, 0x00]);
    golden(
        &mut server,
        &app,
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x2A, 0x2B],
        &join(&[&[0x09, 0x12, 0x0A, 0x00], &DB.hash()]),
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
    assert_eq!(server.notify(example::KEYBOARD, &[0; 8], Sec::Open, &mut out), Err(NotifyError::Insecure));
    assert!(server.notify(example::BATTERY_LEVEL, &[1], Sec::Open, &mut out).is_ok());
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

#[test]
fn requests_the_server_does_not_serve_get_request_not_supported() {
    let app = App::new();
    let mut server = Server::new(&DB);
    // Prepare Write, Execute Write, Read Multiple, Read Multiple Variable
    // and an unknown request.
    for request in [
        &[0x16, 0x16, 0x00, 0x00, 0x00, 0x01][..],
        &[0x18, 0x01],
        &[0x0E, 0x03, 0x00, 0x05, 0x00],
        &[0x20, 0x03, 0x00, 0x05, 0x00],
        &[0x3F],
    ] {
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
    let request = join(&[&[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &long]);
    golden(&mut server, &app, &request, &[0x07, 0x12, 0x00, 0x24, 0x00]);
    long[12] = 0x13;
    let request = join(&[&[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28], &long]);
    golden(&mut server, &app, &request, &[0x01, 0x06, 0x01, 0x00, 0x0A]);
    golden(&mut server, &app, &[0x06, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28, 0x19, 0x2A], &[0x01, 0x06, 0x01, 0x00, 0x0A]);
    // Read By Type with a 128-bit type.
    long[12] = 0x19;
    long[13] = 0x2A;
    let request = join(&[&[0x08, 0x01, 0x00, 0xFF, 0xFF], &long]);
    golden(&mut server, &app, &request, &[0x09, 0x03, 0x0D, 0x00, 90]);
}

#[test]
fn notifications_need_a_subscription_and_fit_the_mtu() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let mut out = [0_u8; MTU];
    assert_eq!(server.notify(example::KEYBOARD, &[0; 8], Sec::Encrypted, &mut out), Err(NotifyError::NotSubscribed));
    golden(&mut server, &app, &[0x12, 0x1B, 0x00, 0x01, 0x00], &[0x13]);
    assert!(server.notify(example::KEYBOARD, &[0; 8], Sec::Encrypted, &mut out).is_ok());
    assert!(server.notify(example::KEYBOARD, &[0; 20], Sec::Encrypted, &mut out).is_ok());
    assert_eq!(server.notify(example::KEYBOARD, &[0; 21], Sec::Encrypted, &mut out), Err(NotifyError::TooLong));
    // Only notifications were enabled.
    assert_eq!(server.indicate(example::KEYBOARD, &[0; 8], Sec::Encrypted, &mut out), Err(NotifyError::NotSubscribed));
    assert_eq!(server.service_changed(Sec::Encrypted, &mut out), None);
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
fn service_changed_is_indicated_only_after_this_links_configuration_write() {
    let app = App::new();
    let mut server = Server::new(&TEST_DB);
    let mut out = [0_u8; MTU];
    assert_eq!(TEST_DB.service_changed(), Some(CHANGED));
    assert_eq!(CHANGED.handle(), 3);
    // Restored from a bond only: not written on this link.
    server.restore(crate::host::gatt::Subscriptions::from_bits(0b10));
    assert_eq!(server.service_changed(Sec::Encrypted, &mut out), None);
    golden(&mut server, &app, &[0x12, 0x04, 0x00, 0x02, 0x00], &[0x13]);
    let len = server.service_changed(Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1D, 0x03, 0x00, 0x01, 0x00, 0xFF, 0xFF]);
    assert!(server.is_indicating());
    // One at a time, until the confirmation.
    assert_eq!(server.service_changed(Sec::Encrypted, &mut out), None);
    assert_eq!(server.indicate(CHANGED, &[0; 4], Sec::Encrypted, &mut out), Err(NotifyError::Pending));
    assert!(exchange(&mut server, &app, &[0x1E], Sec::Encrypted).is_none());
    assert!(!server.is_indicating());
    assert!(server.service_changed(Sec::Encrypted, &mut out).is_some());
    server.cancel_indication();
    assert!(!server.is_indicating());
    // Turned off on this link: nothing more.
    golden(&mut server, &app, &[0x12, 0x04, 0x00, 0x00, 0x00], &[0x13]);
    assert_eq!(server.service_changed(Sec::Encrypted, &mut out), None);
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
        &join(&[&[0x11, 0x14, 0x05, 0x00, 0x0A, 0x00], &LONG_SERVICE]),
    );
    // Characteristic declarations: 7 octets, then 21 in the next response.
    golden(&mut server, &app, &[0x08, 0x05, 0x00, 0x0A, 0x00, 0x03, 0x28], &[
        0x09, 0x07, 0x06, 0x00, 0x02, 0x07, 0x00, 0x00, 0x2A,
    ]);
    golden(
        &mut server,
        &app,
        &[0x08, 0x07, 0x00, 0x0A, 0x00, 0x03, 0x28],
        &join(&[&[0x09, 0x15, 0x08, 0x00, 0x0E, 0x09, 0x00], &LONG_CHAR]),
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
    golden(&mut server, &app, &[0x04, 0x09, 0x00, 0xFF, 0xFF], &join(&[&[0x05, 0x02, 0x09, 0x00], &LONG_CHAR]));
    golden(&mut server, &app, &[0x04, 0x0A, 0x00, 0xFF, 0xFF], &[0x05, 0x01, 0x0A, 0x00, 0x01, 0x29]);
    // An indicate-only value cannot be read.
    golden(&mut server, &app, &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x05, 0x2A], &[0x01, 0x08, 0x03, 0x00, 0x02]);
    // The descriptor is longer than a Read By Type entry holds: cut.
    golden(
        &mut server,
        &app,
        &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x01, 0x29],
        &join(&[&[0x09, 0x0D, 0x0A, 0x00], b"description"]),
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
    assert_eq!(server.indicate(SECRET_INDICATE, &[1], Sec::Open, &mut out), Err(NotifyError::Insecure));
    assert!(!server.is_indicating());
    assert!(server.notify(OPEN_NOTIFY, &[1; 8], Sec::Open, &mut out).is_ok());
    let len = server.notify(SECRET_NOTIFY, &[1; 8], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1B, 0x03, 0x00, 1, 1, 1, 1, 1, 1, 1, 1]);
    let len = server.indicate(SECRET_INDICATE, &[1], Sec::Encrypted, &mut out).unwrap();
    assert_eq!(&out[..len], &[0x1D, 0x06, 0x00, 1]);
    // Their configuration descriptors need the same.
    let response = exchange(&mut server, &app, &[0x0A, 0x04, 0x00], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x0A, 0x04, 0x00, 0x0F]);
    let response = exchange(&mut server, &app, &[0x12, 0x07, 0x00, 0x02, 0x00], Sec::Open).unwrap();
    assert_eq!(*response, [0x01, 0x12, 0x07, 0x00, 0x0F]);
}
