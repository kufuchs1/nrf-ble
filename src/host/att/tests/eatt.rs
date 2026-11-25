//! Tests of what the feature `eatt` adds to the server: Read Multiple
//! Variable Length, Prepare and Execute Write, the Client and Server
//! Supported Features and Multiple Handle Value Notifications.

use super::*;

crate::gatt! {
    /// The table of these tests.
    ///
    /// | Handle | Attribute |
    /// |---|---|
    /// | 1 to 7 | GATT service: Database Hash (3), Client Supported Features (5), Server Supported Features (7) |
    /// | 8 to 11 | Battery service: the level (10, 90 %, notifies), its configuration (11) |
    /// | 12 to 15 | HID service: an input report (14, 8 zeros, encrypted, notifies), its configuration (15) |
    /// | 16, 17 | the Report Map, 126 octets |
    /// | 18, 19 | the HID Control Point, write without response |
    /// | 20, 21 | the application's value 1, 4 octets, read and written encrypted |
    /// | 22, 23 | the application's value 2, whose read fails |
    const DB;
    service 0x1801 {
        char 0x2B2A [read] = Value::Hash;
        char 0x2B29 [read, write] = Value::ClientFeatures;
        char 0x2B3A [read] = Value::ServerFeatures;
    }
    service 0x180F {
        /// The battery level.
        char LEVEL: 0x2A19 [read, notify] = Value::Dynamic(BATTERY_LEVEL_VALUE);
        ccc;
    }
    service 0x1812 {
        /// An input report.
        char INPUT: 0x2A4D [read, notify; encrypted] = Value::Zeros(8);
        ccc;
        char 0x2A4B [read] = Value::Const(&REPORT_MAP);
        char 0x2A4C [write_without_response] = Value::Sink;
        char 0x2A1E [read, write; encrypted] = Value::Dynamic(ValueId::new(1));
        char 0x2A1F [read] = Value::Dynamic(ValueId::new(2));
    }
}

/// The Client Supported Features' value.
const CLIENT: u8 = 5;
/// The Server Supported Features' value.
const SERVER: u8 = 7;
/// The battery level's configuration.
const LEVEL_CCC: u8 = 11;
/// The input report's value.
const REPORT: u8 = 14;
/// The Report Map.
const MAP: u8 = 17;
/// The HID Control Point.
const SINK: u8 = 19;
/// The application's value that needs encryption.
const SECRET: u8 = 21;
/// The application's value whose read fails.
const FAILING: u8 = 23;
/// A handle past the table.
const NOWHERE: u8 = 0x63;

/// A Read Multiple Variable Length Request for `handles`.
fn read_multiple(handles: &[u8]) -> Vec<u8> {
    [&[0x20][..], &handles.iter().flat_map(|&handle| [handle, 0]).collect::<Vec<_>>()].concat()
}

/// The Error Response to `opcode` for `handle` with `code`.
fn error(opcode: u8, handle: u8, code: u8) -> [u8; 5] { [0x01, opcode, handle, 0x00, code] }

#[test]
fn read_multiple_gives_each_length_and_value_in_the_order_asked() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let level = LEVEL.handle().to_le_bytes()[0];
    golden(
        &mut server,
        &app,
        &read_multiple(&[level, 3]),
        &[&[0x21, 0x01, 0x00, 90, 0x10, 0x00][..], &DB.hash()].concat(),
    );
    // The handles may repeat, in any order.
    golden(&mut server, &app, &read_multiple(&[SECRET, level, SECRET]), &[
        0x21, 0x04, 0x00, 1, 2, 3, 4, 0x01, 0x00, 90, 0x04, 0x00, 1, 2, 3, 4,
    ]);
    // The feature values.
    golden(&mut server, &app, &read_multiple(&[SERVER, CLIENT]), &[0x21, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00]);
}

#[test]
fn read_multiple_is_cut_after_the_mtu_less_1_but_never_inside_a_length() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let level = LEVEL.handle().to_le_bytes()[0];
    // The Report Map gives its length and 20 octets: 23 in all.
    golden(&mut server, &app, &read_multiple(&[MAP, level]), &[&[0x21, 0x7E, 0x00][..], &REPORT_MAP[..20]].concat());
    golden(
        &mut server,
        &app,
        &read_multiple(&[level, MAP]),
        &[&[0x21, 0x01, 0x00, 90, 0x7E, 0x00][..], &REPORT_MAP[..17]].concat(),
    );
    // The hash and the level take 22 octets: the third length field would
    // not fit whole, so the response ends before it.
    golden(
        &mut server,
        &app,
        &read_multiple(&[3, level, level]),
        &[&[0x21, 0x10, 0x00][..], &DB.hash(), &[0x01, 0x00, 90]].concat(),
    );
    // At an ATT MTU of 65: 62 octets of the Report Map.
    golden(&mut server, &app, &[0x02, 0x05, 0x02], &[0x03, 0x41, 0x00]);
    golden(&mut server, &app, &read_multiple(&[MAP, level]), &[&[0x21, 0x7E, 0x00][..], &REPORT_MAP[..62]].concat());
}

#[test]
fn read_multiple_reports_the_first_handle_with_the_most_important_error() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let level = LEVEL.handle().to_le_bytes()[0];
    // Fewer than two handles, or half a handle.
    golden(&mut server, &app, &[0x20, level, 0x00], &error(0x20, 0, 0x04));
    golden(&mut server, &app, &[0x20], &error(0x20, 0, 0x04));
    golden(&mut server, &app, &[0x20, level, 0x00, level], &error(0x20, 0, 0x04));
    // Encryption before an invalid handle before a read that is not
    // permitted, whatever their order.
    // No response is an empty one, which none of the expected ones is.
    let exchange_open = |on: &mut Server, request: &[u8]| exchange(on, &app, request, Sec::Open).unwrap_or_default();
    assert_eq!(
        *exchange_open(&mut server, &read_multiple(&[SINK, NOWHERE, REPORT, SECRET])),
        error(0x20, REPORT, 0x0F)
    );
    golden(&mut server, &app, &read_multiple(&[SINK, level, NOWHERE, REPORT, NOWHERE]), &error(0x20, NOWHERE, 0x01));
    golden(&mut server, &app, &read_multiple(&[level, SINK, 0, SINK]), &error(0x20, 0, 0x01));
    golden(&mut server, &app, &read_multiple(&[level, SINK, REPORT]), &error(0x20, SINK, 0x02));
    // Then the application's own error, for the first value it fails.
    golden(&mut server, &app, &read_multiple(&[level, FAILING]), &error(0x20, FAILING, 0x0E));
    // All of them readable on an encrypted link.
    golden(&mut server, &app, &read_multiple(&[REPORT, level]), &[
        0x21, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 90,
    ]);
}

/// A Prepare Write Request for `handle` at `offset` with `part`.
fn prepare(handle: u8, offset: u16, part: &[u8]) -> Vec<u8> {
    let [offset0, offset1] = offset.to_le_bytes();
    [&[0x16, handle, 0x00, offset0, offset1][..], part].concat()
}

/// The Prepare Write Response that echoes `request`.
fn prepared(request: &[u8]) -> Vec<u8> { [&[0x17][..], request.get(1..).unwrap_or_default()].concat() }

#[test]
fn prepared_parts_that_follow_each_other_are_written_at_the_execute() {
    let app = App::new();
    let mut server = Server::new(&DB);
    for request in [prepare(SECRET, 0, &[0xA1, 0xA2]), prepare(SECRET, 2, &[]), prepare(SECRET, 2, &[0xA3])] {
        golden(&mut server, &app, &request, &prepared(&request));
    }
    assert_eq!(app.written.get(), None, "nothing written before the execute");
    golden(&mut server, &app, &[0x18, 0x01], &[0x19]);
    assert_eq!(app.written.get(), Some(([0xA1, 0xA2, 0xA3, 0], 3, true)));
    // The queue is empty again: an execute writes nothing.
    app.written.set(None);
    golden(&mut server, &app, &[0x18, 0x01], &[0x19]);
    assert_eq!(app.written.get(), None);
    // A client characteristic configuration in two parts.
    let level_ccc = prepare(LEVEL_CCC, 0, &[0x01]);
    golden(&mut server, &app, &level_ccc, &prepared(&level_ccc));
    let rest = prepare(LEVEL_CCC, 1, &[0x00]);
    golden(&mut server, &app, &rest, &prepared(&rest));
    golden(&mut server, &app, &[0x18, 0x01], &[0x19]);
    assert!(server.subscriptions().notifying(0));
    assert!(server.subscriptions().is_written(0));
}

#[test]
fn the_prepare_queue_takes_one_value_of_22_octets_in_order() {
    let app = App::new();
    let mut server = Server::new(&DB);
    golden(&mut server, &app, &prepare(LEVEL_CCC, 0, &[0x01]), &prepared(&prepare(LEVEL_CCC, 0, &[0x01])));
    // A gap, a part already queued, another attribute: Prepare Queue Full.
    for request in [prepare(LEVEL_CCC, 2, &[0x00]), prepare(LEVEL_CCC, 0, &[0x01]), prepare(SECRET, 1, &[0x00])] {
        golden(&mut server, &app, &request, &error(0x16, request.get(1).copied().unwrap_or_default(), 0x09));
    }
    golden(&mut server, &app, &[0x18, 0x00], &[0x19]);
    assert!(!server.subscriptions().is_written(0), "cancelled");
    // 18 octets, then 4: 22 in all. A 23rd is refused, the queue kept.
    let first = prepare(LEVEL_CCC, 0, &[0x01; 18]);
    golden(&mut server, &app, &first, &prepared(&first));
    let second = prepare(LEVEL_CCC, 18, &[0x02; 4]);
    golden(&mut server, &app, &second, &prepared(&second));
    golden(&mut server, &app, &prepare(LEVEL_CCC, 22, &[0x03]), &error(0x16, LEVEL_CCC, 0x09));
    assert_eq!(server.prepared.value(), [[0x01; 18].as_slice(), &[0x02; 4]].concat());
    // A configuration of 22 octets is no configuration.
    golden(&mut server, &app, &[0x18, 0x01], &error(0x18, LEVEL_CCC, 0x0D));
    // Nor are 3, and the queue is emptied after a failed execute.
    for request in [prepare(LEVEL_CCC, 0, &[0x01, 0x00]), prepare(LEVEL_CCC, 2, &[0x00])] {
        golden(&mut server, &app, &request, &prepared(&request));
    }
    golden(&mut server, &app, &[0x18, 0x01], &error(0x18, LEVEL_CCC, 0x0D));
    golden(&mut server, &app, &[0x18, 0x01], &[0x19]);
    assert!(!server.subscriptions().is_written(0));
    // A queue that does not start at the value's start: Invalid Offset.
    golden(&mut server, &app, &prepare(SECRET, 1, &[0x01]), &prepared(&prepare(SECRET, 1, &[0x01])));
    golden(&mut server, &app, &[0x18, 0x01], &error(0x18, SECRET, 0x07));
    assert_eq!(app.written.get(), None);
    golden(&mut server, &app, &[0x18, 0x01], &[0x19]);
    // A single part of 22 octets fits, at an ATT MTU of 65; 23 do not.
    golden(&mut server, &app, &[0x02, 0x05, 0x02], &[0x03, 0x41, 0x00]);
    golden(&mut server, &app, &prepare(SECRET, 0, &[0x05; 22]), &prepared(&prepare(SECRET, 0, &[0x05; 22])));
    golden(&mut server, &app, &[0x18, 0x00], &[0x19]);
    golden(&mut server, &app, &prepare(SECRET, 0, &[0x05; 23]), &error(0x16, SECRET, 0x09));
}

#[test]
fn prepare_write_checks_the_handle_the_permission_and_the_security() {
    let app = App::new();
    let mut server = Server::new(&DB);
    // No response is an empty one, which none of the expected ones is.
    let mut open = |request: &[u8]| exchange(&mut server, &app, request, Sec::Open).unwrap_or_default();
    assert_eq!(*open(&prepare(NOWHERE, 0, &[1])), error(0x16, NOWHERE, 0x01));
    assert_eq!(*open(&prepare(0, 0, &[1])), error(0x16, 0, 0x01));
    assert_eq!(*open(&prepare(SERVER, 0, &[1])), error(0x16, SERVER, 0x03));
    assert_eq!(*open(&prepare(MAP, 0, &[1])), error(0x16, MAP, 0x03));
    assert_eq!(*open(&prepare(SECRET, 0, &[1])), error(0x16, SECRET, 0x0F));
    // Malformed: no offset, a request longer than the ATT MTU, and an
    // Execute Write without flags or with flags other than 0 and 1.
    assert_eq!(*open(&[0x16, SECRET, 0x00, 0x00]), error(0x16, 0, 0x04));
    assert_eq!(*open(&prepare(LEVEL_CCC, 0, &[1; 19])), error(0x16, 0, 0x04));
    assert_eq!(*open(&[0x18]), error(0x18, 0, 0x04));
    assert_eq!(*open(&[0x18, 0x02]), error(0x18, 0, 0x04));
    assert_eq!(*open(&[0x18, 0x01, 0x00]), error(0x18, 0, 0x04));
    // The write at the execute needs the security too.
    let request = prepare(SECRET, 0, &[1]);
    assert_eq!(*assert_some!(exchange(&mut server, &app, &request, Sec::Encrypted)), *prepared(&request));
    assert_eq!(*assert_some!(exchange(&mut server, &app, &[0x18, 0x01], Sec::Open)), error(0x18, SECRET, 0x0F));
    assert_eq!(app.written.get(), None);
}

#[test]
fn the_client_features_keep_bits_0_to_2_and_never_lose_one() {
    let app = App::new();
    let mut server = Server::new(&DB);
    // No response is an empty one, which none of the expected ones is.
    let mut open = |request: &[u8]| exchange(&mut server, &app, request, Sec::Open).unwrap_or_default();
    // Both read without encryption: the client's 0, the server's EATT.
    assert_eq!(*open(&[0x0A, CLIENT, 0x00]), [0x0B, 0x00]);
    assert_eq!(*open(&[0x0A, SERVER, 0x00]), [0x0B, 0x01]);
    assert_eq!(*open(&[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x3A, 0x2B]), [0x09, 0x03, SERVER, 0x00, 0x01]);
    assert_eq!(*open(&[0x12, SERVER, 0x00, 0x00]), error(0x12, SERVER, 0x03));
    // Octet 0 holds them; its bits 3 to 7 and the octets after it are
    // ignored.
    assert_eq!(*open(&[0x12, CLIENT, 0x00, 0xFD, 0xFF, 0xFF]), [0x13]);
    assert_eq!(*open(&[0x0A, CLIENT, 0x00]), [0x0B, 0x05]);
    // BlueZ with one channel writes 05, with more 07: a bit more is taken.
    assert_eq!(*open(&[0x12, CLIENT, 0x00, 0x07]), [0x13]);
    assert_eq!(server.client_features(), 0x07);
    // A write that clears a bit is not allowed and changes nothing, an
    // empty one included; a Write Command that would is dropped.
    let mut open_raw = |request: &[u8]| exchange(&mut server, &app, request, Sec::Open);
    assert_eq!(*assert_some!(open_raw(&[0x12, CLIENT, 0x00, 0x05])), error(0x12, CLIENT, 0x13));
    assert_eq!(*assert_some!(open_raw(&[0x12, CLIENT, 0x00])), error(0x12, CLIENT, 0x13));
    assert_eq!(open_raw(&[0x52, CLIENT, 0x00, 0x00]), None);
    assert_eq!(*assert_some!(open_raw(&[0x12, CLIENT, 0x00, 0x07])), [0x13]);
    assert_eq!(server.client_features(), 0x07);
    // On a new link an empty write is 0.
    let mut new_link = Server::new(&DB);
    assert_eq!(*assert_some!(exchange(&mut new_link, &app, &[0x12, CLIENT, 0x00], Sec::Open)), [0x13]);
    assert_eq!(new_link.client_features(), 0);
    // A bond adds its bits to those written before the encryption.
    assert_eq!(exchange(&mut new_link, &app, &[0x52, CLIENT, 0x00, 0x04], Sec::Open), None);
    new_link.restore_client_features(0xF9);
    assert_eq!(new_link.client_features(), 0x05);
    assert_eq!(
        *assert_some!(exchange(&mut new_link, &app, &[0x12, CLIENT, 0x00, 0x04], Sec::Open)),
        error(0x12, CLIENT, 0x13)
    );
}

#[test]
fn multiple_notifications_need_the_client_s_bit_2_and_two_values() {
    let app = App::new();
    let mut server = Server::new(&DB);
    let mut out = [0_u8; MTU];
    // Both subscribed, the report on an encrypted link.
    golden(&mut server, &app, &[0x12, LEVEL_CCC, 0x00, 0x01, 0x00], &[0x13]);
    golden(&mut server, &app, &[0x12, REPORT + 1, 0x00, 0x01, 0x00], &[0x13]);
    let values: [(Char, &[u8]); 2] = [(LEVEL, &[50]), (INPUT, &[1, 2, 3, 4, 5, 6, 7, 8])];
    assert_eq!(server.notify_multiple(&values, Sec::Encrypted, &mut out), Err(NotifyError::Unsupported));
    golden(&mut server, &app, &[0x12, CLIENT, 0x00, 0x03], &[0x13]);
    assert_eq!(server.notify_multiple(&values, Sec::Encrypted, &mut out), Err(NotifyError::Unsupported));
    golden(&mut server, &app, &[0x12, CLIENT, 0x00, 0x04], &error(0x12, CLIENT, 0x13)[..]);
    golden(&mut server, &app, &[0x12, CLIENT, 0x00, 0x07], &[0x13]);
    let len = assert_ok!(server.notify_multiple(&values, Sec::Encrypted, &mut out));
    assert_eq!(
        out.get(..len),
        Some(&[0x23, 0x0A, 0x00, 0x01, 0x00, 50, 0x0E, 0x00, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8][..])
    );
    // Fewer than two values.
    assert_eq!(server.notify_multiple(&values[..1], Sec::Encrypted, &mut out), Err(NotifyError::Unsupported));
    assert_eq!(server.notify_multiple(&[], Sec::Encrypted, &mut out), Err(NotifyError::Unsupported));
    // Each value is checked as a notification is.
    assert_eq!(server.notify_multiple(&values, Sec::Open, &mut out), Err(NotifyError::Insecure));
    let map = DB.characteristic(16);
    assert_eq!(
        server.notify_multiple(&[(LEVEL, &[1]), (map, &[2])], Sec::Open, &mut out),
        Err(NotifyError::NotSubscribed)
    );
    assert_eq!(
        server.notify_multiple(&[(LEVEL, &[1; 21]), (LEVEL, &[2])], Sec::Open, &mut out),
        Err(NotifyError::TooLong)
    );
    // All of them in one PDU of 23 octets, never cut: 1 + 9 + 13 fits,
    // one octet more does not.
    let full = assert_ok!(server.notify_multiple(&[(LEVEL, &[1; 5]), (LEVEL, &[2; 9])], Sec::Open, &mut out));
    assert_eq!(full, MTU);
    assert_eq!(
        server.notify_multiple(&[(LEVEL, &[1; 5]), (LEVEL, &[2; 10])], Sec::Open, &mut out),
        Err(NotifyError::TooLong)
    );
    // A new link starts without the client's features.
    assert_eq!(Server::new(&DB).notify_multiple(&values, Sec::Encrypted, &mut out), Err(NotifyError::Unsupported));
}
