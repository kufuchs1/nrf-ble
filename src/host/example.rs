//! The tests' example device: a remote with a keyboard, consumer control
//! and a mouse over HID, a battery and device information, defined as a
//! device crate defines its own (see the readme), for the host tests only.
//!
//! | Handle | Attribute |
//! |---|---|
//! | 1 | GAP service 0x1800 |
//! | 2, 3 | Device Name 0x2A00, read: [`NAME`] |
//! | 4, 5 | Appearance 0x2A01, read: 0x03C1, a keyboard |
//! | 6, 7 | Peripheral Preferred Connection Parameters 0x2A04, read: [`PARAMS`] |
//! | 8 | GATT service 0x1801 |
//! | 9, 10 | Database Hash 0x2B2A, read: the table's hash |
//! | 11 | Battery service 0x180F |
//! | 12, 13, 14 | Battery Level 0x2A19, read and notify, through the handler as [`BATTERY_LEVEL_VALUE`]; its configuration |
//! | 15 | Device Information service 0x180A |
//! | 16, 17 | PnP ID 0x2A50, read: [`PNP_ID`] |
//! | 18 | HID service 0x1812 |
//! | 19, 20 | HID Information 0x2A4A, read: [`HID_INFORMATION`] |
//! | 21, 22 | Report Map 0x2A4B, read: [`REPORT_MAP`] |
//! | 23, 24 | HID Control Point 0x2A4C, write without response, ignored |
//! | 25 to 28 | Keyboard input report 0x2A4D (ID 1, 8 octets): value, configuration, Report Reference |
//! | 29 to 32 | Consumer input report 0x2A4D (ID 2, 2 octets): the same |
//! | 33 to 36 | Mouse input report 0x2A4D (ID 3, 5 octets): the same |
//!
//! The input reports need an encrypted link to be read, configured or
//! notified, and read as zeros. There is no Service Changed characteristic,
//! no Protocol Mode and no boot report.

use crate::{
    bytes::le16,
    host::{
        adv::{Advertising, BATTERY_SERVICE, Content, HID_SERVICE, Mode, Overflow, Phase, Schedule},
        engine::{Config, Unclaimed},
        gatt::{Value, ValueId, ppcp},
    },
    link::ParamRange,
};
use embassy_time::Duration;

/// The device name: 18 octets, so the advertising data shortens it.
pub const NAME: &[u8] = b"Example HID Remote";
/// Appearance: a keyboard (0x03C1), least significant octet first.
pub const APPEARANCE: [u8; 2] = [0xC1, 0x03];
/// The connection parameters the device asks for.
///
/// The Peripheral Preferred Connection Parameters characteristic and the
/// L2CAP connection parameter update request both take them: an interval of
/// 15 ms (12 units), a latency of 30 events and a timeout of 6 s.
pub const PARAMS: ParamRange = ParamRange::new(12, 12, 30, 600);
/// The `PnP` ID: vendor ID source 2 (USB), vendor 0x1209 (pid.codes), product
/// 0x0001 (a test ID) and version 0x0100, each least significant octet first.
pub const PNP_ID: [u8; 7] = [0x02, 0x09, 0x12, 0x01, 0x00, 0x00, 0x01];
/// HID Information: HID version 1.11, no country code, flags remote wake
/// and normally connectable.
pub const HID_INFORMATION: [u8; 4] = [0x11, 0x01, 0x00, 0x03];
/// Report ID of the keyboard input report.
pub const KEYBOARD_REPORT_ID: u8 = 1;
/// Report ID of the consumer control input report.
pub const CONSUMER_REPORT_ID: u8 = 2;
/// Report ID of the mouse input report.
pub const MOUSE_REPORT_ID: u8 = 3;
/// Length of the keyboard input report: modifiers, a reserved octet and six
/// key usages.
pub const KEYBOARD_REPORT_LEN: u8 = 8;
/// Length of the consumer control input report: one 16-bit usage.
pub const CONSUMER_REPORT_LEN: u8 = 2;
/// Length of the mouse input report: buttons, then X and Y as 16-bit
/// signed values.
pub const MOUSE_REPORT_LEN: u8 = 5;
/// Report type of an input report in a Report Reference.
const INPUT_REPORT: u8 = 1;
/// The battery level, which the application's handler reads.
pub const BATTERY_LEVEL_VALUE: ValueId = ValueId::new(0);
/// The Peripheral Preferred Connection Parameters value of [`PARAMS`].
const PPCP: [u8; 8] = ppcp(PARAMS);
/// Length of [`REPORT_MAP`].
pub const REPORT_MAP_LEN: usize = 126;

/// The HID report descriptor.
///
/// A keyboard (report 1), consumer control (report 2) and a mouse (report
/// 3), each an application collection with its report ID. The notifications
/// carry the reports without their ID: `BlueZ` adds it from the Report
/// Reference.
#[rustfmt::skip]
pub const REPORT_MAP: [u8; REPORT_MAP_LEN] = [
    0x05, 0x01,                     // Usage Page (Generic Desktop)
    0x09, 0x06,                     // Usage (Keyboard)
    0xA1, 0x01,                     // Collection (Application)
    0x85, KEYBOARD_REPORT_ID,       //   Report ID (1)
    0x05, 0x07,                     //   Usage Page (Keyboard/Keypad)
    0x19, 0xE0,                     //   Usage Minimum (Left Control)
    0x29, 0xE7,                     //   Usage Maximum (Right GUI)
    0x15, 0x00,                     //   Logical Minimum (0)
    0x25, 0x01,                     //   Logical Maximum (1)
    0x75, 0x01,                     //   Report Size (1)
    0x95, 0x08,                     //   Report Count (8)
    0x81, 0x02,                     //   Input (Data, Variable, Absolute): the eight modifier bits
    0x95, 0x01,                     //   Report Count (1)
    0x75, 0x08,                     //   Report Size (8)
    0x81, 0x01,                     //   Input (Constant): the reserved octet
    0x95, 0x06,                     //   Report Count (6)
    0x75, 0x08,                     //   Report Size (8)
    0x15, 0x00,                     //   Logical Minimum (0)
    0x25, 0x65,                     //   Logical Maximum (101)
    0x05, 0x07,                     //   Usage Page (Keyboard/Keypad)
    0x19, 0x00,                     //   Usage Minimum (0)
    0x29, 0x65,                     //   Usage Maximum (101, Application)
    0x81, 0x00,                     //   Input (Data, Array, Absolute): six key usages
    0xC0,                           // End Collection
    0x05, 0x0C,                     // Usage Page (Consumer)
    0x09, 0x01,                     // Usage (Consumer Control)
    0xA1, 0x01,                     // Collection (Application)
    0x85, CONSUMER_REPORT_ID,       //   Report ID (2)
    0x15, 0x00,                     //   Logical Minimum (0)
    0x26, 0xFF, 0x03,               //   Logical Maximum (1023)
    0x19, 0x00,                     //   Usage Minimum (0)
    0x2A, 0xFF, 0x03,               //   Usage Maximum (1023)
    0x75, 0x10,                     //   Report Size (16)
    0x95, 0x01,                     //   Report Count (1)
    0x81, 0x00,                     //   Input (Data, Array, Absolute): one consumer usage, 0 when released
    0xC0,                           // End Collection
    0x05, 0x01,                     // Usage Page (Generic Desktop)
    0x09, 0x02,                     // Usage (Mouse)
    0xA1, 0x01,                     // Collection (Application)
    0x85, MOUSE_REPORT_ID,          //   Report ID (3)
    0x09, 0x01,                     //   Usage (Pointer)
    0xA1, 0x00,                     //   Collection (Physical)
    0x05, 0x09,                     //     Usage Page (Button)
    0x19, 0x01,                     //     Usage Minimum (1)
    0x29, 0x03,                     //     Usage Maximum (3)
    0x15, 0x00,                     //     Logical Minimum (0)
    0x25, 0x01,                     //     Logical Maximum (1)
    0x95, 0x03,                     //     Report Count (3)
    0x75, 0x01,                     //     Report Size (1)
    0x81, 0x02,                     //     Input (Data, Variable, Absolute): three buttons
    0x95, 0x01,                     //     Report Count (1)
    0x75, 0x05,                     //     Report Size (5)
    0x81, 0x01,                     //     Input (Constant): padding to the octet
    0x05, 0x01,                     //     Usage Page (Generic Desktop)
    0x09, 0x30,                     //     Usage (X)
    0x09, 0x31,                     //     Usage (Y)
    0x16, 0x01, 0x80,               //     Logical Minimum (-32767)
    0x26, 0xFF, 0x7F,               //     Logical Maximum (32767)
    0x75, 0x10,                     //     Report Size (16)
    0x95, 0x02,                     //     Report Count (2)
    0x81, 0x06,                     //     Input (Data, Variable, Relative): X and Y motion
    0xC0,                           //   End Collection
    0xC0,                           // End Collection
];

crate::gatt! {
    /// The table: see the module documentation.
    pub const DB;
    service 0x1800 {
        char 0x2A00 [read] = Value::Const(NAME);
        char 0x2A01 [read] = Value::Const(&APPEARANCE);
        char 0x2A04 [read] = Value::Const(&PPCP);
    }
    service 0x1801 {
        char 0x2B2A [read] = Value::Hash;
    }
    service 0x180F {
        /// The Battery Level, which the application notifies.
        char BATTERY_LEVEL: 0x2A19 [read, notify] = Value::Dynamic(BATTERY_LEVEL_VALUE);
        ccc;
    }
    service 0x180A {
        char 0x2A50 [read] = Value::Const(&PNP_ID);
    }
    service 0x1812 {
        char 0x2A4A [read] = Value::Const(&HID_INFORMATION);
        char 0x2A4B [read] = Value::Const(&REPORT_MAP);
        char 0x2A4C [write_without_response] = Value::Sink;
        /// The keyboard input report, ID 1.
        char KEYBOARD: 0x2A4D [read, notify; encrypted] = Value::Zeros(KEYBOARD_REPORT_LEN);
        ccc;
        desc 0x2908 [read] = Value::Const(&[KEYBOARD_REPORT_ID, INPUT_REPORT]);
        /// The consumer control input report, ID 2.
        char CONSUMER: 0x2A4D [read, notify; encrypted] = Value::Zeros(CONSUMER_REPORT_LEN);
        ccc;
        desc 0x2908 [read] = Value::Const(&[CONSUMER_REPORT_ID, INPUT_REPORT]);
        /// The mouse input report, ID 3.
        char MOUSE: 0x2A4D [read, notify; encrypted] = Value::Zeros(MOUSE_REPORT_LEN);
        ccc;
        desc 0x2908 [read] = Value::Const(&[MOUSE_REPORT_ID, INPUT_REPORT]);
    }
}

/// The advertising phases: 20 ms for 3 s, 50 ms for 12 s, 400 ms for 45 s.
pub const PHASES: [Phase; 3] = [
    Phase::new(32, Duration::from_secs(3)),
    Phase::new(80, Duration::from_secs(12)),
    Phase::new(640, Duration::from_secs(45)),
];
/// Pairing: [`PHASES`], and 60 s to pair.
pub const PAIRING: Schedule = Schedule::new(&PHASES, Duration::from_secs(60));
/// Reconnection: [`PHASES`], and 20 s for the bonded central to encrypt.
pub const RECONNECT: Schedule = Schedule::new(&PHASES, Duration::from_secs(20));
/// What the device advertises: its name and appearance, the HID and Battery
/// services, no TX power level.
pub const CONTENT: Content<'static> = Content::new(NAME, le16(APPEARANCE), &[HID_SERVICE, BATTERY_SERVICE]);
/// The engine's configuration: [`PARAMS`], and a link nobody waits for is
/// kept.
pub const CONFIG: Config = Config::new(Some(PARAMS), Unclaimed::Keep);

/// The advertising in `mode`: [`CONTENT`] with `tx_power`, on [`PAIRING`] or
/// [`RECONNECT`].
pub fn advertising(mode: Mode<'_>, tx_power: Option<i8>) -> Result<Advertising<'_>, Overflow> {
    let schedule = match mode {
        Mode::Pairing => &PAIRING,
        Mode::Reconnect(_) => &RECONNECT,
    };
    Advertising::new(mode, schedule, &CONTENT.with_tx_power(tx_power))
}
