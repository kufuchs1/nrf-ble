//! A device defined outside the crate, as a firmware defines its own: an
//! attribute table built with the exported `gatt!` macro, its advertising
//! content and schedules and the host's configuration, all from the public
//! API only.

use embassy_time::Duration;
use nrf_ble::{
    host::{
        adv::{
            AD_NAME,
            AD_SHORT_NAME,
            Advertising,
            BATTERY_SERVICE,
            Content,
            HID_SERVICE,
            Mode,
            Overflow,
            Phase,
            Schedule,
        },
        att::{ATT_MAX, Server},
        engine::{Config, Unclaimed},
        gatt::{AttError, Handler, PROP_NOTIFY, PROP_READ, Sec, Uuid, Value, ValueId, ppcp},
    },
    link::ParamRange,
};

/// The device's own name.
const NAME: &[u8] = b"Device Under Test";
/// Appearance: a generic remote control (0x0180).
const APPEARANCE: u16 = 0x0180;
/// The connection parameters it asks for.
const PARAMS: ParamRange = ParamRange::new(24, 40, 4, 400);
/// The Peripheral Preferred Connection Parameters of [`PARAMS`].
const PPCP: [u8; 8] = ppcp(PARAMS);
/// The battery level, through the handler.
const LEVEL: ValueId = ValueId::new(0);
/// A vendor service, 128-bit, least significant octet first.
const VENDOR: [u8; 16] =
    [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
/// A vendor characteristic.
const VENDOR_STATUS: [u8; 16] =
    [0x11, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];

nrf_ble::gatt! {
    /// The device's table.
    pub const DB;
    service 0x1800 {
        char 0x2A00 [read] = Value::Const(NAME);
        char 0x2A01 [read] = Value::Const(&APPEARANCE.to_le_bytes());
        char 0x2A04 [read] = Value::Const(&PPCP);
    }
    service 0x1801 {
        char 0x2B2A [read] = Value::Hash;
        // With the feature `eatt`, as a firmware lists them under a feature
        // of its own that enables nrf-ble's.
        #[cfg(feature = "eatt")]
        char 0x2B29 [read, write] = Value::ClientFeatures;
        #[cfg(feature = "eatt")]
        char 0x2B3A [read] = Value::ServerFeatures;
    }
    service 0x180F {
        /// The battery level.
        char BATTERY: 0x2A19 [read, notify] = Value::Dynamic(LEVEL);
        ccc;
    }
    service (Uuid::U128(&VENDOR)) {
        /// The vendor status, encrypted.
        char STATUS: (Uuid::U128(&VENDOR_STATUS)) [read, notify; encrypted] = Value::Zeros(4);
        ccc;
    }
}

/// 20 ms for 1 s, then 100 ms for 29 s.
const PHASES: [Phase; 2] = [Phase::new(32, Duration::from_secs(1)), Phase::new(160, Duration::from_secs(29))];
/// Pairing: 30 s to pair.
const PAIRING: Schedule = Schedule::new(&PHASES, Duration::from_secs(30));
/// What the device advertises.
const CONTENT: Content<'static> = Content::new(NAME, APPEARANCE, &[HID_SERVICE, BATTERY_SERVICE]);
/// The host's configuration.
const CONFIG: Config = Config::new(Some(PARAMS), Unclaimed::Disconnect);
/// How much higher the handles after the GATT service are with the feature
/// `eatt`: its two feature characteristics.
const SHIFT: u16 = if cfg!(feature = "eatt") { 4 } else { 0 };

/// The application's side of the dynamic value.
struct App;

impl Handler for App {
    fn read(&self, id: ValueId, out: &mut [u8]) -> Result<usize, AttError> {
        match out.first_mut() {
            Some(level) if id == LEVEL => {
                *level = 42;
                Ok(1)
            },
            _ => Err(AttError::UNLIKELY_ERROR),
        }
    }

    fn write(&self, _id: ValueId, _data: &[u8], _with_response: bool) -> Result<(), AttError> {
        Err(AttError::WRITE_NOT_PERMITTED)
    }
}

/// A Read Request for `handle`.
fn read(handle: u16) -> Vec<u8> { [&[0x0A][..], &handle.to_le_bytes()].concat() }

/// Sends `request` to a server of [`DB`] on a link of security `level`: its
/// response, empty if there is none.
fn exchange(request: &[u8], level: Sec) -> Vec<u8> {
    let mut server = Server::new(&DB);
    let mut out = [0; ATT_MAX];
    let len = server.handle(request, level, &App, &mut out);
    len.and_then(|response| out.get(..response)).unwrap_or_default().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_has_its_handles() {
        assert_eq!(DB.last_handle(), 18 + SHIFT);
        assert_eq!(DB.cccds(), 2);
        assert_eq!(DB.service_changed(), None);
        assert_eq!(BATTERY.handle(), 13 + SHIFT);
        assert_eq!(BATTERY.cccd(), Some(0));
        assert_eq!(BATTERY.props(), PROP_READ | PROP_NOTIFY);
        assert_eq!(STATUS.handle(), 17 + SHIFT);
        assert_eq!(STATUS.cccd(), Some(1));
        assert_eq!(STATUS.sec(), Sec::Encrypted);
    }

    #[test]
    fn the_server_serves_the_table() {
        let mut name = vec![0x0B];
        name.extend_from_slice(NAME);
        assert_eq!(exchange(&[0x0A, 0x03, 0x00], Sec::Open), name);
        assert_eq!(exchange(&[0x0A, 0x05, 0x00], Sec::Open), [0x0B, 0x80, 0x01]);
        assert_eq!(exchange(&[0x0A, 0x07, 0x00], Sec::Open), [&[0x0B][..], &PPCP].concat());
        assert_eq!(exchange(&[0x0A, 0x0A, 0x00], Sec::Open), [&[0x0B][..], &DB.hash()].concat());
        assert_eq!(exchange(&read(BATTERY.handle()), Sec::Open), [0x0B, 42]);
        // The vendor status needs encryption.
        let [status0, status1] = STATUS.handle().to_le_bytes();
        assert_eq!(exchange(&read(STATUS.handle()), Sec::Open), [0x01, 0x0A, status0, status1, 0x0F]);
        assert_eq!(exchange(&read(STATUS.handle()), Sec::Encrypted), [0x0B, 0, 0, 0, 0]);
        // The vendor service, with its real end handle.
        let [start0, start1] = (15 + SHIFT).to_le_bytes();
        let [end0, end1] = DB.last_handle().to_le_bytes();
        assert_eq!(
            exchange(&[0x10, start0, start1, 0xFF, 0xFF, 0x00, 0x28], Sec::Open),
            [&[0x11, 20, start0, start1, end0, end1][..], &VENDOR].concat()
        );
        // With `eatt`, the features, readable without encryption.
        if cfg!(feature = "eatt") {
            assert_eq!(exchange(&read(12), Sec::Open), [0x0B, 0x00]);
            assert_eq!(exchange(&read(14), Sec::Open), [0x0B, 0x01]);
        }
    }

    #[test]
    fn the_device_advertises_its_own_content() {
        let built = Advertising::new(Mode::Pairing, &PAIRING, &CONTENT).ok();
        assert!(built.is_some(), "the content fits");
        let Some(advertising) = built else { return };
        let adv = advertising.data().as_bytes();
        assert_eq!(adv.get(..13), Some(&[2, 0x01, 0x06, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0x80, 0x01][..]));
        if cfg!(feature = "extended-advertising") {
            // The name complete in the advertising data, no scan response.
            assert_eq!(adv.get(13..), Some([&[18, AD_NAME][..], NAME].concat().as_slice()));
            assert!(advertising.scan().is_empty());
        } else {
            assert_eq!(adv.get(13..15), Some(&[17, AD_SHORT_NAME][..]));
            assert_eq!(adv.get(15..), NAME.get(..16));
            assert_eq!(advertising.scan().as_bytes(), [&[18, AD_NAME][..], NAME].concat());
        }
        assert_eq!(advertising.schedule(), &PAIRING);
        assert_eq!(PAIRING.total(), Duration::from_secs(30));
        let with_power = CONTENT.with_tx_power(Some(-4));
        assert_eq!(with_power.tx_power, Some(-4));
        if cfg!(feature = "extended-advertising") {
            // A long name is only shortened; refused only if not one character
            // fits after the other structures.
            assert_eq!(Content::new(&[b'x'; 241], APPEARANCE, &[]).data(true).err(), None);
            assert_eq!(Content::new(b"x", APPEARANCE, &[0x1800; 117]).data(true).err(), Some(Overflow::TooLong));
        } else {
            // The complete name has to fit the scan response.
            assert_eq!(Content::new(&[b'x'; 30], APPEARANCE, &[]).data(true).err(), Some(Overflow::TooLong));
        }
    }

    #[test]
    fn the_configuration_is_the_device_s() {
        assert_eq!(CONFIG.params, Some(PARAMS));
        assert_eq!(CONFIG.unclaimed, Unclaimed::Disconnect);
    }
}
