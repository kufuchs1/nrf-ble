//! What the nRF52833 alone needs: the turnaround timing of Zephyr's Nordic
//! HAL for this chip, its transmit power levels up to +8 dBm and its 10-bit
//! TIFS register, and none of the nRF52832's workarounds that write
//! undocumented registers.
//!
//! Nothing of this crate has run on an nRF52833. Its timing comes from
//! Zephyr's `radio_nrf52833.h` (zephyrproject-rtos/zephyr, commit
//! 02f236e1206013b780c522f4edc47badbaeb2a62), whose constants Zephyr
//! describes as "based on empirical measurements and sniffer logs"; this
//! crate has not measured them. The receiver's ready time with the fast
//! ramp-up is the nRF52832's (`HAL_RADIO_NRF52833_RXEN_RXIDLE_RX_1M_FAST_NS`
//! and `_2M_FAST_NS` 40300, "40.1 + 0.2", as on the nRF52832), so
//! [`super::RX_READY_US`] serves both chips, as does
//! [`super::TX_CHAIN_NS`].
//!
//! # Errata
//!
//! Which errata apply to the nRF52833 comes from Nordic's nrfx
//! (`bsp/stable/mdk/nrf52/nrf52_erratas.h`, release v4.7.1), which lists each
//! erratum for the chips and revisions it concerns; the titles come from
//! Nordic's code that works around them, as Nordic's errata document for the
//! nRF52833 could not be read for this port.
//!
//! - **182** ("RADIO: Fixes for anomalies #102, #106, and #107 do not take
//!   effect", nrfx `system_nrf52.c`), **102**, **106** and **107**: nRF52832
//!   only. [`ANOMALY_182`] is `None`, so [`super::radio_trim`] writes nothing
//!   here, as Zephyr's `hal_radio_reset` for this chip ("Nothing to be done for
//!   this target").
//! - **192** (the RC oscillator after a calibration, nrfx
//!   `nrfx_clock_lfclk.c`): nRF52832 only. [`ANOMALY_192`] is `None`, so
//!   [`super::set_calibration_workaround`] writes nothing here.
//! - **201** (HFCLKSTARTED may come twice, nrfx `nrfx_clock_hfclk.c`) and
//!   **179** (an RTC compare event may come twice): nRF52832 only. The link
//!   layer's self-disabling PPI channels guard against both, and stay on the
//!   nRF52833, where they do no harm.
//! - **78** (TIMER: the STOP task leaves the timer drawing current, which nrfx
//!   avoids with SHUTDOWN, `doc/errata.dox`): applies. TIMER0 and TIMER1 are
//!   shut down as on the nRF52832.
//! - **36** ("CLOCK: Some registers are not reset when expected", nrfx
//!   `system_nrf52.c`: `EVENTS_DONE`, `EVENTS_CTTO`, `CTIV`): applies. The
//!   calibration clears `EVENTS_DONE` before it starts one, and the link layer
//!   uses neither the calibration timer nor its event.
//! - **66** ("TEMP: Linearity specification not met with default settings",
//!   nrfx `system_nrf52.c`): applies. embassy-nrf's `init` loads the TEMP
//!   coefficients from FICR on every nRF52.
//! - **225** (the RSSI depends on the temperature; Nordic's 802.15.4 driver,
//!   hal_nordic `nrf_802154_rssi.c`, corrects a sample by +3 dB at -30 °C or
//!   below down to -3 dB at 85 °C, and -4 dB above): applies, not corrected.
//!   Zephyr's Bluetooth controller does not correct it either; the power
//!   control's 12 dB between stepping down and up absorbs a few dB, and
//!   `Link::rssi` reports the uncorrected value.
//! - Outside the link layer: the other errata with an nRF52833 branch in nrfx
//!   concern peripherals this crate does not use, according to nrfx's
//!   `doc/errata.dox` and the code that works around them: I2S (55, 194, 196),
//!   GPIO and GPIOTE (173, 210), TWIM (219), SAADC (212, 237, 241), NFCT (190,
//!   218), USBD (187, 211, 223), NVMC (233), RESETREAS (136) and the system
//!   (246).
//! - Open: the errata with an nRF52833 branch in nrfx whose subject the sources
//!   above do not name, 20, 87, 170, 176, 183, 184, 228, 236 (first revision
//!   only), 243, 245, 248, 250, 251, 252, 258, 259, 263, 266, 267, 268 and 271
//!   (20, 87, 176, 183, 245, 252 and 266 also concern the nRF52832). Whether
//!   one of them touches RADIO, TIMER, RTC, CLOCK, PPI or CCM is to be read in
//!   Nordic's errata document.

use crate::radio::Phy;
use embassy_nrf::pac::RADIO;

/// No fix for anomaly 182: it and the anomalies 102, 106 and 107 it covers
/// are nRF52832 errata, and the register its fix writes is not documented
/// for the nRF52833.
pub const ANOMALY_182: Option<(usize, u32)> = None;
/// No workaround for anomaly 192: it is an nRF52832 erratum, and the
/// register its workaround writes is not documented for the nRF52833.
pub const ANOMALY_192: Option<usize> = None;
/// Transmit power levels in dBm, lowest first: every TXPOWER setting of the
/// nRF52833 PAC, -40 dBm and -20 to +8 dBm, but for -30 dBm, which the PAC
/// marks as deprecated and documents as -40 dBm. Zephyr's
/// `hal_radio_tx_power_floor` for this chip skips it too ("The -30 dBm power
/// level is deprecated so ignore it!").
///
/// Above +4 dBm the radio needs supply headroom, and the product's
/// regulatory approval has to cover the power: the power control stays at or
/// below [`crate::power_control::CEILING_DBM`] until the firmware raises the
/// ceiling.
pub const LEVELS_DBM: [i8; 14] = [-40, -20, -16, -12, -8, -4, 0, 2, 3, 4, 5, 6, 7, 8];

/// Delay of the receive chain in ns on `phy`, from the last bit on air to
/// the radio's END event, as in Zephyr's Nordic HAL (`radio_nrf52833.h`):
/// `HAL_RADIO_NRF52833_RX_CHAIN_DELAY_1M_NS` 9400 ("9.4") and
/// `HAL_RADIO_NRF52833_RX_CHAIN_DELAY_2M_NS` 5000 ("5.0"). Not measured on
/// an nRF52833.
#[inline]
#[must_use = "the delay is only computed"]
pub const fn rx_chain_ns(phy: Phy) -> u32 {
    match phy {
        Phy::M1 => 9400,
        Phy::M2 => 5000,
    }
}

/// Sets the radio's interframe space to `us`: TIFS has ten bits on the
/// nRF52833.
#[inline]
pub fn set_tifs(us: u8) { RADIO.tifs().write(|w| w.set_tifs(u16::from(us))); }

/// Time in ns from TXEN until the first bit of the packet is on air on
/// `phy`, with the fast ramp-up, as in Zephyr's Nordic HAL
/// (`radio_nrf52833.h`): `HAL_RADIO_NRF52833_TXEN_TXIDLE_TX_1M_FAST_NS`
/// 40900 ("40.1 + 0.8") and `HAL_RADIO_NRF52833_TXEN_TXIDLE_TX_2M_FAST_NS`
/// 40000 ("40.1 - 0.1"). Not measured on an nRF52833.
#[inline]
#[must_use = "the time is only computed"]
pub const fn tx_ready_ns(phy: Phy) -> u32 {
    match phy {
        Phy::M1 => 40_900,
        Phy::M2 => 40_000,
    }
}

#[cfg(test)]
mod tests {
    use super::{ANOMALY_182, ANOMALY_192, LEVELS_DBM};
    use crate::{chip::txpower, radio::Phy};
    use embassy_nrf::pac::radio::vals::Txpower;

    #[test]
    fn no_nrf52832_workaround_writes_an_undocumented_register() {
        assert!(ANOMALY_182.is_none());
        assert!(ANOMALY_192.is_none());
    }

    /// Against the nRF52832, only the answer on LE 1M to a packet received
    /// on LE 2M moves, by 1 us: 40.9 us ready time and 5.0 us receive chain
    /// round to 46 us instead of 47.
    #[test]
    fn turnaround_offsets_match_nrf52833_hal_timing_vectors() {
        assert_eq!(Phy::M2.response_offset_us(Phy::M1), 101);
        assert_eq!(Phy::M1.response_offset_us(Phy::M2), 104);
        assert_eq!(Phy::M1.response_offset_us(Phy::M1), 100);
        assert_eq!(Phy::M2.response_offset_us(Phy::M2), 105);
        // Ready 8 us before the earliest packet: 150 - 41 - 8.
        assert_eq!(Phy::M1.listen_offset_us(), 101);
        assert_eq!(Phy::M2.listen_offset_us(), 101);
    }

    #[test]
    fn the_levels_leave_out_the_deprecated_minus_30_dbm() {
        assert!(!LEVELS_DBM.contains(&-30));
        assert_eq!(LEVELS_DBM.first(), Some(&-40));
        assert_eq!(LEVELS_DBM.last(), Some(&8));
    }

    /// The register takes the level in dBm, so the power control's own
    /// compile-time check cannot tell a level the radio lacks from one it
    /// has; this compares each level with the PAC's TXPOWER settings.
    #[test]
    fn every_level_is_a_txpower_setting_of_the_pac() {
        let settings = [
            Txpower::Neg40dBm,
            Txpower::Neg20dBm,
            Txpower::Neg16dBm,
            Txpower::Neg12dBm,
            Txpower::Neg8dBm,
            Txpower::Neg4dBm,
            Txpower::_0dBm,
            Txpower::Pos2dBm,
            Txpower::Pos3dBm,
            Txpower::Pos4dBm,
            Txpower::Pos5dBm,
            Txpower::Pos6dBm,
            Txpower::Pos7dBm,
            Txpower::Pos8dBm,
        ];
        assert_eq!(LEVELS_DBM.len(), settings.len());
        for (&level, setting) in LEVELS_DBM.iter().zip(settings) {
            assert!(txpower(level) == setting, "{level} dBm is not the PAC's setting");
        }
    }
}
