//! What the nRF52832 alone needs: the registers of the workarounds of
//! anomalies 182 and 192, which its product specification does not
//! document, the turnaround timing of Zephyr's Nordic HAL for this chip, its
//! transmit power levels and its 8-bit TIFS register.

use crate::radio::Phy;
use embassy_nrf::pac::RADIO;

/// Register holding the enable bit for the fixes of anomalies 102, 106 and
/// 107 (anomaly 182), and that bit.
pub const ANOMALY_182: Option<(usize, u32)> = Some((0x4000_173C, 1_u32.strict_shl(10)));
/// Register of the workaround for nRF52832 anomaly 192: the RC oscillator's
/// frequency can be off by more than 500 ppm after a calibration during
/// which the CPU slept.
pub const ANOMALY_192: Option<usize> = Some(0x4000_0C34);
/// Transmit power levels in dBm, lowest first: the radio's levels from
/// -20 dBm up.
pub const LEVELS_DBM: [i8; 8] = [-20, -16, -12, -8, -4, 0, 3, 4];

/// Delay of the receive chain in ns on `phy`, from the last bit on air to
/// the radio's END event, as in Zephyr's Nordic HAL (`radio_nrf52832.h`):
/// `HAL_RADIO_NRF52832_RX_CHAIN_DELAY_1M_NS` 9400 and
/// `HAL_RADIO_NRF52832_RX_CHAIN_DELAY_2M_NS` 5450 ("5.0 + 0.45").
#[inline]
#[must_use = "the delay is only computed"]
pub const fn rx_chain_ns(phy: Phy) -> u32 {
    match phy {
        Phy::M1 => 9400,
        Phy::M2 => 5450,
    }
}

/// Sets the radio's interframe space to `us`: TIFS has eight bits on the
/// nRF52832.
#[inline]
pub fn set_tifs(us: u8) { RADIO.tifs().write(|w| w.set_tifs(us)); }

/// Time in ns from TXEN until the first bit of the packet is on air on
/// `phy`, with the fast ramp-up, as in Zephyr's Nordic HAL
/// (`radio_nrf52832.h`): `HAL_RADIO_NRF52832_TXEN_TXIDLE_TX_1M_FAST_NS` 41050
/// ("40.1 + 0.95") and `HAL_RADIO_NRF52832_TXEN_TXIDLE_TX_2M_FAST_NS` 40000
/// ("40.1 - 0.1").
#[inline]
#[must_use = "the time is only computed"]
pub const fn tx_ready_ns(phy: Phy) -> u32 {
    match phy {
        Phy::M1 => 41_050,
        Phy::M2 => 40_000,
    }
}

#[cfg(test)]
mod tests {
    use crate::radio::Phy;

    #[test]
    fn turnaround_offsets_match_nrf52832_hal_timing_vectors() {
        assert_eq!(Phy::M2.response_offset_us(Phy::M1), 101);
        assert_eq!(Phy::M1.response_offset_us(Phy::M2), 103);
        assert_eq!(Phy::M1.response_offset_us(Phy::M1), 100);
        assert_eq!(Phy::M2.response_offset_us(Phy::M2), 105);
        // Ready 8 us before the earliest packet: 150 - 41 - 8.
        assert_eq!(Phy::M1.listen_offset_us(), 101);
        assert_eq!(Phy::M2.listen_offset_us(), 101);
    }
}
