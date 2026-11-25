//! Register code of the nRF52832 and the nRF52833: the fast ramp-up, LE 2M,
//! the radio's S1 byte in RAM, the CCM's extended length mode and the AMLI
//! RAM priorities, which both chips share.
//!
//! Where the chips differ, the module of the chip built for (`variant`)
//! holds what differs, and the functions here apply it: the registers of
//! the errata workarounds, the radio's turnaround timing, the transmit power
//! levels and the width of the TIFS register.
//!
//! The nRF52833 PAC has fields and registers the nRF52832 lacks in the
//! peripherals the link layer drives. Each keeps a value that gives the
//! nRF52832's behaviour:
//!
//! - RADIO PCNF0: `CILEN`, `TERMLEN`, `CRCINC` and the second bit of `PLEN` are
//!   0 after `Radio::new` writes the register, which is LE 1M and LE 2M without
//!   a length field that counts the CRC; [`set_phy`] and [`set_packet_layout`]
//!   modify the register and keep them. With the feature `coded-phy`,
//!   [`set_phy`] writes `PLEN`, `CILEN` and `TERMLEN` for LE Coded and clears
//!   `CILEN` and `TERMLEN` for the other PHYs.
//! - RADIO CRCCNF: `SKIPADDR` has two bits, and `Radio::new` writes `Skip`.
//! - RADIO SHORTS: the shortcuts the nRF52832 lacks stay 0, as every write of
//!   the register leaves them.
//! - RADIO TIFS: ten bits, see [`set_tifs`].
//! - CCM MODE: `DATARATE` has two bits, and [`ccm_mode`] writes 1M or 2M, and
//!   with the feature `coded-phy` 125 kbit/s for a decryption on LE Coded.
//! - CCM `RATEOVERRIDE`: written only with the feature `coded-phy`, with 500
//!   kbit/s before a decryption on LE Coded.
//! - CCM `MAXPACKETSIZE` and `HEADERMASK`: never written, so they keep their
//!   reset values. `HEADERMASK` masks NESN, SN and MD out of the MIC, as BLE
//!   requires: Zephyr's `radio.c` writes 0xE3 for data PDUs and calls it the
//!   reset value. `MAXPACKETSIZE` is expected to reset to 251 octets, the value
//!   nrfx's workaround of nRF52840 erratum 103 restores and the one Zephyr's
//!   `radio.c` derives from a MAXLEN of 255; the nRF52833's product
//!   specification has not been checked for it. nrf-pac's `Default` for these
//!   registers is 0, not the reset value, so they must not be written with
//!   `write`.
//! - CCM ERROR: the nRF52833 PAC calls the event deprecated. The link layer
//!   only clears it and counts an operation without it as complete, which holds
//!   whether the event comes or not.
//! - CLOCK `HFXODEBOUNCE`: never written, so it keeps its reset value, and the
//!   crystal's start event comes after that debounce time; the adaptive crystal
//!   lead ([`CRYSTAL_LEAD_US`]) absorbs it.

/// What the nRF52832 alone needs.
#[cfg(feature = "nrf52832")]
#[path = "nrf52832.rs"]
mod variant;
/// What the nRF52833 alone needs.
#[cfg(feature = "nrf52833")]
#[path = "nrf52833.rs"]
mod variant;

use crate::{
    clock::RC_PPM,
    radio::{LENGTH_BITS, Phy},
};
use core::ptr::{read_volatile, with_exposed_provenance_mut, write_volatile};
#[cfg(feature = "coded-phy")]
use embassy_nrf::pac::ccm::vals::Rateoverride;
use embassy_nrf::pac::{
    CCM,
    PPI,
    RADIO,
    TEMP,
    ccm::vals::{Datarate, Length, Mode as CcmMode},
    radio::vals::{Mode, Plen, Ru, S1incl, Txpower},
};

/// Length of the coding indicator in bits, in RADIO PCNF0 on LE Coded:
/// Zephyr's `radio_pkt_configure` writes 2.
#[cfg(feature = "coded-phy")]
const CODED_CILEN: u8 = 2;
/// Length of the TERM field in bits, in RADIO PCNF0 on LE Coded: Zephyr's
/// `radio_pkt_configure` writes 3, the three bits of TERM1 and TERM2.
#[cfg(feature = "coded-phy")]
const CODED_TERMLEN: u8 = 3;
/// AMLI RAM priority register of the radio.
const AMLI_RAMPRI_RADIO: usize = 0x4000_0E08;
/// AMLI RAM priority register of the CCM.
const AMLI_RAMPRI_CCM: usize = 0x4000_0E10;
/// Time the high frequency crystal gets to start before TIMER0 restarts, at
/// first: the nRF52832's 32 MHz crystal typically starts in about 360 us.
/// The nRF52833 starts the same way, from the same lead; its crystal's start
/// time has not been measured.
pub const CRYSTAL_LEAD_US: u32 = 800;
/// Bounds of the crystal lead time.
pub const CRYSTAL_LEAD_RANGE_US: (u32, u32) = (300, 1500);
/// Largest advertising channel payload the radio accepts: as on the data
/// channels, which takes in the longest `AUX_ADV_IND` of extended
/// advertising.
pub const ADV_MAXLEN: u8 = MAX_PAYLOAD;
/// Busy-wait iterations for a decryption to finish after the packet end,
/// about 250 us at 64 MHz.
pub const DECRYPT_WAIT: u32 = 2000;
/// Busy-wait iterations for sealing a PDU ahead of its event, whose key
/// stream the CCM generates first: about 1 ms at 64 MHz, far above
/// the time it takes.
pub const SEAL_WAIT: u32 = 8000;
/// Whether host data queued while the crystal started for an event, after
/// the sleep before it stopped listening for the host, is still prepared
/// once TIMER0 restarted, within the [`crate::clock::SETUP_US`] before the
/// radio's start: a preparation takes a few microseconds at 64 MHz, the
/// radio's setup after it about as long.
pub const PREPARE_AFTER_RESTART: bool = true;
/// Whether the next PDU is prepared, and sealed, while our answer goes out,
/// so that one connection event carries several PDUs of ours: a few
/// microseconds at 64 MHz, well within our packet and the interframe space
/// after it.
pub const PREPARE_IN_EVENT: bool = true;
/// Transmit power levels in dBm, lowest first: those of the chip built for
/// ([`variant::LEVELS_DBM`]).
pub const LEVELS_DBM: [i8; variant::LEVELS_DBM.len()] = variant::LEVELS_DBM;
/// Largest payload the radio accepts on any channel.
const MAX_PAYLOAD: u8 = 255;
/// The most octets of a packet in RAM: S0, length, S1 and payload together
/// cannot exceed 258 bytes, whatever MAXLEN holds (nRF52832 Product
/// Specification v1.0, 23.3): every payload of 255 octets fits, also with
/// the data channels' S1 octet. The same limit is assumed on the nRF52833,
/// whose product specification has not been checked for it.
pub const PACKET_RAM_MAX: usize = 258;
/// Largest payload the radio accepts on any channel, for the size of the
/// packet buffers.
pub const PAYLOAD_MAX: usize = 255;
/// Whether the radio has LE 2M.
pub const PHY_2M: bool = true;
/// Receiver ready time after RXEN with fast ramp-up.
pub const RX_READY_US: u32 = 40;
/// Delay of the transmit chain in ns, from the radio's start of a packet to
/// its first bit on air: 600 ns on both chips in Zephyr's Nordic HAL
/// (`HAL_RADIO_NRF52832_TX_CHAIN_DELAY_NS` in `radio_nrf52832.h`,
/// `HAL_RADIO_NRF52833_TX_CHAIN_DELAY_1M_NS` and `_2M_NS` in
/// `radio_nrf52833.h`).
pub const TX_CHAIN_NS: u32 = 600;
/// CCM scratch space for every value of an untrusted eight-bit length field:
/// RADIO MAXLEN bounds radio DMA but does not rewrite that field for the CCM.
pub const SCRATCH_LEN: usize = 16_usize.strict_add(255);

/// Sets the CCM mode for a packet on `phy`, in the extended length mode.
#[cfg_attr(
    feature = "coded-phy",
    doc = "",
    doc = "On LE Coded a decryption runs at 125 kbit/s, and `RATEOVERRIDE` holds 500 kbit/s for the RATEBOOST of a \
           packet sent with S=2 (`crate::crypto::PPI_RATE`), as Zephyr's `radio_ccm_ext_rx_pkt_set` sets them. An \
           encryption, which runs ahead of the packet, runs at 2 Mbit/s, the fastest rate, as Zephyr's \
           `radio_ccm_ext_tx_pkt_set` does on every PHY (\"use fastest data rate as tx data needs to be prepared \
           before radio Tx on any PHY\")."
)]
#[inline]
pub fn ccm_mode(mode: CcmMode, phy: Phy) {
    #[cfg(feature = "coded-phy")]
    let rate_phy = if phy.is_coded() && mode == CcmMode::Encryption { Phy::M2 } else { phy };
    #[cfg(not(feature = "coded-phy"))]
    let rate_phy = phy;
    #[cfg(feature = "coded-phy")]
    if rate_phy.is_coded() {
        CCM.rateoverride().write(|w| w.set_rateoverride(Rateoverride::_500kbps));
    }
    CCM.mode().write(|w| {
        w.set_mode(mode);
        w.set_datarate(datarate(rate_phy));
        w.set_length(Length::Extended);
    });
}

/// The CCM data rate matching `phy`, for decryption on the fly: on LE
/// Coded the rate of S=8, which the coding indicator of each packet comes
/// with.
const fn datarate(phy: Phy) -> Datarate {
    match phy {
        Phy::M1 => Datarate::_1mbit,
        Phy::M2 => Datarate::_2mbit,
        #[cfg(feature = "coded-phy")]
        Phy::CodedS8 | Phy::CodedS2 => Datarate::_125kbps,
    }
}

/// Disables PPI `channel` alone.
#[inline]
pub fn disable_channel(channel: usize) { PPI.chenclr().write(|w| w.set_ch(channel, true)); }

/// The fast ramp-up of 40 us instead of 140 us.
#[inline]
pub fn fast_ramp_up() { RADIO.modecnf0().write(|w| w.set_ru(Ru::Fast)); }

/// Applies the fix for anomaly 182, which covers anomalies 102, 106 and 107,
/// after the radio was powered, on the chip it concerns: the nRF52832, not
/// the nRF52833 ([`variant::ANOMALY_182`]).
#[inline]
pub fn radio_trim() {
    let Some((address, bit)) = variant::ANOMALY_182 else { return };
    let register = with_exposed_provenance_mut::<u32>(address);
    // SAFETY: the anomaly 182 register is a word-aligned RADIO register.
    let value = unsafe { read_volatile(register) };
    // SAFETY: Nordic documents this write for the anomaly 182 fix.
    unsafe { write_volatile(register, value | bit) }
}

/// Gives the radio and the CCM the highest priority on every RAM block, as
/// Zephyr does on the nRF52832 and the nRF52833 (`hal_radio_ram_prio_setup`
/// in `radio_nrf52832.h` and `radio_nrf52833.h`, the same AMLI registers and
/// values on both). The CCM decrypts a packet while the radio writes it to
/// RAM; a radio write that waits behind the CPU or another DMA master, such
/// as SPIM, SAADC or PWM, lets the CCM read stale bytes and fail a packet
/// with a valid CRC on its MIC. All other masters keep their reset priority.
#[inline]
pub fn ram_priority() {
    for register in [AMLI_RAMPRI_RADIO, AMLI_RAMPRI_CCM] {
        // SAFETY: the AMLI RAM priority registers of the radio and the CCM,
        // word-aligned, with one priority field per RAM block; 0 is the
        // highest.
        unsafe { write_volatile(with_exposed_provenance_mut::<u32>(register), 0) }
    }
}

/// Accuracy of the low frequency clock in ppm: the RC oscillator, which
/// [`crate::clock::calibrate_rc`] keeps calibrated.
#[inline]
pub const fn sleep_clock_ppm() -> u32 { RC_PPM }

/// The die temperature in units of 0.25 °C, once a measurement is ready.
#[inline]
pub fn read_temperature() -> i32 { TEMP.temp().read().cast_signed() }

/// Delay of the receive chain in ns on `phy`, from the last bit on air to
/// the radio's END event: the chip's ([`variant::rx_chain_ns`]).
#[inline]
#[must_use = "the delay is only computed"]
pub const fn rx_chain_ns(phy: Phy) -> u32 { variant::rx_chain_ns(phy) }

/// Makes PPI `channel` disable `group` on its event, with the channel alone
/// in the group: enabling the group arms the channel for one event.
#[inline]
pub fn self_disabling(channel: usize, group: usize) {
    PPI.chg(group).write(|w| w.set_ch(channel, true));
    PPI.fork(channel).tep().write_value(PPI.tasks_chg(group).dis().as_ptr().addr().strict_cast());
}

/// Sets the workaround for anomaly 192 while an RC calibration may run, and
/// clears it after, on the chip it concerns: the nRF52832, not the nRF52833
/// ([`variant::ANOMALY_192`]).
pub fn set_calibration_workaround(calibrating: bool) {
    let Some(address) = variant::ANOMALY_192 else { return };
    let register = with_exposed_provenance_mut::<u32>(address);
    // SAFETY: Nordic documents these writes for the anomaly 192 workaround.
    unsafe { write_volatile(register, if calibrating { 2 } else { 0 }) }
}

/// The most octets the radio writes to RAM for a packet received with the
/// packet layout of [`set_packet_layout`]: S0, length, the S1 byte on the
/// data channels, and as many octets as MAXLEN admits.
#[inline]
#[must_use = "the length is only computed"]
pub const fn packet_ram_len(data_channel: bool) -> usize {
    let s1: usize = if data_channel { 1 } else { 0 };
    2_usize.strict_add(s1).strict_add(MAX_PAYLOAD.strict_cast())
}

/// Sets whether packets in RAM carry the S1 byte, which the CCM needs on
/// data channels.
#[inline]
pub fn set_packet_layout(data_channel: bool) {
    // Data PDUs carry up to 251 payload octets and the four-byte MIC
    // with the data length extension, as advertising PDUs fit 255 too:
    // the radio receives and sends whole packets of either.
    RADIO.pcnf1().modify(|w| w.set_maxlen(MAX_PAYLOAD));
    RADIO.pcnf0().modify(|w| {
        w.set_lflen(LENGTH_BITS);
        w.set_s0len(true);
        w.set_s1len(0);
        w.set_s1incl(if data_channel { S1incl::Include } else { S1incl::Automatic });
    });
}

/// Sets the radio mode and preamble of `phy`. The radio must be disabled.
#[cfg_attr(
    feature = "coded-phy",
    doc = "",
    doc = "LE Coded sends with S=8 in `Ble_LR125Kbit` and with S=2 in `Ble_LR500Kbit`, and receives either coding in \
           both (\"Long range 125 kbps TX, 125 kbps and 500 kbps RX\" in the PAC), with the long range preamble, a \
           coding indicator of two bits and a TERM field of three, the values of Zephyr's `radio_pkt_configure` \
           (`CILEN` 2, `TERMLEN` 3). LE 1M and LE 2M clear `CILEN` and `TERMLEN`."
)]
#[inline]
pub fn set_phy(phy: Phy) {
    RADIO.mode().write(|w| {
        w.set_mode(match phy {
            Phy::M1 => Mode::Ble1mbit,
            Phy::M2 => Mode::Ble2mbit,
            #[cfg(feature = "coded-phy")]
            Phy::CodedS8 => Mode::BleLr125kbit,
            #[cfg(feature = "coded-phy")]
            Phy::CodedS2 => Mode::BleLr500kbit,
        });
    });
    RADIO.pcnf0().modify(|w| {
        w.set_plen(match phy {
            Phy::M1 => Plen::_8bit,
            Phy::M2 => Plen::_16bit,
            #[cfg(feature = "coded-phy")]
            Phy::CodedS8 | Phy::CodedS2 => Plen::LongRange,
        });
        #[cfg(feature = "coded-phy")]
        {
            let (indicator, term) = if phy.is_coded() { (CODED_CILEN, CODED_TERMLEN) } else { (0, 0) };
            w.set_cilen(indicator);
            w.set_termlen(term);
        }
    });
}

/// Sets the radio's interframe space to `us`, in the chip's TIFS register
/// ([`variant::set_tifs`]).
#[inline]
pub fn set_tifs(us: u8) { variant::set_tifs(us); }

/// Time in ns from TXEN until the first bit of the packet is on air on
/// `phy`, with the fast ramp-up: the chip's ([`variant::tx_ready_ns`]).
#[inline]
#[must_use = "the time is only computed"]
pub const fn tx_ready_ns(phy: Phy) -> u32 { variant::tx_ready_ns(phy) }

/// The transmit power setting of `dbm`, one of the levels the radio
/// supports: the register takes the level in dBm.
#[inline]
pub const fn txpower(dbm: i8) -> Txpower { Txpower::from_bits(dbm.cast_unsigned()) }
