//! BLE 1 Mbit radio driver.

/// The turnaround timing: the radio's own on the nRF51.
#[cfg(feature = "nrf51")]
#[path = "radio/switch_tifs.rs"]
mod switch;
/// The turnaround timing: TIMER1 on the nRF52832 and the nRF52833.
#[cfg(feature = "_nrf52")]
#[path = "radio/switch_timer.rs"]
mod switch;
/// The tests of the PHYs.
#[cfg(test)]
#[path = "radio/tests.rs"]
mod tests;

#[cfg(feature = "_nrf52")] use crate::crypto;
use crate::{chip, pdu::BUFFER_LEN, sleep};
use core::sync::atomic::{Ordering, compiler_fence};
use embassy_nrf::{
    Peri,
    interrupt::{self, InterruptExt as _},
    pac::{
        RADIO as REGS,
        radio::{
            regs::Int,
            vals::{Crcstatus, Endian, Len, Mode, Skipaddr, State, Txpower},
        },
    },
    peripherals::{RADIO, RNG},
};
#[cfg(feature = "coded-phy")]
use embassy_nrf::{pac::PPI, peripherals::PPI_CH18};
#[cfg(feature = "_nrf52")]
use embassy_nrf::{
    peripherals::{PPI_CH4, PPI_CH5, PPI_CH25, TIMER1},
    ppi::Channel as _,
};
/// The PPI channels of the turnaround, for [`crate::PPI_CHANNELS`].
#[cfg(feature = "_nrf52")]
pub(crate) use switch::{PPI_SWITCH_ENABLE, PPI_SWITCH_START};

/// Time on air of the part of an LE Coded packet always sent with S=8.
///
/// It is the preamble (80 us), access address (256 us), coding indicator
/// (16 us) and TERM1 (24 us) (Core, Vol 6, Part B, 2.2; Zephyr's
/// `CODED_PHY_*_TIME_US` in `pdu.h`).
#[cfg(feature = "coded-phy")]
pub const CODED_ADDRESS_US: u32 = 376;
/// Base address length in bytes.
const BASE_ADDRESS_LEN: u8 = 3;
/// BLE CRC polynomial x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1.
const CRC_POLY: u32 = 0x0000_065B;
/// Interframe space in microseconds.
const IFS_US: u8 = 150;
/// Length field size in bits.
pub(crate) const LENGTH_BITS: u8 = 8;
/// Receiver ready time after RXEN: 40 us with the fast ramp-up of the
/// nRF52832 and the nRF52833, about 140 us on the nRF51.
pub const RX_READY_US: u32 = chip::RX_READY_US;
/// Whether the answer within the interframe space sets the next turnaround.
///
/// It does so right after its packet pointer with the nRF51's own
/// turnaround; with TIMER1 on the nRF52 chips the exchange sets it once the
/// answer started.
pub const TURNAROUND_IN_ANSWER: bool = switch::SET_IN_ANSWER;
/// Time by which the receiver is ready before the earliest packet start one
/// interframe space after our packet: the peer may be 2 us early, and the
/// receiver locks onto the preamble before the access address.
#[cfg(feature = "_nrf52")]
const RX_EARLY_US: u32 = 8;
/// Whitening initial value bit that the radio requires to be set.
const WHITENING_BIT6: u8 = 0x40;

/// A buffer of `N` octets the radio may receive into.
///
/// Every buffer the radio points at while a reception may start is one
/// ([`Radio::prepare`], [`Radio::set_buffer`], [`Radio::rearm_receive`]),
/// and the radio takes it only if it holds the longest packet the current
/// packet layout lets the radio write ([`Radio::set_s1_included`]): a
/// reception stays inside it whatever arrives, and whenever the hardware
/// starts it. Only [`Radio::prepare_send`] and [`Radio::set_send_buffer`]
/// take a shorter PDU, for a transmission no reception can follow. Word
/// aligned, so that its copies move words.
#[derive(Clone, Copy)]
#[non_exhaustive]
#[repr(C, align(4))]
pub struct Buffer<const N: usize>(pub [u8; N]);

impl<const N: usize> Buffer<N> {
    /// A buffer of zeros.
    pub const ZERO: Self = Self([0; N]);
}

/// The packet buffer of the data channels and of legacy advertising,
/// [`BUFFER_LEN`] octets.
pub type PacketBuffer = Buffer<BUFFER_LEN>;

/// Physical layer of a connection.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Phy {
    /// LE Coded with S=2: 500 kbit/s after the same S=8 part as
    /// [`Self::CodedS8`], twice the airtime of LE 1M for the header,
    /// payload and CRC. Only a transmit PHY.
    #[cfg(feature = "coded-phy")]
    CodedS2,
    /// LE Coded with S=8: 125 kbit/s, eight times the airtime of LE 1M for
    /// the header, payload and CRC, after a preamble, access address,
    /// coding indicator and TERM1 always sent with S=8. As a receive PHY it
    /// stands for LE Coded with either coding: the radio decodes both, by
    /// the coding indicator of each packet.
    #[cfg(feature = "coded-phy")]
    CodedS8,
    /// LE 1M: 1 Mbit/s, 8-bit preamble.
    M1,
    /// LE 2M: 2 Mbit/s, 16-bit preamble, half the airtime.
    M2,
}

/// The coding of the packets this side sends on LE Coded: S=8 for the
/// longest range, S=2 for a quarter of the airtime of the header, payload
/// and CRC.
#[cfg(feature = "coded-phy")]
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Coding {
    /// S=2, 500 kbit/s.
    S2,
    /// S=8, 125 kbit/s.
    S8,
}

impl Phy {
    /// Time from the start of a packet to its access address event: 8
    /// preamble and 32 address bits at 1 Mbit/s, 16 and 32 at 2 Mbit/s,
    /// and on LE Coded the 80 us preamble, the 256 us access address, the
    /// 16 us coding indicator and the 24 us TERM1, 376 us, after which the
    /// radio knows the packet's coding. The time of LE Coded is Zephyr's
    /// (`addr_us_get` in `lll_tim_internal.h`: `case BIT(2): return 376;`).
    #[inline]
    #[must_use = "the time is only computed"]
    pub const fn address_offset_us(self) -> u32 {
        match self {
            Self::M1 => 40,
            Self::M2 => 24,
            #[cfg(feature = "coded-phy")]
            Self::CodedS8 | Self::CodedS2 => CODED_ADDRESS_US,
        }
    }

    /// The bit of the PHY in a link layer PHY bit field: bit 0 for LE 1M,
    /// bit 1 for LE 2M and bit 2 for LE Coded with either coding.
    #[inline]
    #[must_use = "the bit is only computed"]
    pub const fn bit(self) -> u8 {
        match self {
            Self::M1 => 1,
            Self::M2 => 2,
            #[cfg(feature = "coded-phy")]
            Self::CodedS8 | Self::CodedS2 => 4,
        }
    }

    /// LE Coded with `coding`.
    #[cfg(feature = "coded-phy")]
    #[inline]
    #[must_use = "the PHY is only built"]
    pub const fn coded(coding: Coding) -> Self {
        match coding {
            Coding::S8 => Self::CodedS8,
            Coding::S2 => Self::CodedS2,
        }
    }

    /// The PHY of a link layer PHY bit field with exactly one of 1M, 2M and
    /// LE Coded, if the radio has it: the nRF51 has LE 1M alone, and only
    /// the nRF52833 with the feature `coded-phy` has LE Coded, which decodes
    /// as [`Self::CodedS8`], the PHY the radio receives LE Coded in.
    #[inline]
    #[must_use = "the PHY is only decoded"]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::M1),
            2 if chip::PHY_2M => Some(Self::M2),
            #[cfg(feature = "coded-phy")]
            4 => Some(Self::CodedS8),
            _ => None,
        }
    }

    /// The PHY of the power control procedures' PHY value (Core, Vol 6,
    /// Part B, 2.4.2.31): 1 for LE 1M, 2 for LE 2M, and with the feature
    /// `coded-phy` 3 for LE Coded with S=8 and 4 with S=2, if the radio has
    /// it.
    #[inline]
    #[must_use = "the PHY is only decoded"]
    pub const fn from_power(value: u8) -> Option<Self> {
        match value {
            #[cfg(feature = "coded-phy")]
            3 => Some(Self::CodedS8),
            #[cfg(feature = "coded-phy")]
            4 => Some(Self::CodedS2),
            _ => Self::from_bits(value),
        }
    }

    /// The HCI value of the PHY: 1 for LE 1M, 2 for LE 2M and 3 for LE
    /// Coded with either coding.
    #[inline]
    #[must_use = "the value is only computed"]
    pub const fn hci(self) -> u8 {
        match self {
            Self::M1 => 1,
            Self::M2 => 2,
            #[cfg(feature = "coded-phy")]
            Self::CodedS8 | Self::CodedS2 => 3,
        }
    }

    /// Whether the PHY is LE Coded.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_coded(self) -> bool {
        match self {
            Self::M1 | Self::M2 => false,
            #[cfg(feature = "coded-phy")]
            Self::CodedS8 | Self::CodedS2 => true,
        }
    }

    /// TIMER RXEN offset from the END of our packet sent on this PHY, so the
    /// receiver is ready shortly before a packet one interframe space later.
    /// The fast ramp-up and TX chain timings follow Zephyr's Nordic HAL.
    #[cfg_attr(
        feature = "coded-phy",
        doc = "",
        doc = "On LE Coded the nRF52833's receiver is ready after 40.3 us with the fast ramp-up and its transmit \
               chain takes 0.6 us, as on LE 1M (`HAL_RADIO_NRF52833_RXEN_RXIDLE_RX_S8_FAST_NS` and `_S2_FAST_NS` \
               40300, `HAL_RADIO_NRF52833_TX_CHAIN_DELAY_S8_NS` and `_S2_NS` 600), so the offset is the same."
    )]
    #[cfg(feature = "_nrf52")]
    #[must_use = "the delay is only computed"]
    #[inline]
    pub const fn listen_offset_us(self) -> u32 {
        let rx_ready_ns = RX_READY_US.saturating_mul(1000);
        let delay = rx_ready_ns.saturating_add(chip::TX_CHAIN_NS).div_ceil(1000);
        150_u32.saturating_sub(delay).saturating_sub(RX_EARLY_US)
    }

    /// The most PDU octets, header, payload and MIC, a packet on LE Coded
    /// with this coding carries within `us` microseconds on the air: the
    /// inverse of [`Self::pdu_us`], 33 octets in 2704 us with S=8.
    #[cfg(feature = "coded-phy")]
    #[inline]
    #[must_use = "the length is only computed"]
    pub const fn pdu_octets_within(self, us: u32) -> u32 {
        let us_per_bit: u32 = if matches!(self, Self::CodedS2) { 2 } else { 8 };
        us.saturating_sub(CODED_ADDRESS_US).strict_div(us_per_bit).saturating_sub(27).strict_div(8)
    }

    /// Time on air of a packet whose PDU, header, payload and MIC, holds
    /// `pdu_octets` octets: preamble, access address, PDU and CRC at 8 us
    /// an octet on LE 1M and 4 us on LE 2M, whose preamble is two octets;
    /// on LE Coded the 376 us of preamble, access address, coding indicator
    /// and TERM1, then the PDU, the CRC and the three bits of TERM2 at 8 us
    /// a bit with S=8 and 2 us with S=2 (Core, Vol 6, Part B, 2.2; Zephyr's
    /// `PDU_US` in `pdu.h`). An empty PDU takes 80 us on LE 1M and 720 us
    /// with S=8; 27 octets with a MIC take 328 us on LE 1M, 2704 us with
    /// S=8 and 958 us with S=2.
    #[inline]
    #[must_use = "the time is only computed"]
    pub const fn pdu_us(self, pdu_octets: usize) -> u32 {
        let octets: u32 = pdu_octets.saturating_cast();
        match self {
            Self::M1 => octets.saturating_add(8).saturating_mul(8),
            Self::M2 => octets.saturating_add(9).saturating_mul(4),
            #[cfg(feature = "coded-phy")]
            Self::CodedS8 => coded_block2_bits(octets).saturating_mul(8).saturating_add(CODED_ADDRESS_US),
            #[cfg(feature = "coded-phy")]
            Self::CodedS2 => coded_block2_bits(octets).saturating_mul(2).saturating_add(CODED_ADDRESS_US),
        }
    }

    /// The bit of the PHY in the PHY bit field of `LL_POWER_CHANGE_IND` and
    /// of the power reports a central asks for (Core, Vol 6, Part B,
    /// 2.4.2.33): bit 0 for LE 1M, bit 1 for LE 2M, bit 2 for LE Coded with
    /// S=8 and bit 3 with S=2.
    #[inline]
    #[must_use = "the bit is only computed"]
    pub const fn power_bit(self) -> u8 {
        match self {
            Self::M1 => 1,
            Self::M2 => 2,
            #[cfg(feature = "coded-phy")]
            Self::CodedS8 => 4,
            #[cfg(feature = "coded-phy")]
            Self::CodedS2 => 8,
        }
    }

    /// TIMER TXEN offset from RX END for a 150-us interframe space: the
    /// chip's fast ramp-up and RX chain timings of Zephyr's Nordic HAL,
    /// rounded to the microsecond.
    #[cfg_attr(
        feature = "coded-phy",
        doc = "",
        doc = "A packet received on LE Coded is `receive` [`Self::CodedS8`] or [`Self::CodedS2`] by the coding it \
               came with ([`Radio::received`]): the receive chain takes 29.6 us with S=8 and 24.6 us with S=2."
    )]
    #[cfg(feature = "_nrf52")]
    #[must_use = "the delay is only computed"]
    #[inline]
    pub const fn response_offset_us(self, receive: Self) -> u32 {
        let delay =
            chip::tx_ready_ns(self).saturating_add(chip::rx_chain_ns(receive)).saturating_add(500).strict_div(1000);
        150_u32.saturating_sub(delay)
    }

    /// The PHY with `coding` if it is LE Coded, otherwise itself: a
    /// transmit PHY with this side's coding.
    #[cfg(feature = "coded-phy")]
    #[inline]
    #[must_use = "the PHY is only built"]
    pub const fn with_coding(self, coding: Coding) -> Self { if self.is_coded() { Self::coded(coding) } else { self } }
}

/// What the radio does after a packet.
///
/// On the nRF52832 and the nRF52833 a turnaround is timed by TIMER1,
/// which PPI starts at the packet END, and whose compare enables the radio
/// one interframe space after the packet, as Zephyr's software switch does:
/// the radio's own interframe timing works only with the slow ramp-up. The
/// nRF51 has only that ramp-up and uses the radio's own timing.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Turnaround {
    /// Disables after the packet.
    None,
    /// Starts receiving one interframe space after the packet.
    Receive,
    /// Starts sending one interframe space after the packet.
    Transmit,
}

/// The PPI channels of a [`Radio`] on the nRF52832 and the nRF52833, which
/// it owns for its lifetime.
///
/// They are the programmable channels 4 and 5 of the turnaround, and the
/// fixed channel 25, from the access address to the CCM's decryption; with
/// the feature `coded-phy` also the programmable channel 18, from the
/// radio's RATEBOOST to the CCM's RATEOVERRIDE.
/// [`crate::PPI_CHANNELS`] holds every channel of the link layer.
#[cfg(feature = "_nrf52")]
pub struct Ppi<'peripherals> {
    /// Fixed channel 25: RADIO ADDRESS to CCM CRYPT.
    _crypt:         Peri<'peripherals, PPI_CH25>,
    /// Channel 18: RADIO RATEBOOST to CCM RATEOVERRIDE.
    #[cfg(feature = "coded-phy")]
    _rate:          Peri<'peripherals, PPI_CH18>,
    /// Channel 5: TIMER1 COMPARE0 to RADIO TXEN or RXEN.
    _switch_enable: Peri<'peripherals, PPI_CH5>,
    /// Channel 4: RADIO END to TIMER1 START.
    _switch_start:  Peri<'peripherals, PPI_CH4>,
}

#[cfg(feature = "_nrf52")]
impl<'peripherals> Ppi<'peripherals> {
    /// Takes the channels 4, 5 and 25, and with the feature `coded-phy`
    /// channel 18.
    #[inline]
    #[must_use = "the channels are only claimed while the radio holds them"]
    pub fn new(
        switch_start: Peri<'peripherals, PPI_CH4>,
        switch_enable: Peri<'peripherals, PPI_CH5>,
        crypt: Peri<'peripherals, PPI_CH25>,
        #[cfg(feature = "coded-phy")] rate: Peri<'peripherals, PPI_CH18>,
    ) -> Self {
        debug_assert_eq!(
            [switch_start.number(), switch_enable.number(), crypt.number()],
            [PPI_SWITCH_START, PPI_SWITCH_ENABLE, crypto::PPI_CRYPT],
            "a PPI channel of the radio is not its token"
        );
        #[cfg(feature = "coded-phy")]
        debug_assert_eq!(rate.number(), crypto::PPI_RATE, "the rate channel of the radio is not its token");
        Self {
            _crypt: crypt,
            #[cfg(feature = "coded-phy")]
            _rate: rate,
            _switch_enable: switch_enable,
            _switch_start: switch_start,
        }
    }
}

/// The radio, configured for BLE, with fast ramp-up on the nRF52832 and the
/// nRF52833.
pub struct Radio<'peripherals> {
    /// The radio peripheral, owned for the lifetime of the driver.
    _peripheral: Peri<'peripherals, RADIO>,
    /// The PPI channels, owned for the lifetime of the driver.
    #[cfg(feature = "_nrf52")]
    _ppi:        Ppi<'peripherals>,
    /// The random number generator, which [`crate::rng`] drives for the
    /// link layer and the host, owned for the lifetime of the driver.
    _rng:        Peri<'peripherals, RNG>,
    /// The timer of the turnarounds, owned for the lifetime of the driver.
    #[cfg(feature = "_nrf52")]
    _switch:     Peri<'peripherals, TIMER1>,
    /// The most octets the current packet layout lets the radio write to
    /// RAM for a reception.
    longest:     usize,
    /// PHY the turnarounds are timed for.
    #[cfg(feature = "_nrf52")]
    phy:         Phy,
    /// Size of the buffer the radio points at, 0 for a PDU only to send or
    /// once the radio is disabled.
    pointed:     usize,
}

impl<'peripherals> Radio<'peripherals> {
    /// Panics unless the radio points at a buffer that takes the longest
    /// packet the layout lets it write, before a reception may start.
    pub(crate) fn check_receivable(&self) {
        assert!(self.pointed >= self.longest, "a reception into a buffer too short for it");
    }

    /// Clears the access address event.
    #[inline]
    pub fn clear_address(&mut self) { REGS.events_address().write_value(0); }

    /// Sets `turnaround` and clears the events of the packet before.
    fn clear_for(&mut self, turnaround: Turnaround) {
        self.set_turnaround(turnaround);
        REGS.events_address().write_value(0);
        REGS.events_end().write_value(0);
        REGS.events_disabled().write_value(0);
        REGS.events_rssiend().write_value(0);
        #[cfg(feature = "coded-phy")]
        REGS.events_rateboost().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Clears the ready event, so that [`Self::tx_started`] tells of the
    /// next ramp-up only.
    #[inline]
    pub fn clear_ready(&mut self) {
        REGS.events_ready().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Whether the last received packet had a valid CRC.
    #[inline]
    #[must_use = "the CRC status is only read"]
    pub fn crc_ok(&self) -> bool { REGS.crcstatus().read().crcstatus() == Crcstatus::CrcOk }

    /// Stops sending or receiving and waits until the radio is disabled.
    /// The radio then points at no buffer a reception may take, until it is
    /// given one again.
    #[inline]
    pub fn disable(&mut self) {
        // The turnaround goes first: on the nRF51 the disabled event that
        // follows would otherwise enable the radio again through the
        // shortcut, and send.
        self.set_turnaround(Turnaround::None);
        if REGS.state().read().state() != State::Disabled {
            REGS.events_disabled().write_value(0);
            REGS.tasks_disable().write_value(1);
            Self::sleep_on(|w| w.set_disabled(true), || self.is_disabled());
        }
        REGS.events_disabled().write_value(0);
        // Not in `wait_disabled` or `wait_stopped`: on the nRF52 chips a
        // turnaround to receive enables the radio again after it was
        // disabled.
        self.pointed = 0;
        compiler_fence(Ordering::SeqCst);
    }

    /// Whether an access address was received or sent since the last start.
    #[inline]
    #[must_use = "the event is only read"]
    pub fn has_address(&self) -> bool { REGS.events_address().read() != 0 }

    /// Whether the radio became disabled since the last start.
    #[inline]
    #[must_use = "the event is only read"]
    pub fn is_disabled(&self) -> bool { REGS.events_disabled().read() != 0 }

    /// Whether a packet ended since the last start.
    #[inline]
    #[must_use = "the event is only read"]
    pub fn is_end(&self) -> bool { REGS.events_end().read() != 0 }

    /// Powers the radio and configures it for BLE 1 Mbit: on the nRF52832 and
    /// the nRF52833 with the fast ramp-up and TIMER1 timing the turnarounds
    /// through the channels of `ppi`, on the nRF51 with the radio's own
    /// interframe timing and the radio trim values of FICR. The high frequency
    /// crystal must be running. Takes the RNG, which [`crate::rng`] drives, so
    /// that no other driver can.
    #[inline]
    #[must_use = "the radio is unusable once dropped"]
    pub fn new(
        radio: Peri<'peripherals, RADIO>,
        #[cfg(feature = "_nrf52")] switch: Peri<'peripherals, TIMER1>,
        #[cfg(feature = "_nrf52")] ppi: Ppi<'peripherals>,
        rng: Peri<'peripherals, RNG>,
    ) -> Self {
        sleep::enable();
        REGS.power().write(|w| w.set_power(true));
        chip::radio_trim();
        chip::ram_priority();
        REGS.mode().write(|w| w.set_mode(Mode::Ble1mbit));
        chip::fast_ramp_up();
        chip::set_tifs(IFS_US);
        switch::init();
        #[cfg(feature = "coded-phy")]
        PPI.ch(crypto::PPI_RATE).eep().write_value(REGS.events_rateboost().as_ptr().addr().strict_cast());
        #[cfg(feature = "coded-phy")]
        PPI.ch(crypto::PPI_RATE).tep().write_value(crypto::rate_override_task());
        REGS.pcnf0().write(|w| {
            w.set_lflen(LENGTH_BITS);
            w.set_s0len(true);
            w.set_s1len(0);
        });
        REGS.pcnf1().write(|w| {
            w.set_maxlen(chip::ADV_MAXLEN);
            w.set_statlen(0);
            w.set_balen(BASE_ADDRESS_LEN);
            w.set_endian(Endian::Little);
            w.set_whiteen(true);
        });
        REGS.crccnf().write(|w| {
            w.set_len(Len::Three);
            w.set_skipaddr(Skipaddr::Skip);
        });
        REGS.crcpoly().write(|w| w.set_crcpoly(CRC_POLY));
        REGS.txaddress().write(|w| w.set_txaddress(0));
        REGS.rxaddresses().write(|w| w.set_addr0(true));
        REGS.txpower().write(|w| w.set_txpower(Txpower::_0dBm));
        Self {
            _peripheral: radio,
            #[cfg(feature = "_nrf52")]
            _ppi: ppi,
            _rng: rng,
            #[cfg(feature = "_nrf52")]
            _switch: switch,
            longest: chip::packet_ram_len(false),
            #[cfg(feature = "_nrf52")]
            phy: Phy::M1,
            pointed: 0,
        }
    }

    /// Clears the events and arms the radio for a packet started by a task
    /// or a PPI channel, from or into `buffer`, with `turnaround` after it.
    ///
    /// # Safety
    ///
    /// As for [`Self::set_buffer`].
    #[inline]
    pub unsafe fn prepare<const N: usize>(&mut self, buffer: &mut Buffer<N>, turnaround: Turnaround) {
        // SAFETY: the caller upholds the contract of `set_buffer`.
        unsafe { self.set_buffer(buffer) }
        self.clear_for(turnaround);
    }

    /// Clears the events and arms the radio to send `pdu`, started by a task
    /// or a PPI channel, with nothing after it.
    ///
    /// # Safety
    ///
    /// As for [`Self::set_send_buffer`].
    #[inline]
    pub unsafe fn prepare_send(&mut self, pdu: &[u8]) {
        // SAFETY: the caller upholds the contract of `set_send_buffer`, and
        // no turnaround follows the transmission.
        unsafe { self.set_send_buffer(pdu) }
        self.clear_for(Turnaround::None);
    }

    /// Points the radio at `buffer` for the reception that the shortcut after
    /// the current transmission starts, and clears that transmission's
    /// address, end and signal strength events. Call it once the
    /// transmission ended, before the reception starts.
    ///
    /// # Safety
    ///
    /// As for [`Self::set_buffer`].
    #[inline]
    pub unsafe fn rearm_receive<const N: usize>(&mut self, buffer: &mut Buffer<N>) {
        // SAFETY: the caller upholds the contract of `set_buffer`.
        unsafe { self.set_buffer(buffer) }
        REGS.events_address().write_value(0);
        REGS.events_end().write_value(0);
        REGS.events_rssiend().write_value(0);
        #[cfg(feature = "coded-phy")]
        REGS.events_rateboost().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Starts receiving now.
    ///
    /// # Panics
    ///
    /// If the radio points at a buffer too short for the packet layout
    /// ([`Buffer`]).
    #[inline]
    pub fn receive(&mut self) {
        self.check_receivable();
        REGS.tasks_rxen().write_value(1);
    }

    /// The PHY the last packet received on `phy` came with: on LE Coded
    /// [`Phy::CodedS2`] if the radio switched to S=2 at its coding indicator
    /// (its RATEBOOST event, "`Ble_LR` CI field received, receive mode is
    /// changed from `Ble_LR125Kbit` to `Ble_LR500Kbit`" in the PAC), otherwise
    /// [`Phy::CodedS8`]; `phy` itself on LE 1M and LE 2M. Zephyr reads the
    /// same event (`radio_phy_flags_rx_get` in `radio.c`).
    #[cfg(feature = "coded-phy")]
    #[inline]
    #[must_use = "the PHY is only read"]
    pub fn received(&self, phy: Phy) -> Phy {
        if !phy.is_coded() {
            return phy;
        }
        if REGS.events_rateboost().read() != 0 { Phy::CodedS2 } else { Phy::CodedS8 }
    }

    /// The packet layout, interframe space and whitening as the radio holds
    /// them: PCNF0, PCNF1, TIFS and DATAWHITEIV, for the log.
    #[inline]
    #[must_use = "the registers are only read"]
    pub fn registers(&self) -> [u32; 4] {
        [REGS.pcnf0().read().0, REGS.pcnf1().read().0, REGS.tifs().read().0, REGS.datawhiteiv().read().0]
    }

    /// Received signal strength of the last packet in -dBm, measured when
    /// its access address arrived.
    #[inline]
    #[must_use = "the signal strength is only read"]
    pub fn rssi(&self) -> Option<u8> {
        (REGS.events_rssiend().read() != 0).then(|| REGS.rssisample().read().rssisample())
    }

    /// Sets the access address of the following packets.
    #[inline]
    pub fn set_access_address(&mut self, address: u32) {
        REGS.base0().write_value(address.wrapping_shl(8));
        REGS.prefix0().write(|w| w.set_ap0(address.wrapping_shr(24).truncate()));
    }

    /// Sets the packet buffer the radio sends from or receives into by DMA,
    /// at the next packet's start. A reception, whatever arrives and
    /// whenever it starts, stays inside `buffer`.
    ///
    /// # Panics
    ///
    /// If `buffer` is shorter than the longest packet the packet layout lets
    /// the radio write ([`Self::set_s1_included`]).
    ///
    /// # Safety
    ///
    /// The radio keeps the address: `buffer` must stay valid until the radio
    /// is disabled or given another buffer, and the CPU must not access it
    /// meanwhile while the radio may, but for the one header byte of an
    /// answer it patches before the answer starts.
    #[inline]
    pub unsafe fn set_buffer<const N: usize>(&mut self, buffer: &mut Buffer<N>) {
        assert!(N >= self.longest, "a radio buffer shorter than the packets the layout admits");
        self.pointed = N;
        compiler_fence(Ordering::SeqCst);
        REGS.packetptr().write_value(buffer.0.as_mut_ptr().addr().strict_cast());
    }

    /// Tunes to a BLE channel index and sets the matching whitening.
    #[inline]
    pub fn set_channel(&mut self, channel: u8) {
        REGS.frequency().write(|w| w.set_frequency(frequency(channel)));
        REGS.datawhiteiv().write(|w| w.set_datawhiteiv(channel | WHITENING_BIT6));
    }

    /// Sets the CRC initial value of the following packets.
    #[inline]
    pub fn set_crc_init(&mut self, init: u32) { REGS.crcinit().write(|w| w.set_crcinit(init)); }

    /// Sets the PHY of the following packets: LE 1M, the only one on the
    /// nRF51. The radio must be disabled.
    #[cfg(feature = "nrf51")]
    #[inline]
    pub fn set_phy(&mut self, phy: Phy) { chip::set_phy(phy); }

    /// Sets the PHY of the following packets. The radio must be disabled.
    #[cfg(feature = "_nrf52")]
    #[inline]
    pub fn set_phy(&mut self, phy: Phy) {
        self.phy = phy;
        chip::set_phy(phy);
    }

    /// Sets the packet layout of the data channels, whose header in RAM
    /// carries the S1 byte the CCM needs, or of the advertising channels.
    #[inline]
    pub fn set_s1_included(&mut self, included: bool) {
        chip::set_packet_layout(included);
        self.longest = chip::packet_ram_len(included);
    }

    /// Sets `pdu` as the packet the radio sends next, a PDU shorter than a
    /// [`Buffer`], which the radio only reads.
    ///
    /// # Safety
    ///
    /// As for [`Self::set_buffer`], and no reception may start while the
    /// radio points at `pdu`, as it would overrun it: no turnaround to
    /// receive is armed, and a reception the last one started has latched
    /// its buffer, as its access address tells. `pdu` must hold the whole PDU
    /// its header announces.
    #[inline]
    pub unsafe fn set_send_buffer(&mut self, pdu: &[u8]) {
        self.pointed = 0;
        compiler_fence(Ordering::SeqCst);
        REGS.packetptr().write_value(pdu.as_ptr().addr().strict_cast());
    }

    /// Sets what the radio does after the current packet.
    ///
    /// # Panics
    ///
    /// For a reception, if the radio points at a buffer too short for the
    /// packet layout ([`Buffer`]).
    #[inline]
    pub fn set_turnaround(&mut self, turnaround: Turnaround) {
        if turnaround == Turnaround::Receive {
            self.check_receivable();
        }
        // TIMER1 is armed before the packet, whose coding sets the receive
        // chain's delay on LE Coded: an answer to such a packet is started
        // from TIMER0 once its coding is known.
        #[cfg(feature = "coded-phy")]
        debug_assert!(
            turnaround != Turnaround::Transmit || !self.phy.is_coded(),
            "a turnaround to send armed before a packet on LE Coded"
        );
        #[cfg(feature = "nrf51")]
        switch::arm(turnaround);
        #[cfg(feature = "_nrf52")]
        switch::arm(self, turnaround);
    }

    /// Sets the transmit power of the following packets in dBm, one of the
    /// levels the radio supports.
    #[inline]
    pub fn set_tx_power(&mut self, dbm: i8) { REGS.txpower().write(|w| w.set_txpower(chip::txpower(dbm))); }

    /// Sleeps until `ready` holds, woken by the radio events in `events`.
    fn sleep_on<Ready>(events: impl Fn(&mut Int), ready: Ready)
    where
        Ready: FnMut() -> bool,
    {
        REGS.intenset().write(&events);
        sleep::until(ready);
        REGS.intenclr().write(events);
        interrupt::RADIO.unpend();
    }

    /// The radio's state as the STATE register holds it, for the log.
    #[inline]
    #[must_use = "the state is only read"]
    pub fn state(&self) -> u8 { REGS.state().read().state().to_bits() }

    /// Starts sending now.
    #[inline]
    pub fn transmit(&mut self) { REGS.tasks_txen().write_value(1); }

    /// Whether a transmission ramped up since [`Self::clear_ready`]: its
    /// READY event, which starts it through the shortcut and so latches the
    /// packet pointer, or the radio sending already. Read after setting the
    /// buffer of an answer, it tells whether the answer came too late and
    /// the radio sends the buffer it pointed at before.
    #[inline]
    #[must_use = "the state is only read"]
    pub fn tx_started(&self) -> bool {
        compiler_fence(Ordering::SeqCst);
        REGS.events_ready().read() != 0 || matches!(REGS.state().read().state(), State::TxIdle | State::Tx)
    }

    /// Sleeps until an access address arrives or `expired` holds, which is
    /// checked on every wake: it must depend on an event that wakes the CPU,
    /// such as the deadline the clock arms on its TIMER0 compare. Returns
    /// whether the address arrived.
    #[inline]
    pub fn wait_address<Expired>(&mut self, mut expired: Expired) -> bool
    where
        Expired: FnMut() -> bool,
    {
        Self::sleep_on(|w| w.set_address(true), || self.has_address() || expired());
        self.has_address()
    }

    /// Sleeps until the radio is disabled and clears the event.
    #[inline]
    pub fn wait_disabled(&mut self) {
        Self::sleep_on(|w| w.set_disabled(true), || self.is_disabled());
        REGS.events_disabled().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Sleeps until a packet ends and clears the event.
    #[inline]
    pub fn wait_end(&mut self) {
        Self::sleep_on(|w| w.set_end(true), || self.is_end());
        REGS.events_end().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Sleeps until the radio is disabled after the packet under way, by its
    /// state rather than its disabled event, and clears the end and disabled
    /// events.
    ///
    /// Unlike [`Self::wait_end`] and [`Self::wait_disabled`] it returns also
    /// when that packet ended before and its events came and were cleared,
    /// as [`Self::wait_switched`] clears the disabled event on the nRF52 chips:
    /// an answer that has already gone out leaves the radio disabled, and no
    /// event follows.
    #[inline]
    pub fn wait_stopped(&mut self) {
        Self::sleep_on(|w| w.set_disabled(true), || REGS.state().read().state() == State::Disabled);
        REGS.events_end().write_value(0);
        REGS.events_disabled().write_value(0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Sleeps until the turnaround set before the last packet END enabled the
    /// radio again, and clears the disabled event of that packet. Set the
    /// next turnaround only after this, or it replaces the pending one.
    #[inline]
    pub fn wait_switched(&mut self) { switch::wait(); }

    /// Polls until the transmission the turnaround enabled has started and so
    /// latched its packet pointer ([`Self::tx_started`]), at most `polls`
    /// times. Returns whether it started.
    #[inline]
    #[must_use = "the pointer may only change once the transmission started"]
    pub fn wait_tx_started(&self, polls: u32) -> bool {
        let mut remaining = polls;
        while !self.tx_started() {
            if remaining == 0 {
                return false;
            }
            remaining = remaining.saturating_sub(1);
        }
        true
    }
}

/// Radio frequency offset from 2400 MHz of a BLE channel index.
const fn frequency(channel: u8) -> u8 {
    match channel {
        0..=10 => 4_u8.saturating_add(channel.saturating_mul(2)),
        11..=36 => 6_u8.saturating_add(channel.saturating_mul(2)),
        38 => 26,
        39 => 80,
        _ => 2,
    }
}

/// Bits of the second FEC block of an LE Coded packet whose PDU holds
/// `pdu_octets` octets: the PDU, the 24-bit CRC and the 3-bit TERM2.
#[cfg(feature = "coded-phy")]
const fn coded_block2_bits(pdu_octets: u32) -> u32 { pdu_octets.saturating_mul(8).saturating_add(27) }
