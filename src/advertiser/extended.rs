//! Extended advertising, connectable, undirected or directed.
//!
//! An `ADV_EXT_IND` on each enabled primary channel points to one
//! `AUX_ADV_IND` on a secondary channel, with the advertising data and no
//! scan response. A central connects with an `AUX_CONNECT_REQ` right after
//! it, which the `AUX_CONNECT_RSP` answers within the interframe space; the
//! connection then starts on the secondary channel's PHY with channel
//! selection algorithm 2. This module holds its types and data limits, the
//! renewal of the advertising set's ADI and secondary channel, its PDUs from
//! the settings, its event, and the event's timing, checked at compile time
//! for LE 1M and, on the nRF52 chips, LE 2M on the secondary channel, and
//! with the feature `coded-phy` LE Coded on the primary and the secondary
//! channels.
//!
//! # Timing
//!
//! Every packet of the event starts at an absolute time of the clock, and
//! the plan is in on-air start times: primary `k` of `n` starts
//! `k × PRIMARY_SPACING_US` after the first, and the `AUX_ADV_IND`
//! [`AUX_GAP_US`] after the last. Both are multiples of the `AuxPtr`'s 30 us
//! unit but for the gap's remainder, so the auxiliary packet starts the same
//! 12 us into the unit its offset names, seen from every primary
//! ([`aux_offset`]), whatever the PHY: the radio's ramp-up only moves the
//! TXEN of each packet ([`tx_ready_us`]), never its start on air.
//!
//! A packet whose TXEN is no longer [`MIN_LEAD_US`] ahead when the radio is
//! armed is skipped: a late primary costs that channel, while the others
//! keep their times and their pointers stay right; a late auxiliary packet
//! ends the event. The counters count both, and the connection requests
//! decided late: their answer's pointer came after the radio had started
//! the answer, or their check ended after the answer did
//! ([`decision_budget_us`]).

use super::{Accepted, CHANNELS, LISTEN_US, Settings, Setup};
use crate::{
    channel::{Hopping, UsedChannels},
    chip,
    clock::{At, Clock, Micros},
    pdu::{
        ADV_ACCESS_ADDRESS,
        ADV_CRC_INIT,
        AUX_CONNECT_RSP_LEN,
        AUX_DIRECTED_HEADER_LEN,
        AUX_HEADER_LEN,
        AUX_OFFSET_MAX,
        AUX_PAYLOAD_MAX,
        Adi,
        AuxAdvertisement,
        AuxConnectRsp,
        AuxPtr,
        CONNECT_IND_LEN,
        ConnectInd,
        EXT_PRIMARY_LEN,
        ExtPrimary,
        HEADER_LEN,
        Peer,
        aux_connect_initiator,
        aux_connect_rsp,
        aux_directed,
        aux_undirected,
        ext_primary,
        retarget,
    },
    radio::{self, Buffer, Phy, Radio, Turnaround},
};
use core::{
    array,
    sync::atomic::{AtomicU32, Ordering},
};

/// The shortest advertising interval, 20 ms, which an event has to fit in
/// (Core, Vol 6, Part B, 4.4.2.2.1).
const ADV_INTERVAL_MIN_US: u32 = 20_000;
/// Size of the buffer the `AUX_ADV_IND` goes out from and the request after
/// it comes into: the header and the largest payload the advertising
/// channels admit.
pub const AUX_BUFFER_LEN: usize = HEADER_LEN.strict_add(AUX_PAYLOAD_MAX);
/// Time from the start of the last primary packet on LE 1M to the start of
/// the auxiliary packet on air: at least `T_MAFS` after the primary's end,
/// and 12 us into a 30 us unit.
pub const AUX_GAP_US: u32 = 462;
/// Least CPU time between the radio's DISABLED after a packet and the TXEN
/// of the next.
///
/// On the 64 MHz Cortex-M4F the next packet's setup takes a few
/// microseconds.
#[cfg(feature = "_nrf52")]
pub const CPU_SLACK_MIN_US: u32 = 60;
/// Least CPU time between the radio's DISABLED after a packet and the TXEN
/// of the next.
///
/// On the 16 MHz Cortex-M0 the next packet's setup takes several times as
/// long as on the nRF52 chips.
#[cfg(feature = "nrf51")]
pub const CPU_SLACK_MIN_US: u32 = 100;
/// Largest advertising data: the largest payload the chip sends
/// ([`AUX_PAYLOAD_MAX`]) after the extended header of an undirected
/// `AUX_ADV_IND`, 245 octets on the nRF52 chips and 242 on the nRF51.
pub const DATA_MAX: usize = AUX_PAYLOAD_MAX.strict_sub(AUX_HEADER_LEN);
/// Largest advertising data of directed advertising, whose extended header
/// also holds the target: 239 octets on the nRF52 chips and 236 on the nRF51.
pub const DIRECTED_DATA_MAX: usize = AUX_PAYLOAD_MAX.strict_sub(AUX_DIRECTED_HEADER_LEN);
/// Time from the END of a sent packet until the radio is DISABLED.
pub const DISABLE_US: u32 = 6;
/// Time from the start of an event until the first TXEN: the PDUs are built
/// before, so this only covers arming the radio.
#[cfg(feature = "_nrf52")]
pub const EVENT_LEAD_US: u32 = 60;
/// Time from the start of an event until the first TXEN: the PDUs are built
/// before, so this only covers arming the radio.
#[cfg(feature = "nrf51")]
pub const EVENT_LEAD_US: u32 = 120;
/// The least time ahead a TXEN is armed for: a start closer than this may
/// pass before the compare is set, and the packet is skipped instead.
#[cfg(feature = "_nrf52")]
pub const MIN_LEAD_US: u32 = 5;
/// The least time ahead a TXEN is armed for: a start closer than this may
/// pass before the compare is set, and the packet is skipped instead.
#[cfg(feature = "nrf51")]
pub const MIN_LEAD_US: u32 = 10;
/// The initiator of the `AUX_CONNECT_RSP` until a request names it: no
/// device has this address, so an answer that goes out before the request
/// is known connects nobody.
const NOBODY: Peer = Peer::new([0; 6], false);
/// Time from the start of one primary packet to the next on air: nine
/// units of 30 us.
#[cfg(feature = "_nrf52")]
pub const PRIMARY_SPACING_US: u32 = 270;
/// Time from the start of one primary packet to the next on air: thirteen
/// units of 30 us, for the nRF51's 140 us ramp-up and slower CPU.
#[cfg(feature = "nrf51")]
pub const PRIMARY_SPACING_US: u32 = 390;
/// Airtime of an `ADV_EXT_IND`, on LE 1M: 136 us.
pub const PRIMARY_US: u32 = airtime_us(Phy::M1, EXT_PRIMARY_LEN);
/// Random octets a renewal of the advertising set takes ([`renew`]): the
/// advertising data ID and the secondary channel identifier.
pub const RENEWAL_LEN: usize = 4;
/// Largest scan response data: extended connectable advertising has none.
pub const SCAN_DATA_MAX: usize = 0;
/// The PHYs the secondary channel can use: LE 1M and LE 2M.
#[cfg(feature = "_nrf52")]
pub const SECONDARY_PHYS: [Phy; 2] = [Phy::M1, Phy::M2];
/// The PHYs the secondary channel can use: LE 1M, the nRF51's only one.
#[cfg(feature = "nrf51")]
pub const SECONDARY_PHYS: [Phy; 1] = [Phy::M1];
/// The interframe space.
const T_IFS_US: u32 = 150;
/// Connection requests decided late (see [`late_connect_decisions`]). Only
/// the link layer task writes it.
static LATE_CONNECT_DECISIONS: AtomicU32 = AtomicU32::new(0);
/// Packets skipped because their start was too close or past when the
/// radio was armed. Only the link layer task writes it.
static LATE_STARTS: AtomicU32 = AtomicU32::new(0);
/// Events between two samples of the timing log: every 1024th event logs
/// its timing.
#[cfg(feature = "defmt")]
const TIMING_SAMPLE_MASK: u16 = 0x03FF;
/// The minimum AUX frame space: from the end of a packet with an `AuxPtr` to
/// the start of its auxiliary packet (Core, Vol 6, Part B, 4.1.2).
pub const T_MAFS_US: u32 = 300;
/// The unit of the Aux Offset, Offset Units 0 (Core, Vol 6, Part B,
/// 2.3.4.5).
pub const UNIT_US: u32 = 30;

// The timing plan for every number of channels and every secondary PHY.
const _: () = {
    assert!(PRIMARY_SPACING_US.strict_rem(UNIT_US) == 0, "the primary spacing is not whole units");
    assert!(PRIMARY_SPACING_US <= 10_000, "primaries more than 10 ms apart (Core, Vol 6, Part B, 4.4.2.7)");
    assert!(AUX_GAP_US.strict_sub(PRIMARY_US) >= T_MAFS_US, "the auxiliary packet starts within T_MAFS");
    let residue = aux_residue_us();
    assert!((5..=UNIT_US.strict_sub(5)).contains(&residue), "the auxiliary packet starts at a unit's edge");
    assert!(
        PRIMARY_SPACING_US.strict_sub(PRIMARY_US).strict_sub(DISABLE_US).strict_sub(tx_ready_us(Phy::M1))
            >= CPU_SLACK_MIN_US,
        "no time to set the next primary packet up"
    );
    let mut channels: usize = 1;
    while channels <= CHANNELS.len() {
        let mut index: usize = 0;
        while index < channels {
            let offset = u32::from(aux_offset(Phy::M1, channels, index)).strict_mul(UNIT_US);
            assert!(aux_offset(Phy::M1, channels, index) <= AUX_OFFSET_MAX, "the Aux Offset overflows its 13 bits");
            assert!(offset >= PRIMARY_US.strict_add(T_MAFS_US), "an Aux Offset shorter than the packet and T_MAFS");
            assert!(aux_start_us(Phy::M1, channels, index).strict_sub(offset) == residue, "the AuxPtrs disagree");
            index = index.strict_add(1);
        }
        channels = channels.strict_add(1);
    }
    let mut phys: &[Phy] = &SECONDARY_PHYS;
    while let Some((&secondary, rest)) = phys.split_first() {
        assert!(
            AUX_GAP_US.strict_sub(PRIMARY_US).strict_sub(DISABLE_US).strict_sub(tx_ready_us(secondary))
                >= CPU_SLACK_MIN_US,
            "no time to set the auxiliary packet up"
        );
        assert!(
            T_IFS_US.strict_add(secondary.address_offset_us()).strict_add(UNIT_US) <= LISTEN_US,
            "the listen ends before a request's access address"
        );
        assert!(
            event_us(CHANNELS.len(), Phy::M1, secondary, AUX_PAYLOAD_MAX) < ADV_INTERVAL_MIN_US,
            "the event outlasts 20 ms"
        );
        phys = rest;
    }
};

// The timing plan on LE Coded: on every primary PHY, whole units between
// primaries, at most 10 ms apart, `T_MAFS` and the same residue from every
// primary, an Aux Offset within its 13 bits, the CPU's time between packets
// for every secondary PHY, and a listen that outlasts a request's access
// address on LE Coded.
#[cfg(feature = "coded-phy")]
const _: () = {
    let residue = aux_residue_us();
    let mut primaries: &[Phy] = &[Phy::M1, Phy::CodedS8, Phy::CodedS2];
    while let Some((&primary, rest)) = primaries.split_first() {
        let spacing = primary_spacing_us(primary);
        let on_air = primary_us(primary);
        assert!(spacing.strict_rem(UNIT_US) == 0, "the primary spacing is not whole units");
        assert!(spacing <= 10_000, "primaries more than 10 ms apart (Core, Vol 6, Part B, 4.4.2.7)");
        assert!(
            spacing.strict_sub(on_air).strict_sub(DISABLE_US).strict_sub(tx_ready_us(primary)) >= CPU_SLACK_MIN_US,
            "no time to set the next primary packet up"
        );
        assert!(aux_gap_us(primary).strict_sub(on_air) >= T_MAFS_US, "the auxiliary packet starts within T_MAFS");
        assert!(
            aux_gap_us(primary).strict_rem(UNIT_US) == residue,
            "the auxiliary packet starts elsewhere in its unit"
        );
        let mut channels: usize = 1;
        while channels <= CHANNELS.len() {
            let mut index: usize = 0;
            while index < channels {
                let offset = u32::from(aux_offset(primary, channels, index)).strict_mul(UNIT_US);
                assert!(aux_offset(primary, channels, index) <= AUX_OFFSET_MAX, "the Aux Offset overflows its 13 bits");
                assert!(aux_start_us(primary, channels, index).strict_sub(offset) == residue, "the AuxPtrs disagree");
                assert!(offset >= on_air.strict_add(T_MAFS_US), "an Aux Offset shorter than the packet and T_MAFS");
                index = index.strict_add(1);
            }
            channels = channels.strict_add(1);
        }
        let mut secondaries: &[Phy] = &[Phy::M1, Phy::M2, Phy::CodedS8, Phy::CodedS2];
        while let Some((&secondary, others)) = secondaries.split_first() {
            assert!(
                aux_gap_us(primary).strict_sub(on_air).strict_sub(DISABLE_US).strict_sub(tx_ready_us(secondary))
                    >= CPU_SLACK_MIN_US,
                "no time to set the auxiliary packet up"
            );
            assert!(
                T_IFS_US.strict_add(secondary.address_offset_us()).strict_add(UNIT_US) <= listen_us(secondary),
                "the listen ends before a request's access address"
            );
            secondaries = others;
        }
        primaries = rest;
    }
};

/// The buffer of an `AUX_ADV_IND` and the request that follows it.
pub type AuxBuffer = Buffer<AUX_BUFFER_LEN>;

/// The advertiser's state from one event to the next: the event counter of
/// the secondary channel's selection, the counters of late packets and
/// decisions, and what the log last showed.
#[non_exhaustive]
pub struct Counters {
    /// Events so far: the event counter of channel selection algorithm 2
    /// for the secondary channel ([`aux_channel`]).
    events: u16,
    /// [`late_starts`] and [`late_connect_decisions`] as last logged.
    logged: (u32, u32),
    /// What the last event sent.
    sent:   Option<Sent>,
    /// What the log last showed of [`Self::sent`].
    shown:  Option<Sent>,
    /// The sampled event's times on air from the last primary and from the
    /// first to the auxiliary packet, until logged.
    #[cfg(feature = "defmt")]
    timing: Option<(Micros, Micros)>,
}

impl Counters {
    /// Logs what changed since the last call: the advertising set as sent,
    /// the late counters, and the timing of a sampled event, every 1024th.
    #[inline]
    pub fn log(&mut self) {
        if self.sent != self.shown {
            self.shown = self.sent;
            if let Some(sent) = self.sent {
                info!(
                    "advertising extended: {} channels, did {=u16:03X}, {} octets, secondary {}M",
                    sent.channels,
                    sent.adi.did(),
                    sent.len,
                    sent.phy.hci()
                );
            }
        }
        let late = (late_starts(), late_connect_decisions());
        if late != self.logged {
            self.logged = late;
            info!("advertising: {} starts late, {} connect decisions late", late.0, late.1);
        }
        #[cfg(feature = "defmt")]
        if let Some((from_last, from_first)) = self.timing.take() {
            info!("aux timing: last primary to aux {} us, first to aux {} us", from_last.0, from_first.0);
        }
    }

    /// No events yet, and no counts logged.
    #[inline]
    #[must_use = "the counters are only created"]
    pub const fn new() -> Self {
        Self {
            events: 0,
            logged: (0, 0),
            sent: None,
            shown: None,
            #[cfg(feature = "defmt")]
            timing: None,
        }
    }
}

impl Default for Counters {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// Advertising type: connectable, as the link layer only advertises for a
/// connection.
#[derive(Clone, Copy, Eq)]
#[derive_const(PartialEq)]
#[non_exhaustive]
pub enum Kind {
    /// Connectable undirected.
    ConnectableUndirected,
    /// Connectable directed, low duty cycle: an `AUX_ADV_IND` with the
    /// target, at the advertising interval.
    DirectedLowDuty,
}

/// The PDUs of one advertising event, built before it: one `ADV_EXT_IND`
/// for each enabled primary channel, and the `AUX_ADV_IND`.
#[non_exhaustive]
pub struct Pdus {
    /// The secondary channel.
    pub aux_channel: u8,
    /// The buffer of the `AUX_ADV_IND`, which then takes the request.
    pub auxiliary:   AuxBuffer,
    /// The enabled primary channels in order, as many as [`Self::count`].
    pub channels:    [u8; 3],
    /// How many primary channels are enabled.
    pub count:       usize,
    /// The secondary channel's PHY.
    pub phy:         Phy,
    /// The `ADV_EXT_IND` of each enabled primary channel, in the order of
    /// [`Self::channels`].
    pub primaries:   [ExtPrimary; 3],
}

impl Pdus {
    /// The PDUs of `settings` in the event with the event counter `counter`:
    /// on the secondary channel [`aux_channel`] chooses, each primary with
    /// its Aux Offset, the `AUX_ADV_IND` with the data.
    #[inline]
    #[must_use = "the PDUs are only built"]
    pub fn new(settings: &Settings, counter: u16) -> Self {
        let (channels, count) = primary_channels(settings.channel_map);
        let aux_channel = aux_channel(settings.aux_id, counter);
        let phy = secondary_phy(settings);
        let primary_phy = primary_phy(settings);
        let primaries = array::from_fn(|index| {
            let offset = if index < count { aux_offset(primary_phy, count, index) } else { 0 };
            primary(settings, AuxPtr::new(aux_channel, offset, phy))
        });
        Self { aux_channel, auxiliary: Buffer(auxiliary(settings).into_buffer()), channels, count, phy, primaries }
    }
}

/// What an advertising event sent, for the log.
#[derive(Clone, Copy, Eq, PartialEq)]
struct Sent {
    /// The ADI.
    adi:      Adi,
    /// The number of primary channels.
    channels: usize,
    /// The length of the advertising data.
    len:      u8,
    /// The secondary channel's PHY.
    phy:      Phy,
}

impl Kind {
    /// The largest advertising data of the type: [`DATA_MAX`], or
    /// [`DIRECTED_DATA_MAX`] when directed.
    #[inline]
    #[must_use = "the length is only read"]
    pub const fn data_max(self) -> usize {
        match self {
            Self::ConnectableUndirected => DATA_MAX,
            Self::DirectedLowDuty => DIRECTED_DATA_MAX,
        }
    }

    /// Whether a central may connect: always.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_connectable(self) -> bool { matches!(self, Self::ConnectableUndirected | Self::DirectedLowDuty) }

    /// Whether the advertising is directed.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_directed(self) -> bool { matches!(self, Self::DirectedLowDuty) }

    /// Whether the advertising is high duty cycle directed: never, which
    /// extended advertising does not have.
    #[inline]
    #[must_use = "the property is only read"]
    pub const fn is_high_duty(self) -> bool {
        match self {
            Self::ConnectableUndirected | Self::DirectedLowDuty => false,
        }
    }
}

/// The connection request in `pdu`, a received `AUX_CONNECT_REQ`, if
/// `settings` accept it.
///
/// It has to be addressed to us, with valid parameters, from a central
/// `settings` accept: for directed advertising the target's identity, from
/// its own address or a resolvable private one of its key, and otherwise the
/// filter policy's centrals.
#[inline]
#[must_use = "the request is only checked"]
pub fn accepted_request(settings: &Settings, pdu: &[u8]) -> Option<ConnectInd> {
    accepted_request_with(settings, pdu, |central| settings.accepts_connection(central))
}

/// [`accepted_request`], with `accepts` deciding whether the settings
/// accept the central: in the host tests, with the AES in software.
#[inline]
pub(crate) fn accepted_request_with<Accepts>(settings: &Settings, pdu: &[u8], accepts: Accepts) -> Option<ConnectInd>
where
    Accepts: FnOnce(Peer) -> bool,
{
    ConnectInd::parse_aux(pdu, settings.own).filter(|request| accepts(request.central()))
}

/// Arms the radio's start at `at`, with at least [`MIN_LEAD_US`] to go.
/// Returns false, with the radio disabled, if the start is too close or
/// past, or raced the arming.
fn arm(radio: &mut Radio<'_>, clock: &mut Clock<'_>, at: At) -> bool {
    if clock.transmit_ahead(at, Micros(MIN_LEAD_US)) {
        return true;
    }
    radio.disable();
    false
}

/// Airtime of a packet with `payload_len` octets of payload on `phy`.
///
/// It is the preamble, access address, header, payload and CRC, at 8 us per
/// octet on LE 1M and 4 us on LE 2M, whose preamble is two octets, and on LE
/// Coded as [`Phy::pdu_us`] has it.
#[inline]
#[must_use = "the time is only computed"]
pub const fn airtime_us(phy: Phy, payload_len: usize) -> u32 {
    let (overhead, octet_us): (u32, u32) = match phy {
        Phy::M1 => (10, 8),
        Phy::M2 => (11, 4),
        #[cfg(feature = "coded-phy")]
        Phy::CodedS8 | Phy::CodedS2 => return phy.pdu_us(payload_len.saturating_add(HEADER_LEN)),
    };
    payload_len.saturating_cast::<u32>().saturating_add(overhead).saturating_mul(octet_us)
}

/// The channel of the `AUX_ADV_IND` in event `counter`.
///
/// Channel selection algorithm 2 over all 37 secondary channels with the
/// identifier `aux_id` (Core, Vol 6, Part B, 4.5.8.3) covers every channel
/// evenly; the channel index is the implementation's choice (4.4.2.1).
#[inline]
#[must_use = "the channel is only computed"]
pub fn aux_channel(aux_id: u16, counter: u16) -> u8 {
    Hopping::Csa2 { identifier: aux_id }.channel(&UsedChannels::new([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]), counter)
}

/// The Aux Offset of primary `index` of `channels` on `primary`, in units
/// of 30 us: from its start to the unit in which the auxiliary packet
/// starts.
#[inline]
#[must_use = "the offset is only computed"]
pub const fn aux_offset(primary: Phy, channels: usize, index: usize) -> u16 {
    aux_start_us(primary, channels, index).strict_div(UNIT_US).strict_cast()
}

/// How far into the unit of its Aux Offset the auxiliary packet starts:
/// 12 us, the same from every primary.
#[inline]
#[must_use = "the time is only computed"]
pub const fn aux_residue_us() -> u32 { AUX_GAP_US.strict_rem(UNIT_US) }

/// Time from the start of primary `index` of `channels` on `primary` to the
/// start of the auxiliary packet, on air.
#[inline]
#[must_use = "the time is only computed"]
pub const fn aux_start_us(primary: Phy, channels: usize, index: usize) -> u32 {
    let after: u32 = channels.strict_sub(1).strict_sub(index).strict_cast();
    after.strict_mul(primary_spacing_us(primary)).strict_add(aux_gap_us(primary))
}

/// The `AUX_ADV_IND` of `settings`: undirected, or directed to the target
/// on air, with the advertising set's ADI and the data.
#[inline]
#[must_use = "the PDU is only built"]
pub fn auxiliary(settings: &Settings) -> AuxAdvertisement {
    let data = settings.data.get(..usize::from(settings.len)).unwrap_or_default();
    match settings.kind {
        Kind::ConnectableUndirected => aux_undirected(settings.own, settings.adi, data),
        Kind::DirectedLowDuty => aux_directed(settings.own, settings.target(), settings.adi, data),
    }
}

/// Adds one to `counter`, which only the link layer task writes.
fn count(counter: &AtomicU32) { counter.store(counter.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed); }

/// The TXEN of the auxiliary packet on `phy` in an event of `channels`
/// primaries on `primary` whose first starts on air at `first`.
#[inline]
#[must_use = "the time is only computed"]
pub(crate) const fn aux_txen(first: At, primary: Phy, channels: usize, phy: Phy) -> At {
    first.after(Micros(aux_start_us(primary, channels, 0))).before(Micros(tx_ready_us(phy)))
}

/// Runs one advertising event on the enabled channels.
///
/// Returns the time it started, read once the PDUs are built, and the
/// connection request it accepted, if any: once its `AUX_CONNECT_RSP` was
/// sent, with the transmit window 2.5 ms after the request and the
/// connection on the secondary channel's PHY.
///
/// The radio is disabled and back on LE 1M when it returns.
#[inline]
pub(crate) fn event(
    radio: &mut Radio<'_>,
    clock: &mut Clock<'_>,
    settings: &Settings,
    counters: &mut Counters,
) -> (At, Option<Accepted>) {
    let mut pdus = Pdus::new(settings, counters.events);
    let decoy = aux_connect_rsp(settings.own, NOBODY);
    let mut answer = aux_connect_rsp(settings.own, NOBODY);
    #[cfg(feature = "defmt")]
    let sampled = counters.events & TIMING_SAMPLE_MASK == 0;
    counters.events = counters.events.wrapping_add(1);
    counters.sent =
        Some(Sent { adi: settings.adi, channels: pdus.count, len: settings.len, phy: pdus.phy });
    #[cfg(not(feature = "coded-phy"))]
    let primary = Phy::M1;
    #[cfg(feature = "coded-phy")]
    let primary = primary_phy(settings);
    radio.set_access_address(ADV_ACCESS_ADDRESS);
    radio.set_crc_init(ADV_CRC_INIT);
    radio.set_phy(primary);
    let started = clock.now();
    if pdus.count == 0 {
        return (started, None);
    }
    let first = started.after(Micros(EVENT_LEAD_US)).after(Micros(tx_ready_us(primary)));
    // The first and the last primary sent, on air, for a sampled event.
    #[cfg(feature = "defmt")]
    let mut primaries_on_air: Option<(At, At)> = None;
    for (index, (&channel, pdu)) in pdus.channels.iter().zip(&pdus.primaries).take(pdus.count).enumerate() {
        radio.set_channel(channel);
        // SAFETY: the radio only reads the primary, which lives until the
        // event returns, and no turnaround follows it; every path out waits
        // until the radio is disabled.
        unsafe { radio.prepare_send(pdu.as_bytes()) }
        if !arm(radio, clock, primary_txen(first, primary, index)) {
            count(&LATE_STARTS);
            continue;
        }
        radio.wait_disabled();
        #[cfg(feature = "defmt")]
        if sampled {
            let on_air = clock.address_time().before(Micros(primary.address_offset_us()));
            primaries_on_air = Some((primaries_on_air.map_or(on_air, |(earliest, _)| earliest), on_air));
        }
    }
    radio.set_channel(pdus.aux_channel);
    radio.set_phy(pdus.phy);
    // SAFETY: the radio sends the `AUX_ADV_IND` from the buffer and then
    // receives the request into it; the buffer lives until the event
    // returns, and every path out waits until the radio is disabled.
    unsafe { radio.prepare(&mut pdus.auxiliary, Turnaround::Receive) }
    let accepted = if arm(radio, clock, aux_txen(first, primary, pdus.count, pdus.phy)) {
        radio.wait_end();
        #[cfg(feature = "defmt")]
        if let Some((earliest, latest)) = primaries_on_air.filter(|_| sampled) {
            let on_air = clock.address_time().before(Micros(pdus.phy.address_offset_us()));
            counters.timing = Some((on_air.since(latest), on_air.since(earliest)));
        }
        #[cfg(feature = "coded-phy")]
        let heard = if pdus.phy.is_coded() {
            listen_coded(radio, clock, settings, &mut pdus.auxiliary, &mut answer, pdus.phy)
        } else {
            listen(radio, clock, settings, &mut pdus.auxiliary, (&decoy, &mut answer))
        };
        #[cfg(not(feature = "coded-phy"))]
        let heard = listen(radio, clock, settings, &mut pdus.auxiliary, (&decoy, &mut answer));
        heard.map(|(request, end)| Accepted { end: end.0, request, setup: Setup::aux(pdus.phy) })
    } else {
        count(&LATE_STARTS);
        None
    };
    radio.set_phy(Phy::M1);
    (started, accepted)
}

/// Connection requests decided late.
///
/// Those whose `AUX_CONNECT_RSP` was pointed at only after the radio had
/// started sending, refused as the answer it sent may name nobody, and
/// those whose check ended only after the answer had, past
/// [`decision_budget_us`], when a refusal no longer stops it and an
/// accepted request's answer may have gone out twice. A refusal that stops an
/// answer under way within the budget, of a central the filter policy or the
/// directed target refuses, is no timing failure and not counted. On LE
/// Coded, whose answer is armed once the request ended, also those whose
/// answer could not be armed in time.
#[inline]
#[must_use = "the count is only read"]
pub fn late_connect_decisions() -> u32 { LATE_CONNECT_DECISIONS.load(Ordering::Relaxed) }

/// Packets skipped because their TXEN was less than [`MIN_LEAD_US`] ahead
/// when the radio was armed: a primary, which costs its channel, or the
/// auxiliary packet, which costs the event.
#[inline]
#[must_use = "the count is only read"]
pub fn late_starts() -> u32 { LATE_STARTS.load(Ordering::Relaxed) }

/// Listens for an `AUX_CONNECT_REQ` after the `AUX_ADV_IND` that ended, and
/// answers one `settings` accept. Returns it with the time its packet
/// ended, once the `AUX_CONNECT_RSP` was sent, with the radio disabled.
///
/// The request comes into `buffer`, the one the `AUX_ADV_IND` went out
/// from, which holds the longest packet the advertising channels admit. Once
/// its access address came, the radio points at `decoy`, an answer to
/// nobody, so a turnaround the decision misses never sends the request
/// back. At its end the initiator goes into `answer`, which the radio is
/// then pointed at, so it never reads a half-written answer: if it started
/// sending before, the answer it sent may be the decoy, and the request is
/// refused (see [`late_connect_decisions`]). The request's whole check, with an
/// address resolution on the ECB for a private initiator, follows, and a
/// refusal stops an answer under way: it has to end within
/// [`decision_budget_us`] of the request, about 245 us on LE 2M. An
/// accepted request is answered also when its check ran past the answer's
/// end.
///
/// The answer's `TargetA` is always the request's `InitA`. For directed
/// advertising to a central with a key in device privacy mode, whose request
/// may carry its identity address, the specification recommends another
/// `TargetA` than that `InitA` (should; Core, Vol 6, Part B, 6.2.2). This
/// deviates on purpose: initiators take only an answer whose `TargetA` is
/// their `InitA` (Zephyr's `isr_rx_connect_rsp_check`), so an answer to the
/// advertised private address would lose the connection.
fn listen(
    radio: &mut Radio<'_>,
    clock: &Clock<'_>,
    settings: &Settings,
    buffer: &mut AuxBuffer,
    (decoy, answer): (&AuxConnectRsp, &mut AuxConnectRsp),
) -> Option<(ConnectInd, At)> {
    // SAFETY: `buffer` is borrowed for this event; every path out waits
    // until the radio is disabled.
    unsafe { radio.set_buffer(buffer) }
    radio.wait_switched();
    radio.set_turnaround(Turnaround::Transmit);
    radio.clear_address();
    let deadline = clock.end_time().after(Micros(LISTEN_US));
    clock.expire_at(deadline);
    let heard = radio.wait_address(|| clock.expired(deadline));
    clock.stop_expiry();
    if !heard {
        radio.disable();
        return None;
    }
    // SAFETY: the radio only reads the decoy, which lives until the event
    // returns; every path out waits until the radio is disabled. The
    // request's access address came, so its reception latched `buffer`, and
    // the turnaround after it sends.
    unsafe { radio.set_send_buffer(decoy.as_bytes()) }
    radio.clear_ready();
    radio.wait_end();
    let end = clock.end_time();
    let Some(initiator) = radio.crc_ok().then(|| aux_connect_initiator(&buffer.0)).flatten() else {
        radio.disable();
        return None;
    };
    retarget(answer, initiator);
    // SAFETY: as for the decoy; the radio has not read the answer before.
    unsafe { radio.set_send_buffer(answer.as_bytes()) }
    let late = radio.tx_started();
    if radio::TURNAROUND_IN_ANSWER {
        // The nRF51's DISABLED to TXEN shortcut started the answer a few
        // microseconds after the request's END. Disarmed now, it cannot
        // send the answer again once it ended, however long the check takes.
        radio.wait_switched();
        radio.set_turnaround(Turnaround::None);
    }
    let request = (!late).then(|| accepted_request(settings, &buffer.0)).flatten();
    // Late: the answer was pointed at after it started, or it ended before
    // the check did, past `decision_budget_us`, when a refusal no longer
    // stops it.
    if late || radio.is_end() {
        count(&LATE_CONNECT_DECISIONS);
    }
    if request.is_none() {
        // Stops an answer under way: cut short, it fails its CRC.
        radio.disable();
        return None;
    }
    if !radio::TURNAROUND_IN_ANSWER {
        // TIMER1 is re-armed only once its compare started the answer.
        radio.wait_switched();
        radio.set_turnaround(Turnaround::None);
    }
    // By the radio's state: the answer may have ended, and its events been
    // cleared by `wait_switched`, before.
    radio.wait_stopped();
    request.map(|accepted| (accepted, end))
}

/// Listens for an `AUX_CONNECT_REQ` after the `AUX_ADV_IND` on LE Coded with
/// `phy`'s coding that ended, and answers one `settings` accept. Returns it
/// with the time its packet ended on air, once the `AUX_CONNECT_RSP` was
/// sent, with the radio disabled.
///
/// The answer's turnaround depends on the coding the central chose for its
/// request, which the radio learns from the request's coding indicator: the
/// receive chain takes 29.6 us with S=8 and 24.6 us with S=2. So no
/// turnaround is armed before the request, as [`listen`] arms one; once the
/// request ended, the answer to its initiator is armed on TIMER0 for one
/// interframe space after it ([`Phy::response_offset_us`] of the coding
/// RATEBOOST tells, [`Radio::received`]). The radio stays in the mode of the
/// advertising's coding, which receives either coding, as Zephyr's
/// advertiser does. A request whose CRC fails gets no answer, and one whose
/// answer cannot be armed [`MIN_LEAD_US`] ahead is refused and counted late.
/// The request's whole check follows, and a refusal cancels or stops the
/// answer; a check that ends only after the answer did is counted late,
/// as in [`listen`]. The answer goes out with the advertising's coding.
///
/// The request's END comes the receive chain's delay after its end on air,
/// which the time returned leaves out: the transmit window is timed from
/// the end on air (Core, Vol 6, Part B, 4.5.3).
#[cfg(feature = "coded-phy")]
fn listen_coded(
    radio: &mut Radio<'_>,
    clock: &mut Clock<'_>,
    settings: &Settings,
    buffer: &mut AuxBuffer,
    answer: &mut AuxConnectRsp,
    phy: Phy,
) -> Option<(ConnectInd, At)> {
    // SAFETY: `buffer` is borrowed for this event; every path out waits
    // until the radio is disabled.
    unsafe { radio.set_buffer(buffer) }
    radio.wait_switched();
    radio.set_turnaround(Turnaround::None);
    radio.clear_address();
    let deadline = clock.end_time().after(Micros(listen_us(phy)));
    clock.expire_at(deadline);
    let heard = radio.wait_address(|| clock.expired(deadline));
    clock.stop_expiry();
    if !heard {
        radio.disable();
        return None;
    }
    radio.wait_end();
    let end = clock.end_time();
    let received = radio.received(phy);
    radio.wait_disabled();
    let Some(initiator) = radio.crc_ok().then(|| aux_connect_initiator(&buffer.0)).flatten() else {
        radio.disable();
        return None;
    };
    retarget(answer, initiator);
    // SAFETY: the radio only reads the answer, which lives until the event
    // returns; no turnaround is armed, so no reception follows it.
    unsafe { radio.set_send_buffer(answer.as_bytes()) }
    if !arm(radio, clock, end.after(Micros(phy.response_offset_us(received)))) {
        count(&LATE_CONNECT_DECISIONS);
        return None;
    }
    let request = accepted_request(settings, &buffer.0);
    if radio.is_end() {
        count(&LATE_CONNECT_DECISIONS);
    }
    let Some(accepted) = request else {
        // Cancels an answer still to start, and stops one under way: cut
        // short, it fails its CRC.
        clock.cancel_start();
        radio.disable();
        return None;
    };
    clock.wait_started();
    radio.wait_stopped();
    Some((accepted, end.before(Micros(chip::rx_chain_ns(received).div_ceil(1000)))))
}

/// Time after the end of an `AUX_ADV_IND` on `phy` until a request's access
/// address event must have come.
///
/// It is the 300 us of LE 1M and LE 2M, and on LE Coded as much longer as
/// its access address event comes after the packet's start, 636 us.
#[cfg(feature = "coded-phy")]
#[inline]
#[must_use = "the time is only computed"]
pub const fn listen_us(phy: Phy) -> u32 {
    if phy.is_coded() {
        LISTEN_US.strict_sub(Phy::M1.address_offset_us()).strict_add(phy.address_offset_us())
    } else {
        LISTEN_US
    }
}

/// Time from the end of an `AUX_CONNECT_REQ` on `phy` on air to the end of
/// our `AUX_CONNECT_RSP`, one interframe space later: 342 us on LE 1M,
/// 250 us on LE 2M.
///
/// The request's check has to end within it, or a refusal
/// no longer stops the answer, and the central takes the connection as made
/// (see [`late_connect_decisions`]). The END event the check starts from
/// comes the receive chain's delay later, about 9 us on LE 1M and 5 us on
/// LE 2M on the nRF52 chips, which leaves about 332 to 333 and 245 us from
/// there.
#[inline]
#[must_use = "the time is only computed"]
pub const fn decision_budget_us(phy: Phy) -> u32 { T_IFS_US.strict_add(airtime_us(phy, AUX_CONNECT_RSP_LEN)) }

/// The longest an event of `channels` primaries on `primary` takes with an
/// auxiliary packet of `aux_len` payload octets on `phy`, from its start
/// until the end of an `AUX_CONNECT_RSP`.
#[inline]
#[must_use = "the time is only computed"]
pub const fn event_us(channels: usize, primary: Phy, phy: Phy, aux_len: usize) -> u32 {
    let spacing: u32 = channels.strict_sub(1).strict_cast();
    EVENT_LEAD_US
        .strict_add(tx_ready_us(primary))
        .strict_add(spacing.strict_mul(primary_spacing_us(primary)))
        .strict_add(aux_gap_us(primary))
        .strict_add(airtime_us(phy, aux_len))
        .strict_add(T_IFS_US)
        .strict_add(airtime_us(phy, usize::from(CONNECT_IND_LEN)))
        .strict_add(T_IFS_US)
        .strict_add(airtime_us(phy, AUX_CONNECT_RSP_LEN))
}

/// The PHY of the primary channel: LE 1M, the only one without the feature
/// `coded-phy`.
#[cfg(not(feature = "coded-phy"))]
#[inline]
#[must_use = "the PHY is only read"]
pub const fn primary_phy(_settings: &Settings) -> Phy { Phy::M1 }

/// The PHY of the primary channel: the settings', LE 1M or LE Coded.
#[cfg(feature = "coded-phy")]
#[inline]
#[must_use = "the PHY is only read"]
pub const fn primary_phy(settings: &Settings) -> Phy { settings.primary_phy }

/// Time from the start of one primary packet on `primary` to the next on
/// air: [`PRIMARY_SPACING_US`], the only spacing without the feature
/// `coded-phy`.
#[cfg(not(feature = "coded-phy"))]
#[inline]
#[must_use = "the time is only computed"]
pub const fn primary_spacing_us(_primary: Phy) -> u32 { PRIMARY_SPACING_US }

/// Time from the start of one primary packet on `primary` to the next on
/// air.
///
/// It is [`PRIMARY_SPACING_US`] on LE 1M, and on LE Coded the primary's
/// airtime, the radio's disabling, the ramp-up and [`CPU_SLACK_MIN_US`],
/// rounded up to whole units of 30 us: 1290 us with S=8, 690 us with S=2.
#[cfg(feature = "coded-phy")]
#[inline]
#[must_use = "the time is only computed"]
pub const fn primary_spacing_us(primary: Phy) -> u32 {
    if !primary.is_coded() {
        return PRIMARY_SPACING_US;
    }
    let busy = primary_us(primary).strict_add(DISABLE_US).strict_add(tx_ready_us(primary)).strict_add(CPU_SLACK_MIN_US);
    busy.div_ceil(UNIT_US).strict_mul(UNIT_US)
}

/// Airtime of an `ADV_EXT_IND` on `primary`: [`PRIMARY_US`] on LE 1M,
/// 1168 us on LE Coded with S=8 and 574 us with S=2.
#[inline]
#[must_use = "the time is only computed"]
pub const fn primary_us(primary: Phy) -> u32 { airtime_us(primary, EXT_PRIMARY_LEN) }

/// Time from the start of the last primary packet on `primary` to the
/// start of the auxiliary packet on air: [`AUX_GAP_US`], the only gap
/// without the feature `coded-phy`.
#[cfg(not(feature = "coded-phy"))]
#[inline]
#[must_use = "the time is only computed"]
pub const fn aux_gap_us(_primary: Phy) -> u32 { AUX_GAP_US }

/// Time from the start of the last primary packet on `primary` to the
/// start of the auxiliary packet on air.
///
/// It is [`AUX_GAP_US`] on LE 1M, and on LE Coded 12 us into the first unit
/// of 30 us that starts at least `T_MAFS` after the primary's end, as on LE
/// 1M, and leaves the time to set the auxiliary packet up on any PHY: 1482
/// us with S=8, 912 us with S=2.
#[cfg(feature = "coded-phy")]
#[inline]
#[must_use = "the time is only computed"]
pub const fn aux_gap_us(primary: Phy) -> u32 {
    if !primary.is_coded() {
        return AUX_GAP_US;
    }
    let residue = aux_residue_us();
    let primary_end = primary_us(primary);
    let frame_space = primary_end.strict_add(T_MAFS_US);
    let setup = primary_end
        .strict_add(DISABLE_US)
        .strict_add(tx_ready_us(Phy::CodedS8))
        .strict_add(CPU_SLACK_MIN_US)
        .strict_sub(residue);
    let unit = if frame_space > setup { frame_space } else { setup };
    unit.div_ceil(UNIT_US).strict_mul(UNIT_US).strict_add(residue)
}

/// Raises the interval of `settings` to the longest its event takes.
///
/// That is from its start until the end of an `AUX_CONNECT_RSP`
/// ([`event_us`]), so that one event ends before the next starts and the
/// random delay between them holds. Only an event on LE Coded can outlast the
/// shortest interval, 20 ms: with S=8 on both channels, three primaries and 245
/// octets of data take about 26 ms.
#[cfg(feature = "coded-phy")]
#[inline]
pub fn fit_interval(settings: &mut Settings) {
    let (_, channels) = primary_channels(settings.channel_map);
    let aux_len = auxiliary(settings).as_bytes().len().saturating_sub(HEADER_LEN);
    let event = event_us(channels.max(1), primary_phy(settings), secondary_phy(settings), aux_len);
    settings.interval = settings.interval.max(event);
}

/// The `ADV_EXT_IND` of `settings` with the pointer `aux`.
#[inline]
#[must_use = "the PDU is only built"]
pub fn primary(settings: &Settings, aux: AuxPtr) -> ExtPrimary { ext_primary(settings.adi, aux) }

/// The TXEN of primary `index` on `primary` in an event whose first
/// primary starts on air at `first`: `index` spacings later, less the
/// ramp-up.
#[inline]
#[must_use = "the time is only computed"]
pub(crate) const fn primary_txen(first: At, primary: Phy, index: usize) -> At {
    let spacings: u32 = index.saturating_cast();
    first.after(Micros(primary_spacing_us(primary)).saturating_mul(spacings)).before(Micros(tx_ready_us(primary)))
}

/// The enabled primary channels of `channel_map` in order, and how many
/// there are.
#[inline]
#[must_use = "the channels are only listed"]
pub fn primary_channels(channel_map: u8) -> ([u8; 3], usize) {
    let mut channels = [0; 3];
    let mut count: usize = 0;
    for (channel, _) in CHANNELS.into_iter().filter(|&(_, bit)| channel_map & bit != 0) {
        if let Some(slot) = channels.get_mut(count) {
            *slot = channel;
        }
        count = count.saturating_add(1);
    }
    (channels, count)
}

/// Gives the advertising set a new advertising data ID, neither the current
/// one nor that of the last event ([`Settings::last_used`]), and a new
/// secondary channel identifier, from `random`.
///
/// The link layer task calls it with new random octets before the next
/// event once the data or our address changed (see [`Settings::stale`]).
#[inline]
pub const fn renew(settings: &mut Settings, random: [u8; RENEWAL_LEN]) {
    let [did0, did1, id0, id1] = random;
    settings.adi = settings.adi.renewed(u16::from_le_bytes([did0, did1]), settings.last_used);
    settings.aux_id = u16::from_le_bytes([id0, id1]);
    settings.stale = false;
}

/// The PHY of the secondary channel: the settings', LE 1M on the nRF51,
/// which has no other.
#[inline]
#[must_use = "the PHY is only read"]
pub const fn secondary_phy(settings: &Settings) -> Phy { if chip::PHY_2M { settings.secondary_phy } else { Phy::M1 } }

/// Sets the advertising data of `settings`. Returns false, changing
/// nothing, if it is longer than [`DATA_MAX`] or `scan` is not empty. The
/// advertising set then waits for its renewal ([`renew`]).
#[inline]
#[must_use = "data that does not fit is refused"]
pub fn set_data(settings: &mut Settings, adv: &[u8], scan: &[u8]) -> bool {
    if adv.len() > DATA_MAX || !scan.is_empty() {
        return false;
    }
    settings.data.fill(0);
    if let Some(destination) = settings.data.get_mut(..adv.len()) {
        destination.copy_from_slice(adv);
    }
    settings.len = adv.len().saturating_cast();
    settings.stale = true;
    true
}

/// Sets our address on air; a new one waits for the renewal of the
/// advertising set ([`renew`]), so that neither its ADI nor its secondary
/// channels link the new address to the old one.
#[inline]
pub const fn set_own(settings: &mut Settings, own: Peer) {
    if own != settings.own {
        settings.stale = true;
    }
    settings.own = own;
}

/// Time from TXEN until the packet starts on air on `phy`.
///
/// It is the fast ramp-up and the TX chain, as in Zephyr's Nordic HAL,
/// rounded down: 41 us on LE 1M (41.05 us) and 40 us on LE 2M on the
/// nRF52832, 40 us on both (40.9 and 40 us) on the nRF52833.
#[cfg(feature = "_nrf52")]
#[inline]
#[must_use = "the time is only computed"]
pub const fn tx_ready_us(phy: Phy) -> u32 { chip::tx_ready_ns(phy).strict_div(1000) }

/// Time from TXEN until the packet starts on air: the nRF51's ramp-up,
/// about 140 us on LE 1M, its only PHY.
///
/// TODO(datasheet): measure it; it only sets the CPU time between packets,
/// as every packet of the event ramps up alike.
#[cfg(feature = "nrf51")]
#[inline]
#[must_use = "the time is only computed"]
pub const fn tx_ready_us(phy: Phy) -> u32 {
    match phy {
        Phy::M1 | Phy::M2 => 140,
    }
}

#[cfg(test)] mod tests;
