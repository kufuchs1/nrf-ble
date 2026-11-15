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
//! for LE 1M and, on the nRF52832, LE 2M on the secondary channel.
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
    clock::Clock,
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
    radio::{self, Phy, Radio, Turnaround},
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
/// Time from the end of the last primary packet to the start of the
/// auxiliary packet on air: at least `T_MAFS`, and 12 us into a 30 us unit.
pub const AUX_GAP_US: u32 = 462;
/// Least CPU time between the radio's DISABLED after a packet and the TXEN
/// of the next.
///
/// On the 64 MHz Cortex-M4F the next packet's setup takes a few
/// microseconds.
#[cfg(feature = "nrf52832")]
pub const CPU_SLACK_MIN_US: u32 = 60;
/// Least CPU time between the radio's DISABLED after a packet and the TXEN
/// of the next.
///
/// On the 16 MHz Cortex-M0 the next packet's setup takes several times as
/// long as on the nRF52832.
#[cfg(feature = "nrf51")]
pub const CPU_SLACK_MIN_US: u32 = 100;
/// Largest advertising data: the largest payload the chip sends
/// ([`AUX_PAYLOAD_MAX`]) after the extended header of an undirected
/// `AUX_ADV_IND`, 245 octets on the nRF52832 and 242 on the nRF51.
pub const DATA_MAX: usize = AUX_PAYLOAD_MAX.strict_sub(AUX_HEADER_LEN);
/// Largest advertising data of directed advertising, whose extended header
/// also holds the target: 239 octets on the nRF52832 and 236 on the nRF51.
pub const DIRECTED_DATA_MAX: usize = AUX_PAYLOAD_MAX.strict_sub(AUX_DIRECTED_HEADER_LEN);
/// Time from the END of a sent packet until the radio is DISABLED.
pub const DISABLE_US: u32 = 6;
/// Time from the start of an event until the first TXEN: the PDUs are built
/// before, so this only covers arming the radio.
#[cfg(feature = "nrf52832")]
pub const EVENT_LEAD_US: u32 = 60;
/// Time from the start of an event until the first TXEN: the PDUs are built
/// before, so this only covers arming the radio.
#[cfg(feature = "nrf51")]
pub const EVENT_LEAD_US: u32 = 120;
/// The least time ahead a TXEN is armed for: a start closer than this may
/// pass before the compare is set, and the packet is skipped instead.
#[cfg(feature = "nrf52832")]
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
#[cfg(feature = "nrf52832")]
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
#[cfg(feature = "nrf52832")]
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
            let offset = u32::from(aux_offset(channels, index)).strict_mul(UNIT_US);
            assert!(aux_offset(channels, index) <= AUX_OFFSET_MAX, "the Aux Offset overflows its 13 bits");
            assert!(offset >= PRIMARY_US.strict_add(T_MAFS_US), "an Aux Offset shorter than the packet and T_MAFS");
            assert!(aux_start_us(channels, index).strict_sub(offset) == residue, "the AuxPtrs disagree");
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
        assert!(event_us(CHANNELS.len(), secondary, AUX_PAYLOAD_MAX) < ADV_INTERVAL_MIN_US, "the event outlasts 20 ms");
        phys = rest;
    }
};

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
    timing: Option<(u32, u32)>,
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
            info!("aux timing: last primary to aux {} us, first to aux {} us", from_last, from_first);
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
    pub auxiliary:   [u8; AUX_BUFFER_LEN],
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
        let primaries = array::from_fn(|index| {
            let offset = if index < count { aux_offset(count, index) } else { 0 };
            primary(settings, AuxPtr::new(aux_channel, offset, phy))
        });
        Self { aux_channel, auxiliary: auxiliary(settings).into_buffer(), channels, count, phy, primaries }
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
fn arm(radio: &mut Radio<'_>, clock: &mut Clock<'_>, at: u32) -> bool {
    if clock.transmit_ahead(at, MIN_LEAD_US) {
        return true;
    }
    radio.disable();
    false
}

/// Airtime of a packet with `payload_len` octets of payload on `phy`:
/// preamble, access address, header, payload and CRC, at 8 us per octet on
/// LE 1M and 4 us on LE 2M, whose preamble is two octets.
#[inline]
#[must_use = "the time is only computed"]
pub const fn airtime_us(phy: Phy, payload_len: usize) -> u32 {
    let (overhead, octet_us): (u32, u32) = match phy {
        Phy::M1 => (10, 8),
        Phy::M2 => (11, 4),
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

/// The Aux Offset of primary `index` of `channels`, in units of 30 us: from
/// its start to the unit in which the auxiliary packet starts.
#[inline]
#[must_use = "the offset is only computed"]
pub const fn aux_offset(channels: usize, index: usize) -> u16 {
    aux_start_us(channels, index).strict_div(UNIT_US).strict_cast()
}

/// How far into the unit of its Aux Offset the auxiliary packet starts:
/// 12 us, the same from every primary.
#[inline]
#[must_use = "the time is only computed"]
pub const fn aux_residue_us() -> u32 { AUX_GAP_US.strict_rem(UNIT_US) }

/// Time from the start of primary `index` of `channels` to the start of the
/// auxiliary packet, on air.
#[inline]
#[must_use = "the time is only computed"]
pub const fn aux_start_us(channels: usize, index: usize) -> u32 {
    let after: u32 = channels.strict_sub(1).strict_sub(index).strict_cast();
    after.strict_mul(PRIMARY_SPACING_US).strict_add(AUX_GAP_US)
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
/// primaries whose first starts on air at `first`.
#[inline]
#[must_use = "the time is only computed"]
pub const fn aux_txen(first: u32, channels: usize, phy: Phy) -> u32 {
    first.wrapping_add(aux_start_us(channels, 0)).wrapping_sub(tx_ready_us(phy))
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
pub fn event(
    radio: &mut Radio<'_>,
    clock: &mut Clock<'_>,
    settings: &Settings,
    counters: &mut Counters,
) -> (u32, Option<Accepted>) {
    let mut pdus = Pdus::new(settings, counters.events);
    let decoy = aux_connect_rsp(settings.own, NOBODY);
    let mut answer = aux_connect_rsp(settings.own, NOBODY);
    #[cfg(feature = "defmt")]
    let sampled = counters.events & TIMING_SAMPLE_MASK == 0;
    counters.events = counters.events.wrapping_add(1);
    counters.sent =
        Some(Sent { adi: settings.adi, channels: pdus.count, len: settings.len, phy: pdus.phy });
    radio.set_access_address(ADV_ACCESS_ADDRESS);
    radio.set_crc_init(ADV_CRC_INIT);
    radio.set_phy(Phy::M1);
    let started = clock.now();
    if pdus.count == 0 {
        return (started, None);
    }
    let first = started.wrapping_add(EVENT_LEAD_US).wrapping_add(tx_ready_us(Phy::M1));
    // The first and the last primary sent, on air, for a sampled event.
    #[cfg(feature = "defmt")]
    let mut primaries_on_air: Option<(u32, u32)> = None;
    for (index, (&channel, pdu)) in pdus.channels.iter().zip(&pdus.primaries).take(pdus.count).enumerate() {
        radio.set_channel(channel);
        // SAFETY: the radio only reads the primary, which lives until the
        // event returns; every path out waits until the radio is disabled.
        unsafe { radio.prepare(pdu.as_bytes().as_ptr().cast_mut(), Turnaround::None) }
        if !arm(radio, clock, primary_txen(first, index)) {
            count(&LATE_STARTS);
            continue;
        }
        radio.wait_disabled();
        #[cfg(feature = "defmt")]
        if sampled {
            let on_air = clock.address_time().wrapping_sub(Phy::M1.address_offset_us());
            primaries_on_air = Some((primaries_on_air.map_or(on_air, |(earliest, _)| earliest), on_air));
        }
    }
    radio.set_channel(pdus.aux_channel);
    radio.set_phy(pdus.phy);
    // SAFETY: the radio sends the `AUX_ADV_IND` from the buffer and then
    // receives the request into it, which takes the longest packet the
    // advertising channels admit (`chip::ADV_MAXLEN`, asserted in
    // `pdu`); the buffer lives until the event returns, and every path
    // out waits until the radio is disabled.
    unsafe { radio.prepare(pdus.auxiliary.as_mut_ptr(), Turnaround::Receive) }
    let accepted = if arm(radio, clock, aux_txen(first, pdus.count, pdus.phy)) {
        radio.wait_end();
        #[cfg(feature = "defmt")]
        if let Some((earliest, latest)) = primaries_on_air.filter(|_| sampled) {
            let on_air = clock.address_time().wrapping_sub(pdus.phy.address_offset_us());
            counters.timing = Some((on_air.wrapping_sub(latest), on_air.wrapping_sub(earliest)));
        }
        listen(radio, clock, settings, &mut pdus.auxiliary, (&decoy, &mut answer)).map(|(request, end)| Accepted {
            end,
            request,
            setup: Setup::aux(pdus.phy),
        })
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
/// directed target refuses, is no timing failure and not counted.
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
    buffer: &mut [u8; AUX_BUFFER_LEN],
    (decoy, answer): (&AuxConnectRsp, &mut AuxConnectRsp),
) -> Option<(ConnectInd, u32)> {
    // SAFETY: `buffer` takes any packet the advertising channels admit
    // (`chip::ADV_MAXLEN`, asserted in `pdu`) and is borrowed for this
    // event; every path out waits until the radio is disabled.
    unsafe { radio.set_buffer(buffer.as_mut_ptr()) }
    radio.wait_switched();
    radio.set_turnaround(Turnaround::Transmit);
    radio.clear_address();
    let deadline = clock.end_time().wrapping_add(LISTEN_US);
    clock.expire_at(deadline);
    let heard = radio.wait_address(|| clock.expired(deadline));
    clock.stop_expiry();
    if !heard {
        radio.disable();
        return None;
    }
    // SAFETY: the radio only reads the decoy, which lives until the event
    // returns; every path out waits until the radio is disabled.
    unsafe { radio.set_buffer(decoy.as_bytes().as_ptr().cast_mut()) }
    radio.clear_ready();
    radio.wait_end();
    let end = clock.end_time();
    let Some(initiator) = radio.crc_ok().then(|| aux_connect_initiator(buffer)).flatten() else {
        radio.disable();
        return None;
    };
    retarget(answer, initiator);
    // SAFETY: as for the decoy; the radio has not read the answer before.
    unsafe { radio.set_buffer(answer.as_bytes().as_ptr().cast_mut()) }
    let late = radio.tx_started();
    if radio::TURNAROUND_IN_ANSWER {
        // The nRF51's DISABLED to TXEN shortcut started the answer a few
        // microseconds after the request's END. Disarmed now, it cannot
        // send the answer again once it ended, however long the check takes.
        radio.wait_switched();
        radio.set_turnaround(Turnaround::None);
    }
    let request = (!late).then(|| accepted_request(settings, buffer)).flatten();
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

/// Time from the end of an `AUX_CONNECT_REQ` on `phy` on air to the end of
/// our `AUX_CONNECT_RSP`, one interframe space later: 342 us on LE 1M,
/// 250 us on LE 2M.
///
/// The request's check has to end within it, or a refusal
/// no longer stops the answer, and the central takes the connection as made
/// (see [`late_connect_decisions`]). The END event the check starts from
/// comes the receive chain's delay later, about 9 us on LE 1M and 5 us on
/// LE 2M on the nRF52832, which leaves about 333 and 245 us from there.
#[inline]
#[must_use = "the time is only computed"]
pub const fn decision_budget_us(phy: Phy) -> u32 { T_IFS_US.strict_add(airtime_us(phy, AUX_CONNECT_RSP_LEN)) }

/// The longest an event of `channels` primaries takes with an auxiliary
/// packet of `aux_len` payload octets on `phy`, from its start until the
/// end of an `AUX_CONNECT_RSP`.
#[inline]
#[must_use = "the time is only computed"]
pub const fn event_us(channels: usize, phy: Phy, aux_len: usize) -> u32 {
    let spacing: u32 = channels.strict_sub(1).strict_cast();
    EVENT_LEAD_US
        .strict_add(tx_ready_us(Phy::M1))
        .strict_add(spacing.strict_mul(PRIMARY_SPACING_US))
        .strict_add(AUX_GAP_US)
        .strict_add(airtime_us(phy, aux_len))
        .strict_add(T_IFS_US)
        .strict_add(airtime_us(phy, usize::from(CONNECT_IND_LEN)))
        .strict_add(T_IFS_US)
        .strict_add(airtime_us(phy, AUX_CONNECT_RSP_LEN))
}

/// The `ADV_EXT_IND` of `settings` with the pointer `aux`.
#[inline]
#[must_use = "the PDU is only built"]
pub fn primary(settings: &Settings, aux: AuxPtr) -> ExtPrimary { ext_primary(settings.adi, aux) }

/// The TXEN of primary `index` in an event whose first primary starts on
/// air at `first`: `index` spacings later, less the LE 1M ramp-up.
#[inline]
#[must_use = "the time is only computed"]
pub const fn primary_txen(first: u32, index: usize) -> u32 {
    let spacings: u32 = index.saturating_cast();
    first.wrapping_add(spacings.saturating_mul(PRIMARY_SPACING_US)).wrapping_sub(tx_ready_us(Phy::M1))
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

/// Time from TXEN until the packet starts on air on `phy`: the fast
/// ramp-up and the TX chain, as in Zephyr's Nordic HAL (41.05 us on LE 1M,
/// 40 us on LE 2M), rounded down.
#[cfg(feature = "nrf52832")]
#[inline]
#[must_use = "the time is only computed"]
pub const fn tx_ready_us(phy: Phy) -> u32 {
    match phy {
        Phy::M1 => 41,
        Phy::M2 => 40,
    }
}

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
