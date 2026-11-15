//! Extended advertising, connectable, undirected or directed.
//!
//! An `ADV_EXT_IND` on each enabled primary channel points to one
//! `AUX_ADV_IND` on a secondary channel, with the advertising data and no
//! scan response. This module holds its types and data limits, the renewal
//! of the advertising set's ADI and secondary channel, its PDUs from the
//! settings, and the timing of its event, checked at compile time for LE 1M
//! and, on the nRF52832, LE 2M on the secondary channel.
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

use super::{CHANNELS, LISTEN_US, Settings};
use crate::{
    channel::{Hopping, UsedChannels},
    pdu::{
        AUX_CONNECT_RSP_LEN,
        AUX_DIRECTED_HEADER_LEN,
        AUX_HEADER_LEN,
        AUX_OFFSET_MAX,
        AUX_PAYLOAD_MAX,
        AuxAdvertisement,
        AuxPtr,
        CONNECT_IND_LEN,
        ConnectInd,
        EXT_PRIMARY_LEN,
        ExtPrimary,
        Peer,
        aux_directed,
        aux_undirected,
        ext_primary,
    },
    radio::Phy,
};

/// The shortest advertising interval, 20 ms, which an event has to fit in
/// (Core, Vol 6, Part B, 4.4.2.2.1).
const ADV_INTERVAL_MIN_US: u32 = 20_000;
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

/// The advertiser's counters as last logged: extended advertising counts
/// nothing yet.
#[non_exhaustive]
pub struct Counters;

impl Counters {
    /// Logs the counters that changed since the last call: none yet.
    #[inline]
    pub const fn log(&mut self) {}

    /// No counts logged yet.
    #[inline]
    #[must_use = "the counters are only created"]
    pub const fn new() -> Self { Self }
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
    ConnectInd::parse_aux(pdu, settings.own).filter(|request| settings.accepts_connection(request.central()))
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
