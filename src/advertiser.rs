//! Connectable advertising and its settings.
//!
//! The settings hold the filter accept list and the resolving list. The
//! advertising event returns the connection request a central sent, with
//! how its connection starts. The PDUs and their event live in the variant
//! module, `legacy`, or with the feature `extended-advertising`
//! `extended`, which replaces it: only one is compiled in. The link layer
//! uses the items here.

/// Extended advertising.
#[cfg(feature = "extended-advertising")]
pub mod extended;
/// Legacy advertising.
#[cfg(not(feature = "extended-advertising"))]
pub mod legacy;
/// The filter accept list and the resolving list.
pub mod privacy;

#[cfg(feature = "extended-advertising")]
use crate::pdu::Adi;
use crate::{
    clock::Clock,
    crypto,
    pdu::{ConnectInd, Peer},
    radio::{PacketBuffer, Phy, Radio},
};
#[cfg(feature = "extended-advertising")]
use extended as variant;
#[cfg(not(feature = "extended-advertising"))]
use legacy as variant;
use privacy::{FilterList, ResolvingList};

/// Advertising channels with their bit in the channel map.
const CHANNELS: [(u8, u8); 3] = [(37, 0x01), (38, 0x02), (39, 0x04)];
/// Largest advertising data: 31 octets, or with extended advertising 245
/// on the nRF52832 and 242 on the nRF51 (six less when directed, see
/// `Kind::data_max`).
pub const DATA_MAX: usize = variant::DATA_MAX;
/// Time after the end of a packet until a request's access address must have
/// arrived: interframe space, preamble and access address, margin.
const LISTEN_US: u32 = 300;
/// Largest scan response data: 31 octets, or none with extended
/// advertising.
pub const SCAN_DATA_MAX: usize = variant::SCAN_DATA_MAX;

/// The advertiser's counters as last logged.
pub type Counters = variant::Counters;
/// Advertising type.
pub type Kind = variant::Kind;

/// A connection request the advertising accepted.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct Accepted {
    /// When the request's packet ended, in microseconds of the clock.
    pub end:     u32,
    /// The request.
    pub request: ConnectInd,
    /// How the connection starts.
    pub setup:   Setup,
}

/// Advertising as the host configured it.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct Settings {
    /// Own address as the host set it, the identity address with privacy.
    pub address:            Peer,
    /// The ADI of the advertising set: SID 0 and the advertising data ID,
    /// random and renewed with each change of the data or our address
    /// ([`Self::stale`]).
    #[cfg(feature = "extended-advertising")]
    pub adi:                Adi,
    /// Identifier of channel selection algorithm 2 for the secondary
    /// channel, random and renewed with the advertising data ID.
    #[cfg(feature = "extended-advertising")]
    pub aux_id:             u16,
    /// Advertising channels, bit 0 for channel 37.
    pub channel_map:        u8,
    /// Advertising data.
    pub data:               [u8; DATA_MAX],
    /// Filter accept list.
    pub filter:             FilterList,
    /// Filter policy: bit 0 filters scan requests, bit 1 connection requests.
    pub filter_policy:      u8,
    /// Advertising interval in microseconds.
    pub interval:           u32,
    /// Advertising type.
    pub kind:               Kind,
    /// The ADI of the settings an advertising event last took, which may
    /// have gone on air: a renewal avoids its advertising data ID as well as
    /// the current one, so that two renewals with no event between them
    /// never return to the ID scanners last received (Core, Vol 6, Part B,
    /// 4.4.2.11: not the most recently used value).
    #[cfg(feature = "extended-advertising")]
    pub last_used:          Adi,
    /// Length of [`Self::data`].
    pub len:                u8,
    /// Address on air: [`Self::address`], or a resolvable private address
    /// generated when the advertising starts.
    pub own:                Peer,
    /// Target of directed advertising: its identity, which a connection
    /// request is checked against.
    pub peer:               Peer,
    /// The host asked for a resolvable private address.
    pub private:            bool,
    /// Whether address resolution is enabled by the host.
    pub resolution_enabled: bool,
    /// Peers whose private addresses the filter accept list resolves.
    pub resolving:          ResolvingList,
    /// Scan response data.
    #[cfg(not(feature = "extended-advertising"))]
    pub scan_data:          [u8; SCAN_DATA_MAX],
    /// PHY of the `AUX_ADV_IND`, of the `AUX_CONNECT_REQ` and
    /// `AUX_CONNECT_RSP`, and of the connection's start: LE 1M, or LE 2M on
    /// the nRF52832. The nRF51 takes LE 1M whatever it holds.
    #[cfg(feature = "extended-advertising")]
    pub secondary_phy:      Phy,
    /// Length of [`Self::scan_data`].
    #[cfg(not(feature = "extended-advertising"))]
    pub scan_len:           u8,
    /// The data or our address changed since [`Self::adi`] and
    /// [`Self::aux_id`] were drawn: the link layer task draws new ones
    /// before the next event, which runs only then.
    #[cfg(feature = "extended-advertising")]
    pub stale:              bool,
    /// The target on air of directed advertising: [`Self::peer`], or with a
    /// private address and the peer's key in [`Self::resolving`] a
    /// resolvable private address made with that key when the advertising
    /// starts.
    #[cfg(feature = "directed-advertising")]
    pub target:             Peer,
}

impl Settings {
    /// Whether a central may connect. With the filter accept list, a
    /// resolvable private address counts as the identity it resolves to.
    fn accepts_connection(&self, central: Peer) -> bool { self.accepts_connection_with(central, crypto::resolves) }

    /// [`Self::accepts_connection`], with `resolves` deciding whether an
    /// address resolves with a key.
    pub(crate) fn accepts_connection_with<Resolves>(&self, central: Peer, resolves: Resolves) -> bool
    where
        Resolves: Fn([u8; 16], [u8; 6]) -> bool + Copy,
    {
        if self.resolution_enabled && !self.resolving.accepts_identity(central) {
            return false;
        }
        if self.kind.is_directed() {
            // A central with privacy answers from a resolvable private
            // address of the identity the advertising is directed to, which
            // should differ from the one targeted (Core, Vol 6, Part B, 6.4).
            return central == self.peer || self.resolve_with(central, resolves) == Some(self.peer);
        }
        self.kind.is_connectable()
            && (self.filter_policy & 0x02 == 0
                || self.filter.contains(central)
                || self.resolve_with(central, resolves).is_some_and(|identity| self.filter.contains(identity)))
    }

    /// The defaults after a reset.
    #[inline]
    #[must_use = "the settings are only created"]
    pub const fn new() -> Self {
        Self {
            address: Peer::new([0; 6], true),
            #[cfg(feature = "extended-advertising")]
            adi: Adi::new(0, 0),
            #[cfg(feature = "extended-advertising")]
            aux_id: 0,
            channel_map: 0x07,
            data: [0; DATA_MAX],
            filter: FilterList::new(),
            filter_policy: 0,
            interval: 1_280_000,
            kind: Kind::ConnectableUndirected,
            #[cfg(feature = "extended-advertising")]
            last_used: Adi::new(0, 0),
            len: 0,
            own: Peer::new([0; 6], true),
            peer: Peer::new([0; 6], false),
            private: false,
            resolving: ResolvingList::new(),
            resolution_enabled: false,
            #[cfg(not(feature = "extended-advertising"))]
            scan_data: [0; SCAN_DATA_MAX],
            #[cfg(not(feature = "extended-advertising"))]
            scan_len: 0,
            #[cfg(feature = "extended-advertising")]
            secondary_phy: Phy::M1,
            #[cfg(feature = "extended-advertising")]
            stale: true,
            #[cfg(feature = "directed-advertising")]
            target: Peer::new([0; 6], false),
        }
    }

    /// Gives the advertising set a new advertising data ID and secondary
    /// channel identifier from the random octets `random`, never the last
    /// ID, and clears [`Self::stale`].
    #[cfg(feature = "extended-advertising")]
    #[inline]
    pub const fn renew(&mut self, random: [u8; extended::RENEWAL_LEN]) { extended::renew(self, random); }

    /// Resolves a received private address only when resolution is enabled.
    #[must_use = "the identity is only read"]
    #[inline]
    pub fn resolve(&self, peer: Peer) -> Option<Peer> { self.resolve_with(peer, crypto::resolves) }

    /// [`Self::resolve`], with `resolves` deciding whether an address
    /// resolves with a key.
    fn resolve_with<Resolves>(&self, peer: Peer, resolves: Resolves) -> Option<Peer>
    where
        Resolves: Fn([u8; 16], [u8; 6]) -> bool,
    {
        self.resolution_enabled.then(|| self.resolving.identity(peer, resolves)).flatten()
    }

    /// Sets the advertising data and the scan response data. Returns false,
    /// changing neither, if one is longer than [`DATA_MAX`] or
    /// [`SCAN_DATA_MAX`]. With extended advertising the advertising set then
    /// waits for its renewal (`Settings::stale`).
    #[inline]
    #[must_use = "data that does not fit is refused"]
    pub fn set_data(&mut self, adv: &[u8], scan: &[u8]) -> bool { variant::set_data(self, adv, scan) }

    /// Sets our address on air. With extended advertising, a new one
    /// waits for the renewal of the advertising set (`Settings::stale`), so
    /// that neither its ADI nor its secondary channels link it to the old
    /// one.
    #[inline]
    pub const fn set_own(&mut self, own: Peer) { variant::set_own(self, own); }

    /// The target on air of directed advertising: see [`Self::target`].
    #[cfg(feature = "directed-advertising")]
    const fn target(&self) -> Peer { self.target }

    /// The target on air of directed advertising: the peer's identity.
    #[cfg(not(feature = "directed-advertising"))]
    const fn target(&self) -> Peer { self.peer }
}

impl Default for Settings {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// How a connection starts after its request: the time from the end of the
/// request to the earliest start of the transmit window, before the window
/// offset, and the PHY.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct Setup {
    /// PHY of the connection's first packets both ways.
    pub phy:             Phy,
    /// transmitWindowDelay in microseconds.
    pub window_delay_us: u32,
}

impl Setup {
    /// After a `CONNECT_IND`: 1.25 ms (Core, Vol 6, Part B, 4.5.3), on LE 1M.
    pub const LEGACY: Self = Self { phy: Phy::M1, window_delay_us: 1250 };

    /// After an `AUX_CONNECT_REQ` on `phy`: 2.5 ms from the end of the
    /// request on LE 1M and LE 2M (Core, Vol 6, Part B, 4.5.3), and the
    /// connection starts on `phy` both ways (4.5).
    #[cfg(feature = "extended-advertising")]
    #[inline]
    #[must_use = "the setup is only built"]
    pub const fn aux(phy: Phy) -> Self { Self { phy, window_delay_us: 2500 } }
}

/// Runs one advertising event on the enabled channels.
///
/// Returns the time the event started, in microseconds of the clock, and the
/// connection request it accepted, if any. The time is read once the PDUs are
/// built, right before the first goes out, so that the next event, timed from
/// it, starts an advertising interval after this one however long the PDUs
/// took.
///
/// `counters` carries the advertiser's state from one event to the next.
/// Legacy advertising keeps none there; its event receives a request into
/// `rx`.
#[cfg(not(feature = "extended-advertising"))]
#[inline]
pub fn event(
    radio: &mut Radio<'_>,
    clock: &Clock<'_>,
    settings: &Settings,
    _counters: &mut Counters,
    rx: &mut PacketBuffer,
) -> (u32, Option<Accepted>) {
    let (primary, scan_response) = legacy::pdus(settings);
    let started = clock.now();
    let accepted = legacy::event(radio, clock, settings, (&primary, &scan_response), rx)
        .map(|(request, end)| Accepted { end, request, setup: Setup::LEGACY });
    (started, accepted)
}

/// Runs one extended advertising event on the enabled channels.
///
/// Returns the time the event started, in microseconds of the clock, and the
/// connection request it accepted, if any. The time is read once the PDUs are
/// built, right before the first goes out, so that the next event, timed from
/// it, starts an advertising interval after this one however long the PDUs
/// took.
///
/// `counters` carries the event counter of the secondary channel's
/// selection from one event to the next, and the late counts. The request
/// comes into the buffer of the `AUX_ADV_IND`, which takes any packet the
/// advertising channels admit, not into `rx`.
#[cfg(feature = "extended-advertising")]
#[inline]
pub fn event(
    radio: &mut Radio<'_>,
    clock: &mut Clock<'_>,
    settings: &Settings,
    counters: &mut Counters,
    _rx: &mut PacketBuffer,
) -> (u32, Option<Accepted>) {
    extended::event(radio, clock, settings, counters)
}

#[cfg(test)] mod tests;
