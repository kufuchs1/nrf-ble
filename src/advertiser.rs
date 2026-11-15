//! Connectable advertising and its settings.
//!
//! The settings hold the filter accept list and the resolving list. The
//! advertising event returns the connection request a central sent, with
//! how its connection starts. The PDUs and their event live in the variant
//! module; the link layer uses the items here.

/// Legacy advertising.
pub mod legacy;
/// The filter accept list and the resolving list.
pub mod privacy;

use crate::{
    clock::Clock,
    crypto,
    pdu::{BUFFER_LEN, ConnectInd, Peer},
    radio::{Phy, Radio},
};
use privacy::{FilterList, ResolvingList};

/// Advertising channels with their bit in the channel map.
const CHANNELS: [(u8, u8); 3] = [(37, 0x01), (38, 0x02), (39, 0x04)];
/// Largest advertising data.
pub const DATA_MAX: usize = legacy::DATA_MAX;
/// Time after the end of a packet until a request's access address must have
/// arrived: interframe space, preamble and access address, margin.
const LISTEN_US: u32 = 300;
/// Largest scan response data.
pub const SCAN_DATA_MAX: usize = legacy::SCAN_DATA_MAX;

/// The advertiser's counters as last logged.
pub type Counters = legacy::Counters;
/// Advertising type.
pub type Kind = legacy::Kind;

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
    pub scan_data:          [u8; SCAN_DATA_MAX],
    /// Length of [`Self::scan_data`].
    pub scan_len:           u8,
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
    fn accepts_connection_with<Resolves>(&self, central: Peer, resolves: Resolves) -> bool
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
            channel_map: 0x07,
            data: [0; DATA_MAX],
            filter: FilterList::new(),
            filter_policy: 0,
            interval: 1_280_000,
            kind: Kind::ConnectableUndirected,
            len: 0,
            own: Peer::new([0; 6], true),
            peer: Peer::new([0; 6], false),
            private: false,
            resolving: ResolvingList::new(),
            resolution_enabled: false,
            scan_data: [0; SCAN_DATA_MAX],
            scan_len: 0,
            #[cfg(feature = "directed-advertising")]
            target: Peer::new([0; 6], false),
        }
    }

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
    /// [`SCAN_DATA_MAX`].
    #[inline]
    #[must_use = "data that does not fit is refused"]
    pub fn set_data(&mut self, adv: &[u8], scan: &[u8]) -> bool { legacy::set_data(self, adv, scan) }

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
}

/// Runs one advertising event on the enabled channels.
///
/// Returns the time the event started, in microseconds of the clock, and the
/// connection request it accepted, if any. The time is read once the PDUs are
/// built, right before the first goes out, so that the next event, timed from
/// it, starts an advertising interval after this one however long the PDUs
/// took.
#[inline]
pub fn event(
    radio: &mut Radio<'_>,
    clock: &Clock<'_>,
    settings: &Settings,
    rx: &mut [u8; BUFFER_LEN],
) -> (u32, Option<Accepted>) {
    let (primary, scan_response) = legacy::pdus(settings);
    let started = clock.now();
    let accepted = legacy::event(radio, clock, settings, (&primary, &scan_response), rx)
        .map(|(request, end)| Accepted { end, request, setup: Setup::LEGACY });
    (started, accepted)
}

#[cfg(test)] mod tests;
