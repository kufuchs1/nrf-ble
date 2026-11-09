//! The typed interface between the link layer and the host.
//!
//! The host in [`crate::host`] talks to the link layer through this module
//! only, with Rust types and no serialised HCI: no command or event is
//! encoded into bytes and parsed again.
//!
//! [`Shared`] is the one static the two sides share: the link layer task
//! ([`crate::controller::run`]) runs in an interrupt executor and the host in
//! thread mode, and every queue, signal and field in it is guarded by a
//! critical section. A [`Link`] is the host's copyable handle on it. Each of
//! its calls holds the critical section only for a few field copies, as the
//! link layer has to answer within the 150 us interframe space; the RNG and
//! AES work of a resolvable private address runs outside of it.
//!
//! # Links and epochs
//!
//! Each connection has an [`Epoch`], which [`Event::Connected`] and
//! [`Link::info`] carry. A request for a link ([`Link::try_send`],
//! [`Link::ltk_reply`], [`Link::disconnect`] and the others that take an
//! epoch) names the link it was meant for: one for a link that has ended
//! returns [`Error::Gone`] and has no effect on the next link.
//!
//! # Order of what the host receives
//!
//! [`Link::next`] returns events ([`Rx::Event`]) and received ACL fragments
//! ([`Rx::Acl`]) from two queues. They are not one FIFO, and the host may
//! rely on these guarantees only:
//!
//! - [`Event::Connected`] comes before the first fragment of its link: the link
//!   layer receives no data while that event waits for room.
//! - [`Event::Disconnected`] comes after the last fragment of its link: the
//!   link layer queues it only once the host has read every fragment it
//!   acknowledged.
//! - Each [`AclIn`] says whether its PDU was received encrypted. Encrypted data
//!   can reach the host before [`Event::Encryption`], so a security check takes
//!   the level from that flag and from the key the host handed over itself, not
//!   from the order of the two.
//!
//! The event queue holds [`EVENT_QUEUE`] events, as the thread executor stalls
//! for about 3 s during a P-256 multiplication. The connection keeps three
//! more until the queue has room, and ends the link with a hardware failure
//! (0x03) if a fourth one does not fit.
//!
//! # Sending
//!
//! [`Link::try_send`] queues one fragment of an L2CAP message without
//! waiting, [`Link::send`] waits for room. [`Link::tx_room`] gives the free
//! room, [`Link::tx_room_changed`] waits until the link layer took a fragment
//! from the queue or the central acknowledged some, and [`Link::in_flight`]
//! counts the fragments of the link
//! that the central has not acknowledged yet, so the host can keep at most
//! one notification unacknowledged.
//!
//! # Peripheral latency
//!
//! The link layer skips connection events as the peripheral latency allows
//! only while the link is quiet: never during the first second of a link,
//! never within [`LATENCY_HOLD_US`] or [`LATENCY_HOLD_EVENTS`] events,
//! whichever is longer, after a PDU with a payload in either direction, and
//! never while the host holds it with [`Link::hold_latency`]. A request of
//! the central is then answered at the next event, not up to the latency
//! later.

use crate::{
    advertiser::legacy::{DATA_MAX, FILTER_LIST_SIZE, Kind, Settings as LegacySettings},
    crypto,
    log::info,
    pdu::{Llid, Peer, valid_connection_parameters},
};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, AtomicI8, Ordering},
};
use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    channel::Channel,
    signal::Signal,
};
use embassy_time::{Duration, Instant};

/// Devices the filter accept list holds.
pub const ACCEPT_LIST_SIZE: usize = FILTER_LIST_SIZE;
/// Largest ACL fragment each way: 251 octets with the data length extension,
/// otherwise 27.
pub const ACL_MAX: usize = if cfg!(feature = "data-length") { 251 } else { 27 };
/// Default data length: payload octets and time in microseconds.
pub const LENGTH_DEFAULT: [u16; 2] = [27, 328];
/// Largest data length this side supports: payload octets and time.
pub const LENGTH_MAX: [u16; 2] = if cfg!(feature = "data-length") { [251, 2120] } else { LENGTH_DEFAULT };
/// Fragments from the host the link layer queues for the air.
pub const ACL_OUT_BUFFERS: usize = if cfg!(feature = "data-length") { 2 } else { 4 };
/// Received fragments the link layer queues for the host.
pub const ACL_IN_BUFFERS: usize = 2;
/// Events the link layer queues for the host.
pub const EVENT_QUEUE: usize = 6;
/// Shortest time without a skipped connection event after a PDU with a
/// payload in either direction, in microseconds.
pub const LATENCY_HOLD_US: u32 = 200_000;
/// Fewest connection events without a skipped one after a PDU with a
/// payload in either direction.
pub const LATENCY_HOLD_EVENTS: u32 = 8;
/// Time from the start of a link during which no connection event is
/// skipped, in microseconds.
pub const LATENCY_HOLD_START_US: u32 = 1_000_000;

/// Read RSSI value while no packet was received.
const RSSI_UNKNOWN: i8 = 127;
/// Default authenticated payload timeout in units of 10 ms.
const DEFAULT_PAYLOAD_TIMEOUT: u16 = 3000;
/// Lifetime of a resolvable private address, as the Core suggests.
const PRIVATE_ADDRESS_TIMEOUT: Duration = Duration::from_secs(900);
/// Longest lifetime of a resolvable private address in seconds.
const PRIVATE_ADDRESS_TIMEOUT_MAX: u16 = 0x0E10;
/// Shortest advertising interval in units of 0.625 ms.
const ADV_INTERVAL_MIN: u16 = 0x0020;
/// Longest advertising interval in units of 0.625 ms.
const ADV_INTERVAL_MAX: u16 = 0x4000;
/// Disconnection reasons the host may give (Core, Vol 4, Part E, 7.1.6):
/// authentication failure, remote user, low resources, power off,
/// unsupported remote feature, pairing with unit key not supported and
/// unacceptable connection parameters.
const DISCONNECT_REASONS: [u8; 7] = [0x05, 0x13, 0x14, 0x15, 0x1A, 0x29, 0x3B];
/// Host query bit: the central's features.
pub(crate) const QUERY_FEATURES: u8 = 0x01;
/// Host query bit: the central's version.
pub(crate) const QUERY_VERSION: u8 = 0x02;
/// Host query bit: a PHY update the host asked for.
pub(crate) const QUERY_PHY: u8 = 0x04;
/// Host query bit: a connection update the host asked for.
const QUERY_CONNECTION_UPDATE: u8 = 0x08;
/// Host query bit: a central's connection parameter request the host is
/// asked about.
const QUERY_REMOTE_PARAMETERS: u8 = 0x10;

/// Why the link layer refused a request of the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Error {
    /// Not now: advertising runs, a procedure of the same kind runs, the
    /// request answers nothing that was asked, or a connection exists.
    Disallowed,
    /// The list or the queue is full.
    Full,
    /// The link the request names has ended, or there is no link.
    Gone,
    /// A parameter is out of range.
    Invalid,
    /// The chip lacks it: LE 2M and LE Coded on the nRF51.
    Unsupported,
    /// The central lacks the procedure the request needs: a connection
    /// parameter request then goes through the L2CAP signalling channel.
    UnsupportedRemote,
}

/// One connection. A request with the epoch of a link that has ended has
/// no effect on the next one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Epoch(u32);

impl Epoch {
    /// The epoch with the generation `value`, for tests.
    #[cfg(test)]
    pub(crate) const fn for_test(value: u32) -> Self { Self(value) }
}

/// Connection parameters in link layer units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct ConnectionParams {
    /// Interval in units of 1.25 ms.
    pub interval: u16,
    /// Peripheral latency in events.
    pub latency:  u16,
    /// Supervision timeout in units of 10 ms.
    pub timeout:  u16,
}

impl ConnectionParams {
    /// Parameters from their link layer units.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn new(interval: u16, latency: u16, timeout: u16) -> Self { Self { interval, latency, timeout } }
}

/// Connection parameters one side asks for, in link layer units.
///
/// The interval range, the peripheral latency and the supervision timeout.
/// The same range serves the link layer procedure, the L2CAP request and the
/// peripheral preferred connection parameters characteristic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct ParamRange {
    /// Longest interval in units of 1.25 ms.
    pub interval_max: u16,
    /// Shortest interval in units of 1.25 ms.
    pub interval_min: u16,
    /// Peripheral latency in events.
    pub latency:      u16,
    /// Supervision timeout in units of 10 ms.
    pub timeout:      u16,
}

impl ParamRange {
    /// The four values in the order the link layer PDUs carry them.
    const fn fields(self) -> [u16; 4] { [self.interval_min, self.interval_max, self.latency, self.timeout] }

    /// Whether the range is within the ranges of the specification: an
    /// interval of 7.5 ms to 4 s, a latency and a timeout that fit it.
    fn is_valid(self) -> bool {
        self.interval_min <= self.interval_max
            && self.interval_min >= 6
            && valid_connection_parameters(self.interval_max, self.latency, self.timeout, 1, 0)
    }

    /// A range from its link layer units.
    #[inline]
    #[must_use = "the range is only built"]
    pub const fn new(interval_min: u16, interval_max: u16, latency: u16, timeout: u16) -> Self {
        Self { interval_max, interval_min, latency, timeout }
    }
}

/// What the host learns about a link when it starts.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct Info {
    /// The central's sleep clock accuracy as the connection request gave it.
    pub central_accuracy: u8,
    /// The link.
    pub epoch:            Epoch,
    /// The central's identity address, if its address on the air is a
    /// resolvable private address of a peer in the resolving list.
    pub identity:         Option<Peer>,
    /// Our own address on the air, which the central connected to: the
    /// resolvable private address, or the identity address without privacy.
    pub local:            Peer,
    /// The connection parameters the link started with.
    pub params:           ConnectionParams,
    /// The central's address on the air, with its type (`InitA` and
    /// `TxAdd` of the connection request). Pairing uses this address and
    /// [`Self::local`], not the identities.
    pub peer:             Peer,
}

/// An event of the link layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Event {
    /// High duty cycle directed advertising ended without a connection.
    AdvertisingTimeout,
    /// A central connected; [`Link::info`] has the details.
    Connected(Epoch),
    /// The effective data length changed: transmit octets and time, receive
    /// octets and time.
    DataLength([u16; 4]),
    /// The link ended, with the reason.
    Disconnected(u8),
    /// Encryption started (`on`), failed or, with `refresh`, a key refresh
    /// completed, with the status.
    Encryption {
        /// The link is encrypted.
        on:      bool,
        /// A key refresh of an encrypted link, not its first encryption.
        refresh: bool,
        /// Zero on success, the error code otherwise.
        status:  u8,
    },
    /// The central asks for the long term key, with the random number and
    /// diversifier of its request; answer with [`Link::ltk_reply`].
    LtkRequest {
        /// The encrypted diversifier.
        ediv: u16,
        /// The random number, least significant octet first.
        rand: [u8; 8],
    },
    /// The central asks for these connection parameters; answer with
    /// [`Link::reply_params`]. Only with [`Link::set_host_decides_params`].
    ParamsRequested(ParamRange),
    /// The connection parameters changed, or a request of the host for them
    /// ended with the status.
    ParamsUpdated {
        /// The parameters now in use.
        params: ConnectionParams,
        /// Zero on success, the error code otherwise.
        status: u8,
    },
    /// No packet with a valid MIC came within the authenticated payload
    /// timeout.
    PayloadTimeout,
    /// The PHY changed, or a request of the host for one ended with the
    /// status: the receive and transmit PHY, 1 for LE 1M and 2 for LE 2M.
    PhyUpdated {
        /// The receive PHY.
        rx:     u8,
        /// Zero on success, the error code otherwise.
        status: u8,
        /// The transmit PHY.
        tx:     u8,
    },
    /// The central's features, as [`Link::read_remote_features`] asked.
    RemoteFeatures {
        /// The features, zero after an error.
        features: [u8; 8],
        /// Zero on success, the error code otherwise.
        status:   u8,
    },
    /// The central's version, company and subversion, as
    /// [`Link::read_remote_version`] asked.
    RemoteVersion([u8; 5]),
}

#[expect(clippy::rest_pattern_accessible_field, reason = "the events are matched by variant only")]
impl Event {
    /// Whether this starts a link.
    pub(crate) const fn is_connected(&self) -> bool { matches!(self, Self::Connected(_)) }

    /// Whether this reports connection parameters.
    pub(crate) const fn is_params_update(&self) -> bool { matches!(self, Self::ParamsUpdated { .. }) }

    /// Whether this reports a PHY.
    pub(crate) const fn is_phy_update(&self) -> bool { matches!(self, Self::PhyUpdated { .. }) }
}

/// A received ACL fragment.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AclIn {
    /// Payload.
    data:      [u8; ACL_MAX],
    /// Whether the PDU was received encrypted, with a valid MIC.
    encrypted: bool,
    /// Payload length.
    len:       u8,
    /// Whether it starts an L2CAP message.
    start:     bool,
}

impl AclIn {
    /// A fragment of `payload`, which `start`s an L2CAP message or not and
    /// was received `encrypted` or not, for tests.
    #[cfg(test)]
    pub(crate) fn for_test(start: bool, encrypted: bool, payload: &[u8]) -> Self {
        let mut data = [0; ACL_MAX];
        data[..payload.len()].copy_from_slice(payload);
        Self { data, encrypted, len: u8::try_from(payload.len()).unwrap(), start }
    }

    /// Whether the PDU was received encrypted, with a valid MIC. Set when
    /// the link layer received it, so it holds even if the host learns of
    /// the encryption later.
    #[inline]
    #[must_use = "the flag is only read"]
    pub const fn encrypted(&self) -> bool { self.encrypted }

    /// The payload.
    #[inline]
    #[must_use = "the payload is only read"]
    pub fn payload(&self) -> &[u8] { self.data.get(..usize::from(self.len)).unwrap_or_default() }

    /// Whether it starts an L2CAP message rather than continuing one.
    #[inline]
    #[must_use = "the flag is only read"]
    pub const fn start(&self) -> bool { self.start }
}

/// What [`Link::next`] returns.
#[derive(Clone, Copy)]
#[non_exhaustive]
#[cfg_attr(
    feature = "data-length",
    expect(clippy::large_enum_variant, reason = "returned by value from the queue, without a heap to box it")
)]
pub enum Rx {
    /// A received ACL fragment.
    Acl(AclIn),
    /// An event.
    Event(Event),
}

/// An ACL fragment from the host for the air.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AclOut {
    /// Payload.
    pub data:  [u8; ACL_MAX],
    /// Connection generation owning this fragment.
    pub epoch: u32,
    /// Payload length.
    pub len:   u8,
    /// Start or continuation of an L2CAP message.
    pub llid:  Llid,
}

/// Advertising parameters.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AdvParams {
    /// Advertising channels, bit 0 for channel 37.
    pub channel_map:   u8,
    /// Filter policy: bit 0 limits scan responses, bit 1 connections, to the
    /// filter accept list.
    pub filter_policy: u8,
    /// Interval in units of 0.625 ms; high duty cycle directed advertising
    /// uses its own.
    pub interval:      u16,
    /// Advertising type.
    pub kind:          Kind,
    /// The peer of directed advertising, and whose local key gives the
    /// resolvable private address.
    pub peer:          Peer,
    /// Advertise from a resolvable private address made with the local key
    /// in the resolving list, rather than from the identity address.
    pub private:       bool,
}

impl AdvParams {
    /// With an advertising channel map.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn channel_map(self, channel_map: u8) -> Self { Self { channel_map, ..self } }

    /// With a filter policy.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn filter_policy(self, filter_policy: u8) -> Self { Self { filter_policy, ..self } }

    /// With an interval in units of 0.625 ms.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn interval(self, interval: u16) -> Self { Self { interval, ..self } }

    /// Whether the parameters are in range.
    fn is_valid(&self) -> bool {
        let interval_valid =
            self.kind == Kind::DirectedHighDuty || (ADV_INTERVAL_MIN..=ADV_INTERVAL_MAX).contains(&self.interval);
        interval_valid && (1..=0x07).contains(&self.channel_map) && self.filter_policy <= 3
    }

    /// Advertising of `kind` on all three channels every 1.28 s, from the
    /// identity address and without a filter.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn new(kind: Kind) -> Self {
        Self {
            channel_map: 0x07,
            filter_policy: 0,
            interval: 0x0800,
            kind,
            peer: Peer::new([0; 6], false),
            private: false,
        }
    }

    /// With the peer of directed advertising.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn peer(self, peer: Peer) -> Self { Self { peer, ..self } }

    /// From a resolvable private address or not.
    #[inline]
    #[must_use = "the parameters are only built"]
    pub const fn private(self, private: bool) -> Self { Self { private, ..self } }
}

/// Host state kept by the link layer.
struct HostState {
    /// Fragments of the link the central acknowledged.
    acked:            u32,
    /// Host query bits already accepted but not completed.
    active_queries:   u8,
    /// Whether a connection exists.
    connected:        bool,
    /// Changes at each link boundary so requests cannot cross links.
    epoch:            u32,
    /// What the host learns about the current link.
    info:             Option<Info>,
    /// Legacy advertising parameters.
    legacy:           LegacySettings,
    /// Whether the host enabled legacy advertising.
    legacy_enabled:   bool,
    /// An LTK request waits for the host's answer.
    ltk_pending:      bool,
    /// Connection updates the host asked for while it answered a central's
    /// request, each owed a completion when that ends.
    merged_updates:   u8,
    /// Authenticated payload timeout in units of 10 ms.
    payload_timeout:  u16,
    /// Accepted host PHY request.
    phy_pending:      Option<[u8; 2]>,
    /// Current receive and transmit PHY, updated at the instant.
    phys:             [u8; 2],
    /// Default transmit and receive PHY preferences.
    preferred_phys:   [u8; 2],
    /// The last resolvable private address, the key it was made with and
    /// when it expires. Advertising keeps it until then.
    private_address:  Option<(Peer, [u8; 16], Instant)>,
    /// Lifetime of a resolvable private address.
    private_timeout:  Duration,
    /// Host requests waiting for the link layer (features and version).
    queries:          u8,
    /// First byte of the central's features, zero until known.
    remote_features:  u8,
    /// Fragments of the link the host queued.
    sent:             u32,
    /// Data length new links start with: payload octets and time.
    suggested_length: [u16; 2],
}

impl HostState {
    /// A private address is reusable only with the same key, before expiry.
    fn cached_address(&self, key: [u8; 16], now: Instant) -> Option<Peer> {
        let (address, made_with, expires) = self.private_address?;
        (made_with == key && now < expires).then_some(address)
    }

    /// The epoch if it names the current link.
    const fn current(&self, epoch: Epoch) -> Result<(), Error> {
        if self.connected && self.epoch == epoch.0 { Ok(()) } else { Err(Error::Gone) }
    }

    /// Overwrites the cached resolvable private address and its key.
    fn forget_address(&mut self) {
        if let Some(&mut (_, ref mut key, _)) = self.private_address.as_mut() {
            crypto::wipe(key);
        }
        self.private_address = None;
    }

    /// Overwrites every identity resolving key before it is dropped.
    fn forget_keys(&mut self) {
        self.forget_address();
        self.legacy.resolving.clear();
    }

    /// The state after power-on or a reset, in the generation `epoch`.
    const fn new(epoch: u32) -> Self {
        Self {
            acked: 0,
            active_queries: 0,
            connected: false,
            epoch,
            info: None,
            legacy: LegacySettings::new(),
            legacy_enabled: false,
            ltk_pending: false,
            merged_updates: 0,
            payload_timeout: DEFAULT_PAYLOAD_TIMEOUT,
            phy_pending: None,
            phys: [1, 1],
            preferred_phys: [2, 2],
            private_address: None,
            private_timeout: PRIVATE_ADDRESS_TIMEOUT,
            queries: 0,
            remote_features: 0,
            sent: 0,
            suggested_length: LENGTH_DEFAULT,
        }
    }
}

/// State shared between the host and the link layer.
pub struct Shared {
    /// ACL data received from the air.
    acl_in:          Channel<CriticalSectionRawMutex, AclIn, ACL_IN_BUFFERS>,
    /// ACL data from the host for the air.
    acl_out:         Channel<CriticalSectionRawMutex, AclOut, ACL_OUT_BUFFERS>,
    /// The host read ACL data from the air.
    acl_taken:       Signal<CriticalSectionRawMutex, ()>,
    /// Advertising settings changed.
    changed:         Signal<CriticalSectionRawMutex, ()>,
    /// Data length the host set for the link: payload octets and time.
    data_length:     Signal<CriticalSectionRawMutex, [u16; 2]>,
    /// Disconnection requested by the host, with the reason.
    disconnect:      Signal<CriticalSectionRawMutex, u8>,
    /// Events for the host.
    events:          Channel<CriticalSectionRawMutex, Event, EVENT_QUEUE>,
    /// The host holds the peripheral latency off.
    hold_latency:    AtomicBool,
    /// The host decides on a central's connection parameter requests.
    host_decides:    AtomicBool,
    /// Long term key from the host, `None` if it has none.
    ltk:             Signal<CriticalSectionRawMutex, Option<[u8; 16]>>,
    /// Connection parameters the host asks the central for.
    param_request:   Signal<CriticalSectionRawMutex, [u16; 4]>,
    /// The host's answer to a central's connection parameter request: the
    /// parameters to offer, or the reason to reject it.
    parameter_reply: Signal<CriticalSectionRawMutex, Result<[u16; 4], u8>>,
    /// Reset handshake with the radio executor.
    reset:           Signal<CriticalSectionRawMutex, ()>,
    /// Radio reset completion.
    reset_done:      Signal<CriticalSectionRawMutex, ()>,
    /// Received signal strength of the link in dBm, averaged; 127 while
    /// unknown.
    rssi:            AtomicI8,
    /// Host state.
    state:           Mutex<CriticalSectionRawMutex, RefCell<HostState>>,
    /// The link layer took a fragment from the host's queue.
    tx_room:         Signal<CriticalSectionRawMutex, ()>,
    /// Something for the connection arrived from the host.
    wakeup:          Signal<CriticalSectionRawMutex, ()>,
}

impl Default for Shared {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl Shared {
    /// Counts fragments of the link the central acknowledged.
    pub(crate) fn acknowledged(&self, count: u16) {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.acked = state.acked.wrapping_add(u32::from(count));
        });
        // The host paces by the fragments in flight, which only an
        // acknowledgement lowers: the link layer counts them after the
        // connection event, when no fragment may be taken any more.
        if count != 0 {
            self.tx_room.signal(());
        }
    }

    /// Waits until the host read all ACL data received from the air, so
    /// none is lost when a link ends.
    pub(crate) async fn acl_in_drained(&self) {
        while !self.acl_in.is_empty() {
            self.acl_taken.wait().await;
        }
    }

    /// Free places for ACL data towards the host.
    pub(crate) fn acl_room(&self) -> usize { self.acl_in.free_capacity() }

    /// The advertising to run, if the host enabled it and no connection
    /// exists.
    pub(crate) fn advertising(&self) -> Option<LegacySettings> {
        self.state.lock(|cell| {
            let state = cell.borrow();
            (!state.connected && state.legacy_enabled).then_some(state.legacy)
        })
    }

    /// Passes a central's connection parameter request to the host, which
    /// answers with [`Link::reply_params`].
    pub(crate) fn ask_parameters(&self) {
        self.parameter_reply.reset();
        self.state.lock(|cell| cell.borrow_mut().active_queries |= QUERY_REMOTE_PARAMETERS);
    }

    /// Waits until the advertising settings change.
    pub(crate) async fn changed(&self) { self.changed.wait().await; }

    /// Releases a host query once its result is retained for delivery.
    pub(crate) fn complete_query(&self, bit: u8) { self.state.lock(|cell| cell.borrow_mut().active_queries &= !bit); }

    /// Completes a reset once the radio has stopped and the link keys are
    /// wiped.
    pub(crate) fn complete_reset(&self) {
        self.set_connected(false);
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.forget_keys();
            *state = HostState::new(state.epoch.wrapping_add(1));
        });
        self.hold_latency.store(false, Ordering::Relaxed);
        self.host_decides.store(false, Ordering::Relaxed);
        while self.events.try_receive().is_ok() {}
        while self.acl_in.try_receive().is_ok() {}
        self.reset_done.signal(());
    }

    /// Ends a central's connection parameter request the host was asked
    /// about, answered or not.
    pub(crate) fn end_parameter_request(&self) { self.complete_query(QUERY_REMOTE_PARAMETERS); }

    /// Lets the host start another connection update once the current one
    /// reported its outcome.
    pub(crate) fn finish_param_request(&self) { self.complete_query(QUERY_CONNECTION_UPDATE); }

    /// Whether ACL data from the host waits for the air.
    pub(crate) fn has_acl_out(&self) -> bool { !self.acl_out.is_empty() }

    /// Whether the host decides on a central's connection parameter
    /// requests. Otherwise the link layer accepts them.
    pub(crate) fn host_decides_parameters(&self) -> bool { self.host_decides.load(Ordering::Relaxed) }

    /// Whether the host holds the peripheral latency off.
    pub(crate) fn latency_held(&self) -> bool { self.hold_latency.load(Ordering::Relaxed) }

    /// Creates the shared state.
    #[inline]
    #[must_use = "the state is only created"]
    pub const fn new() -> Self {
        Self {
            acl_in:          Channel::new(),
            acl_out:         Channel::new(),
            acl_taken:       Signal::new(),
            changed:         Signal::new(),
            data_length:     Signal::new(),
            disconnect:      Signal::new(),
            events:          Channel::new(),
            hold_latency:    AtomicBool::new(false),
            host_decides:    AtomicBool::new(false),
            ltk:             Signal::new(),
            param_request:   Signal::new(),
            parameter_reply: Signal::new(),
            reset:           Signal::new(),
            reset_done:      Signal::new(),
            rssi:            AtomicI8::new(RSSI_UNKNOWN),
            state:           Mutex::new(RefCell::new(HostState::new(0))),
            tx_room:         Signal::new(),
            wakeup:          Signal::new(),
        }
    }

    /// Takes the next ACL fragment of the current link for the air, if one
    /// is waiting; fragments of a link that ended are dropped.
    pub(crate) fn next_acl_out(&self) -> Option<AclOut> {
        let packet = self.state.lock(|cell| {
            let state = cell.borrow();
            while let Ok(packet) = self.acl_out.try_receive() {
                if state.connected && packet.epoch == state.epoch {
                    return Some(packet);
                }
            }
            None
        });
        if packet.is_some() {
            self.tx_room.signal(());
        }
        packet
    }

    /// A stable own address for advertising, without holding interrupts off
    /// during RNG and AES: the resolvable private address made with
    /// `private_key`, or the identity address without one. Both the host
    /// and the link layer may call it: the link layer can only preempt the
    /// host, and whichever address is cached last is the one advertising
    /// moves to at its next event.
    fn own_address(&self, private_key: Option<[u8; 16]>) -> Peer {
        let (fallback, lifetime) = self.state.lock(|cell| {
            let state = cell.borrow();
            (state.legacy.address, state.private_timeout)
        });
        let Some(key) = private_key else { return fallback };
        let now = Instant::now();
        if let Some(address) = self.state.lock(|cell| cell.borrow().cached_address(key, now)) {
            return address;
        }
        let mut prand = [0; 3];
        crate::rng::fill(&mut prand);
        let address = Peer::new(crypto::resolvable_address(key, prand), true);
        self.state.lock(|cell| {
            cell.borrow_mut().private_address = Some((address, key, now.saturating_add(lifetime)));
        });
        address
    }

    /// The authenticated payload timeout in microseconds.
    pub(crate) fn payload_timeout(&self) -> u32 {
        self.state.lock(|cell| u32::from(cell.borrow().payload_timeout).saturating_mul(10_000))
    }

    /// Default PHY preference for new connections.
    pub(crate) fn preferred_phys(&self) -> [u8; 2] { self.state.lock(|cell| cell.borrow().preferred_phys) }

    /// The key of the resolvable private address the current advertising
    /// settings ask for, if any.
    fn private_key(&self) -> Option<[u8; 16]> {
        self.state.lock(|cell| {
            let state = cell.borrow();
            let legacy = &state.legacy;
            legacy.resolving.local_key(legacy.kind.is_directed().then_some(legacy.peer)).filter(|_| legacy.private)
        })
    }

    /// Passes received ACL data to the host, with whether it was received
    /// encrypted. Returns false if there is no room.
    pub(crate) fn push_acl_in(&self, llid: Llid, payload: &[u8], encrypted: bool) -> bool {
        let mut data = [0_u8; ACL_MAX];
        let len = payload.len().min(ACL_MAX);
        if let (Some(target), Some(source)) = (data.get_mut(..len), payload.get(..len)) {
            target.copy_from_slice(source);
        }
        let start = llid != Llid::Continuation;
        self.acl_in.try_send(AclIn { data, encrypted, len: u8::try_from(len).unwrap_or(u8::MAX), start }).is_ok()
    }

    /// Queues an event for the host, waiting for room.
    pub(crate) async fn push_event(&self, event: Event) { self.events.send(event).await; }

    /// Queues ACL data from the host for the air, as [`Link::try_send`]
    /// does.
    #[cfg(test)]
    pub(crate) fn queue_acl_for_test(&self, payload: &[u8]) -> bool {
        let epoch = self.state.lock(|cell| cell.borrow().epoch);
        Link::new(self).try_send(Epoch(epoch), true, payload).is_ok()
    }

    /// Moves running advertising to a new resolvable private address once
    /// the current one expired, so a device that advertises for long cannot
    /// be followed by its address. Call it before each advertising event,
    /// outside radio events.
    pub(crate) fn refresh_private_address(&self) {
        let enabled = self.state.lock(|cell| cell.borrow().legacy_enabled);
        let Some(key) = self.private_key().filter(|_| enabled) else { return };
        let address = self.own_address(Some(key));
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.legacy_enabled && state.legacy.private && state.legacy.own != address {
                state.legacy.own = address;
                info!("new private address");
            }
        });
    }

    /// Queues a key request and authorizes one answer of the host. Returns
    /// false if there is no room for the event.
    pub(crate) fn request_ltk(&self, rand: [u8; 8], ediv: [u8; 2]) -> bool {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if !state.connected || state.ltk_pending {
                return false;
            }
            if self.events.try_send(Event::LtkRequest { ediv: u16::from_le_bytes(ediv), rand }).is_err() {
                return false;
            }
            state.ltk_pending = true;
            true
        })
    }

    /// Queues a connection parameter request as [`Link::request_params`]
    /// does, without its checks.
    #[cfg(test)]
    pub(crate) fn request_params(&self, params: [u16; 4]) { self.param_request.signal(params); }

    /// Queues host information queries in state machine tests.
    #[cfg(test)]
    pub(crate) fn request_queries(&self, bits: u8) { self.state.lock(|cell| cell.borrow_mut().queries |= bits); }

    /// Waits for a reset, also while radio clean-up waits for the host.
    pub(crate) async fn reset_requested(&self) { self.reset.wait().await; }

    /// Forgets earlier wakeups.
    pub(crate) fn reset_wakeup(&self) { self.wakeup.reset(); }

    /// Records the start or end of the connection. Advertising stops when a
    /// connection starts.
    pub(crate) fn set_connected(&self, connected: bool) {
        let changed = self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let changed = state.connected != connected;
            if changed {
                state.epoch = state.epoch.wrapping_add(1);
                state.ltk_pending = false;
                state.remote_features = 0;
                state.queries = 0;
                state.active_queries = 0;
                state.phys = [1, 1];
                state.phy_pending = None;
                // Per link (Core, Vol 4, Part E, 7.3.94): every link starts
                // with the default.
                state.payload_timeout = DEFAULT_PAYLOAD_TIMEOUT;
                state.merged_updates = 0;
                state.sent = 0;
                state.acked = 0;
                state.info = None;
            }
            state.connected = connected;
            if connected {
                state.legacy_enabled = false;
            }
            changed
        });
        if changed {
            // Requests of the host for the link that ended, or for a link
            // before this one.
            self.disconnect.reset();
            self.ltk.reset();
            self.param_request.reset();
            self.parameter_reply.reset();
            self.data_length.reset();
            self.rssi.store(RSSI_UNKNOWN, Ordering::Relaxed);
        }
        if !connected {
            // Received data stays for the host, which the controller lets
            // read it before the disconnection event.
            while self.acl_out.try_receive().is_ok() {}
            self.wakeup.reset();
            self.tx_room.signal(());
        }
    }

    /// Records what the host learns about the link that just started, from
    /// the central's address on the air, our own, the parameters and the
    /// central's clock accuracy. Returns the link's epoch.
    pub(crate) fn set_info(
        &self,
        (peer, identity, local): (Peer, Option<Peer>, Peer),
        params: ConnectionParams,
        central_accuracy: u8,
    ) -> Epoch {
        self.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            let epoch = Epoch(state.epoch);
            state.info = Some(Info { central_accuracy, epoch, identity, local, params, peer });
            epoch
        })
    }

    /// Publishes the current receive and transmit PHY.
    pub(crate) fn set_phys(&self, rx: u8, tx: u8) { self.state.lock(|cell| cell.borrow_mut().phys = [rx, tx]); }

    /// Records the first feature byte of the central, which decides whether
    /// the connection parameters request procedure can be used.
    pub(crate) fn set_remote_features(&self, features: u8) {
        self.state.lock(|cell| cell.borrow_mut().remote_features = features);
    }

    /// Publishes the averaged signal strength of the link.
    pub(crate) fn set_rssi(&self, dbm: Option<i32>) {
        let value =
            dbm.map_or(RSSI_UNKNOWN, |level| i8::try_from(level.clamp(-127_i32, 20_i32)).unwrap_or(RSSI_UNKNOWN));
        self.rssi.store(value, Ordering::Relaxed);
    }

    /// Wakes the link layer for a reset, also from waits for the host.
    pub(crate) fn signal_reset(&self) {
        self.reset.signal(());
        self.changed.signal(());
        self.wakeup.signal(());
    }

    /// Ends advertising that ran out of time.
    pub(crate) fn stop_advertising(&self) { self.state.lock(|cell| cell.borrow_mut().legacy_enabled = false); }

    /// Data length new links start with: payload octets and time.
    pub(crate) fn suggested_length(&self) -> [u16; 2] { self.state.lock(|cell| cell.borrow().suggested_length) }

    /// Takes the next received fragment for the host.
    #[cfg(test)]
    pub(crate) fn take_acl_in(&self) -> Option<AclIn> {
        let acl = self.acl_in.try_receive().ok();
        self.acl_taken.signal(());
        acl
    }

    /// Takes a data length the host set for the link.
    pub(crate) fn take_data_length(&self) -> Option<[u16; 2]> { self.data_length.try_take() }

    /// Takes a pending disconnection request.
    pub(crate) fn take_disconnect(&self) -> Option<u8> { self.disconnect.try_take() }

    /// Takes the next event for the host.
    #[cfg(test)]
    pub(crate) fn take_event(&self) -> Option<Event> { self.events.try_receive().ok() }

    /// Takes the host's answer to a long term key request: `None` while
    /// none came, `Some(None)` for a host without a key.
    #[expect(clippy::option_option, reason = "no answer differs from the answer that there is no key")]
    pub(crate) fn take_ltk(&self) -> Option<Option<[u8; 16]>> { self.ltk.try_take() }

    /// Takes the number of connection updates that were part of the host's
    /// answer to a central's request, each owed a completion now that the
    /// central's procedure ended.
    pub(crate) fn take_merged_updates(&self) -> u8 {
        self.state.lock(|cell| core::mem::take(&mut cell.borrow_mut().merged_updates))
    }

    /// Takes connection parameters the host asks the central for.
    pub(crate) fn take_param_request(&self) -> Option<[u16; 4]> { self.param_request.try_take() }

    /// Takes the host's answer to a central's connection parameter request.
    pub(crate) fn take_parameter_reply(&self) -> Option<Result<[u16; 4], u8>> { self.parameter_reply.try_take() }

    /// Takes a transmit and receive PHY preference the host asked for.
    pub(crate) fn take_phy_request(&self) -> Option<[u8; 2]> {
        self.state.lock(|cell| cell.borrow_mut().phy_pending.take())
    }

    /// Takes the host's queries for the central's features and version.
    pub(crate) fn take_queries(&self) -> u8 { self.state.lock(|cell| core::mem::take(&mut cell.borrow_mut().queries)) }

    /// Takes a pending host reset at a radio-safe boundary.
    pub(crate) fn take_reset(&self) -> bool { self.reset.try_take().is_some() }

    /// Queues an event for the host. Returns false if there is no room.
    pub(crate) fn try_push_event(&self, event: Event) -> bool { self.events.try_send(event).is_ok() }

    /// Waits until the host passes something to the connection.
    pub(crate) async fn wakeup(&self) { self.wakeup.wait().await; }

    /// Shared state whose host decides on a central's connection parameter
    /// requests.
    #[cfg(test)]
    pub(crate) fn with_all_events() -> Self {
        let shared = Self::new();
        shared.host_decides.store(true, Ordering::Relaxed);
        shared
    }
}

/// The host's handle on the link layer. Every call comes from thread mode,
/// or another priority below the link layer's interrupt executor.
#[derive(Clone, Copy)]
pub struct Link<'shared> {
    /// State shared with the link layer.
    shared: &'shared Shared,
}

#[expect(clippy::same_name_method, reason = "the host's port trait mirrors these calls")]
impl<'shared> Link<'shared> {
    /// Adds a device to the filter accept list. Refused while advertising
    /// uses the list.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising filters on the list,
    /// [`Error::Full`] if it holds [`FILTER_LIST_SIZE`] devices.
    #[inline]
    pub fn accept_list_add(&self, peer: Peer) -> Result<(), Error> {
        self.with_filter_list(|legacy| if legacy.filter.add(peer) { Ok(()) } else { Err(Error::Full) })
    }

    /// Empties the filter accept list.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising filters on the list.
    #[inline]
    pub fn accept_list_clear(&self) -> Result<(), Error> {
        self.with_filter_list(|legacy| {
            legacy.filter.clear();
            Ok(())
        })
    }

    /// Removes a device from the filter accept list.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising filters on the list.
    #[inline]
    pub fn accept_list_remove(&self, peer: Peer) -> Result<(), Error> {
        self.with_filter_list(|legacy| {
            legacy.filter.remove(peer);
            Ok(())
        })
    }

    /// The fragments of the current link the central acknowledged, counted
    /// from the start of the link and wrapping.
    #[inline]
    #[must_use = "the count is only read"]
    pub fn acked(&self) -> u32 { self.shared.state.lock(|cell| cell.borrow().acked) }

    /// Adds a peer to the resolving list, or replaces its keys: its
    /// identity, its identity resolving key, which may be zero, and our
    /// local identity resolving key, which gives our resolvable private
    /// addresses and may be zero too. The peer's privacy mode is network
    /// privacy until [`Self::set_privacy_mode`] changes it.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising resolves addresses,
    /// [`Error::Full`] if the list is full.
    #[inline]
    pub fn add_peer(&self, identity: Peer, peer_irk: [u8; 16], local_irk: [u8; 16]) -> Result<(), Error> {
        self.check_resolving_change()?;
        if !self.shared.state.lock(|cell| cell.borrow().legacy.resolving.can_add(identity)) {
            return Err(Error::Full);
        }
        let needs_address = local_irk != [0; 16]
            && self.shared.state.lock(|cell| {
                let state = cell.borrow();
                state.legacy_enabled && state.legacy.private && state.legacy.own == state.legacy.address
            });
        let own = needs_address.then(|| self.shared.own_address(Some(local_irk)));
        let added = self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            // Advertising that started before the key arrived moves to a
            // private address now.
            if let Some(address) = own {
                state.legacy.own = address;
            }
            state.legacy.resolving.add_keys(identity, peer_irk, local_irk)
        });
        if added { Ok(()) } else { Err(Error::Full) }
    }

    /// Advertises with `params`, the advertising data `adv` and the scan
    /// response data `scan`, from now until a central connects or
    /// [`Self::stop_advertising`]. Replaces advertising that runs. The own
    /// address is the identity of [`Self::set_identity`], or with
    /// [`AdvParams::private`] a resolvable private address made with the
    /// local key in the resolving list.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for parameters out of range, data longer than 31
    /// octets or without an identity address, [`Error::Disallowed`] while a
    /// connection exists.
    #[inline]
    pub fn advertise(&self, params: &AdvParams, adv: &[u8], scan: &[u8]) -> Result<(), Error> {
        let max = DATA_MAX;
        if !params.is_valid() || adv.len() > max || scan.len() > max {
            return Err(Error::Invalid);
        }
        let (address, connected) = self.shared.state.lock(|cell| {
            let state = cell.borrow();
            (state.legacy.address, state.connected)
        });
        if address.address == [0; 6] {
            return Err(Error::Invalid);
        }
        if connected {
            return Err(Error::Disallowed);
        }
        // The key and the address come outside the critical section; the
        // address is cached, so advertising keeps it until it expires.
        let key = params.private.then(|| {
            self.shared
                .state
                .lock(|cell| cell.borrow().legacy.resolving.local_key(params.kind.is_directed().then_some(params.peer)))
        });
        let own = self.shared.own_address(key.flatten());
        let result = self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.connected {
                return Err(Error::Disallowed);
            }
            let legacy = &mut state.legacy;
            legacy.kind = params.kind;
            legacy.private = params.private;
            legacy.interval = u32::from(params.interval).saturating_mul(625);
            legacy.peer = params.peer;
            legacy.channel_map = params.channel_map;
            legacy.filter_policy = params.filter_policy;
            for (target, len, source) in
                [(&mut legacy.data, &mut legacy.len, adv), (&mut legacy.scan_data, &mut legacy.scan_len, scan)]
            {
                target.fill(0);
                if let Some(destination) = target.get_mut(..source.len()) {
                    destination.copy_from_slice(source);
                }
                *len = u8::try_from(source.len()).unwrap_or_default();
            }
            legacy.own = own;
            state.legacy_enabled = true;
            Ok(())
        });
        if result.is_ok() {
            self.shared.changed.signal(());
            info!("advertising");
        }
        result
    }

    /// Refuses resolving list changes while advertising resolves addresses.
    fn check_resolving_change(self) -> Result<(), Error> {
        let busy = self.shared.state.lock(|cell| {
            let state = cell.borrow();
            state.legacy_enabled && state.legacy.resolution_enabled
        });
        if busy { Err(Error::Disallowed) } else { Ok(()) }
    }

    /// Removes every peer from the resolving list, overwriting their keys.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising resolves addresses.
    #[inline]
    pub fn clear_peers(&self) -> Result<(), Error> {
        self.check_resolving_change()?;
        self.shared.state.lock(|cell| cell.borrow_mut().forget_keys());
        Ok(())
    }

    /// Ends the link with `reason`: authentication failure (0x05), remote
    /// user (0x13), low resources (0x14), power off (0x15), unsupported
    /// remote feature (0x1A), pairing with unit key not supported (0x29) or
    /// unacceptable connection parameters (0x3B). [`Event::Disconnected`]
    /// follows.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Invalid`] for another
    /// reason.
    #[inline]
    pub fn disconnect(&self, epoch: Epoch, reason: u8) -> Result<(), Error> {
        // Signalled under the lock of the check, so the request cannot
        // outlive the link it was meant for.
        self.shared.state.lock(|cell| {
            cell.borrow().current(epoch)?;
            if !DISCONNECT_REASONS.contains(&reason) {
                return Err(Error::Invalid);
            }
            self.shared.disconnect.signal(reason);
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Holds the peripheral latency off while `hold` is set: the link layer
    /// then listens at every connection event, as for a link without
    /// latency.
    #[inline]
    pub fn hold_latency(&self, hold: bool) {
        self.shared.hold_latency.store(hold, Ordering::Relaxed);
        self.shared.wakeup.signal(());
    }

    /// The fragments of the link the host queued and the central has not
    /// acknowledged yet, waiting in the queue or on the air.
    #[inline]
    #[must_use = "the count is only read"]
    pub fn in_flight(&self, epoch: Epoch) -> usize {
        self.shared.state.lock(|cell| {
            let state = cell.borrow();
            if state.current(epoch).is_err() {
                return 0;
            }
            usize::try_from(state.sent.wrapping_sub(state.acked)).unwrap_or(usize::MAX)
        })
    }

    /// What the host learns about the current link, `None` without one.
    #[inline]
    #[must_use = "the information is only read"]
    pub fn info(&self) -> Option<Info> { self.shared.state.lock(|cell| cell.borrow().info) }

    /// Answers [`Event::LtkRequest`] with the long term key, least
    /// significant octet first as the link layer takes it, or with `None`
    /// if the host has no key, which rejects the encryption. A key the
    /// security manager derives most significant octet first is reversed
    /// before it is given here.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, which needs no further action,
    /// [`Error::Disallowed`] if no request waits for an answer.
    #[inline]
    pub fn ltk_reply(&self, epoch: Epoch, key: Option<[u8; 16]>) -> Result<(), Error> {
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.current(epoch)?;
            if !state.ltk_pending {
                return Err(Error::Disallowed);
            }
            state.ltk_pending = false;
            self.shared.ltk.signal(key);
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Creates the handle.
    #[inline]
    #[must_use = "the handle is only created"]
    pub const fn new(shared: &'shared Shared) -> Self { Self { shared } }

    /// Waits for the next event or received fragment. See the module
    /// documentation for the order. One task reads them.
    #[inline]
    pub async fn next(&self) -> Rx {
        match select(self.shared.events.receive(), self.shared.acl_in.receive()).await {
            Either::First(event) => Rx::Event(event),
            Either::Second(acl) => {
                self.shared.acl_taken.signal(());
                Rx::Acl(acl)
            },
        }
    }

    /// The authenticated payload timeout of the link in units of 10 ms.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended.
    #[inline]
    pub fn payload_timeout(&self, epoch: Epoch) -> Result<u16, Error> {
        self.shared.state.lock(|cell| {
            let state = cell.borrow();
            state.current(epoch)?;
            Ok(state.payload_timeout)
        })
    }

    /// The receive and transmit PHY of the link, 1 for LE 1M and 2 for
    /// LE 2M.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended.
    #[inline]
    pub fn phy(&self, epoch: Epoch) -> Result<[u8; 2], Error> {
        self.shared.state.lock(|cell| {
            let state = cell.borrow();
            state.current(epoch)?;
            Ok(state.phys)
        })
    }

    /// Starts a query of the central's features or version.
    fn query(self, epoch: Epoch, bit: u8) -> Result<(), Error> {
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.current(epoch)?;
            if state.active_queries & bit != 0 {
                return Err(Error::Disallowed);
            }
            state.active_queries |= bit;
            state.queries |= bit;
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Asks for the central's features; [`Event::RemoteFeatures`] answers.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Disallowed`] while the
    /// previous query runs.
    #[inline]
    pub fn read_remote_features(&self, epoch: Epoch) -> Result<(), Error> { self.query(epoch, QUERY_FEATURES) }

    /// Asks for the central's version; [`Event::RemoteVersion`] answers.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Disallowed`] while the
    /// previous query runs.
    #[inline]
    pub fn read_remote_version(&self, epoch: Epoch) -> Result<(), Error> { self.query(epoch, QUERY_VERSION) }

    /// Removes a peer from the resolving list, overwriting its keys.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising resolves addresses.
    #[inline]
    pub fn remove_peer(&self, identity: Peer) -> Result<(), Error> {
        self.check_resolving_change()?;
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.legacy.resolving.remove(identity);
            state.forget_address();
        });
        Ok(())
    }

    /// Answers [`Event::ParamsRequested`]: with the parameters to offer, or
    /// with the reason to reject the central's request. The link layer
    /// rejects it itself if the host does not answer within 30 s.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Invalid`] for parameters
    /// out of range, [`Error::Disallowed`] if no request waits for an
    /// answer.
    #[inline]
    pub fn reply_params(&self, epoch: Epoch, reply: Result<ParamRange, u8>) -> Result<(), Error> {
        if reply.is_ok_and(|range| !range.is_valid()) {
            return Err(Error::Invalid);
        }
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.current(epoch)?;
            if state.active_queries & QUERY_REMOTE_PARAMETERS == 0 {
                return Err(Error::Disallowed);
            }
            // One answer per request, signalled under the lock that checked
            // the link.
            state.active_queries &= !QUERY_REMOTE_PARAMETERS;
            self.shared.parameter_reply.signal(reply.map(ParamRange::fields));
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Asks the central for connection parameters with the connection
    /// parameters request procedure. [`Event::ParamsUpdated`] reports the
    /// outcome. While the host answers a central's request, the request is
    /// part of that answer and completes when the central's procedure ends.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Invalid`] for parameters
    /// out of range, [`Error::Disallowed`] until the previous request
    /// reported its outcome, [`Error::UnsupportedRemote`] if the central
    /// lacks the procedure: the host then sends the L2CAP request.
    #[inline]
    pub fn request_params(&self, epoch: Epoch, range: ParamRange) -> Result<(), Error> {
        let valid = range.is_valid();
        // Checked and signalled under one lock, so the request cannot
        // outlive the link it was meant for.
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.current(epoch)?;
            if !valid {
                return Err(Error::Invalid);
            }
            // While the host answers a central's request, the central's
            // procedure carries the parameters: the request is part of the
            // answer and completes when that procedure ends. It leaves the
            // host's own update, if one runs, alone.
            if state.active_queries & QUERY_REMOTE_PARAMETERS != 0 {
                state.merged_updates = state.merged_updates.saturating_add(1);
                return Ok(());
            }
            // One update at a time, as in Zephyr: a second request would
            // replace the first, whose outcome the host then never learns.
            if state.active_queries & QUERY_CONNECTION_UPDATE != 0 {
                return Err(Error::Disallowed);
            }
            if state.remote_features & 0x02 == 0 {
                return Err(Error::UnsupportedRemote);
            }
            state.active_queries |= QUERY_CONNECTION_UPDATE;
            self.shared.param_request.signal(range.fields());
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Resets the link layer: ends the link and advertising and forgets
    /// every setting and key the host gave. Returns once the radio stopped.
    #[inline]
    pub async fn reset(&self) {
        self.shared.reset_done.reset();
        self.shared.signal_reset();
        self.shared.reset_done.wait().await;
    }

    /// The averaged signal strength of the link's packets in dBm, `None`
    /// before the first or without the link.
    #[inline]
    #[must_use = "the strength is only read"]
    pub fn rssi(&self, epoch: Epoch) -> Option<i8> {
        let current = self.shared.state.lock(|cell| cell.borrow().current(epoch).is_ok());
        let rssi = self.shared.rssi.load(Ordering::Relaxed);
        (current && rssi != RSSI_UNKNOWN).then_some(rssi)
    }

    /// Queues one fragment of an L2CAP message for the link, `start` for
    /// its first. An empty fragment counts as a continuation.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Invalid`] for a fragment
    /// longer than [`ACL_MAX`], [`Error::Full`] without room.
    #[inline]
    pub async fn send(&self, epoch: Epoch, start: bool, fragment: &[u8]) -> Result<(), Error> {
        loop {
            match self.try_send(epoch, start, fragment) {
                Err(Error::Full) => self.tx_room_changed().await,
                result => return result,
            }
        }
    }

    /// Lets advertising with address resolution accept only peers of the
    /// resolving list under their privacy mode, and resolve their private
    /// addresses for the filter accept list and directed advertising.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising runs.
    #[inline]
    pub fn set_address_resolution(&self, enable: bool) -> Result<(), Error> {
        self.with_idle_advertising(|legacy| {
            legacy.resolution_enabled = enable;
            Ok(())
        })
    }

    /// Sets the data length the link may send: payload octets and time in
    /// microseconds. [`Event::DataLength`] reports the effective lengths.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Invalid`] out of range.
    #[inline]
    pub fn set_data_length(&self, epoch: Epoch, octets: u16, time: u16) -> Result<(), Error> {
        let value = data_length(octets, time)?;
        self.shared.state.lock(|cell| {
            cell.borrow().current(epoch)?;
            self.shared.data_length.signal(value);
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Sets the transmit and receive PHYs new links prefer: bit 0 for LE 1M,
    /// bit 1 for LE 2M, `None` without a preference.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for other bits, [`Error::Unsupported`] for LE 2M
    /// or LE Coded on the nRF51.
    #[inline]
    pub fn set_default_phy(&self, tx: Option<u8>, rx: Option<u8>) -> Result<(), Error> {
        let preferences = phy_preferences(tx, rx)?;
        self.shared.state.lock(|cell| cell.borrow_mut().preferred_phys = preferences);
        Ok(())
    }

    /// Lets the host decide on a central's connection parameter requests
    /// with [`Event::ParamsRequested`] and [`Self::reply_params`]. Without
    /// it the link layer accepts any valid request.
    #[inline]
    pub fn set_host_decides_params(&self, decides: bool) { self.shared.host_decides.store(decides, Ordering::Relaxed); }

    /// Sets the static random identity address, least significant octet
    /// first.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising runs.
    #[inline]
    pub fn set_identity(&self, address: [u8; 6]) -> Result<(), Error> {
        self.with_idle_advertising(|legacy| {
            legacy.address = Peer::new(address, true);
            legacy.own = legacy.address;
            Ok(())
        })
    }

    /// Sets the authenticated payload timeout of the link in units of 10 ms.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Invalid`] for zero.
    #[inline]
    pub fn set_payload_timeout(&self, epoch: Epoch, timeout: u16) -> Result<(), Error> {
        if timeout == 0 {
            return Err(Error::Invalid);
        }
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.current(epoch)?;
            state.payload_timeout = timeout;
            Ok(())
        })
    }

    /// Asks for other PHYs on the link, as [`Self::set_default_phy`] takes
    /// them. [`Event::PhyUpdated`] reports the outcome.
    ///
    /// # Errors
    ///
    /// As [`Self::set_default_phy`], and [`Error::Gone`] if the link ended,
    /// [`Error::Disallowed`] while the previous request runs.
    #[inline]
    pub fn set_phy(&self, epoch: Epoch, tx: Option<u8>, rx: Option<u8>) -> Result<(), Error> {
        let preferences = phy_preferences(tx, rx)?;
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.current(epoch)?;
            if state.active_queries & QUERY_PHY != 0 {
                return Err(Error::Disallowed);
            }
            state.active_queries |= QUERY_PHY;
            state.phy_pending = Some(preferences);
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Sets how a peer of the resolving list may connect: with `device`
    /// privacy from its identity address as well, otherwise only from a
    /// resolvable private address.
    ///
    /// # Errors
    ///
    /// [`Error::Disallowed`] while advertising runs, [`Error::Invalid`] if
    /// the peer is not listed.
    #[inline]
    pub fn set_privacy_mode(&self, identity: Peer, device: bool) -> Result<(), Error> {
        self.with_idle_advertising(|legacy| {
            if legacy.resolving.set_mode(identity, device) { Ok(()) } else { Err(Error::Invalid) }
        })
    }

    /// Sets the lifetime of resolvable private addresses in seconds, 1 to
    /// 3600; the default is 900. The current address keeps its expiry.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] out of range.
    #[inline]
    pub fn set_rpa_timeout(&self, seconds: u16) -> Result<(), Error> {
        if !(1..=PRIVATE_ADDRESS_TIMEOUT_MAX).contains(&seconds) {
            return Err(Error::Invalid);
        }
        self.shared.state.lock(|cell| cell.borrow_mut().private_timeout = Duration::from_secs(u64::from(seconds)));
        Ok(())
    }

    /// Sets the data length new links may send: payload octets and time in
    /// microseconds.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] out of range.
    #[inline]
    pub fn set_suggested_length(&self, octets: u16, time: u16) -> Result<(), Error> {
        let value = data_length(octets, time)?;
        self.shared.state.lock(|cell| cell.borrow_mut().suggested_length = value);
        Ok(())
    }

    /// Ends advertising.
    #[inline]
    pub fn stop_advertising(&self) {
        let was = self.shared.state.lock(|cell| core::mem::take(&mut cell.borrow_mut().legacy_enabled));
        if was {
            self.shared.changed.signal(());
            info!("advertising stopped");
        }
    }

    /// The next event or received fragment, if one waits.
    #[inline]
    #[must_use = "a taken event or fragment is gone from the queue"]
    pub fn try_next(&self) -> Option<Rx> {
        if let Ok(event) = self.shared.events.try_receive() {
            return Some(Rx::Event(event));
        }
        let acl = self.shared.acl_in.try_receive().ok()?;
        self.shared.acl_taken.signal(());
        Some(Rx::Acl(acl))
    }

    /// Queues one fragment of an L2CAP message for the link without waiting,
    /// `start` for its first. An empty fragment counts as a continuation.
    ///
    /// # Errors
    ///
    /// [`Error::Gone`] if the link ended, [`Error::Invalid`] for a fragment
    /// longer than [`ACL_MAX`], [`Error::Full`] without room.
    #[inline]
    pub fn try_send(&self, epoch: Epoch, start: bool, fragment: &[u8]) -> Result<(), Error> {
        let mut data = [0_u8; ACL_MAX];
        let Some(target) = data.get_mut(..fragment.len()) else { return Err(Error::Invalid) };
        target.copy_from_slice(fragment);
        let llid = if start && !fragment.is_empty() { Llid::Start } else { Llid::Continuation };
        let len = u8::try_from(fragment.len()).unwrap_or_default();
        // Queued under the lock of the check, so a fragment cannot reach the
        // next link.
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            state.current(epoch)?;
            self.shared.acl_out.try_send(AclOut { data, epoch: epoch.0, len, llid }).map_err(|_full| Error::Full)?;
            state.sent = state.sent.wrapping_add(1);
            Ok(())
        })?;
        self.shared.wakeup.signal(());
        Ok(())
    }

    /// Free places for fragments towards the air.
    #[inline]
    #[must_use = "the room is only read"]
    pub fn tx_room(&self) -> usize { self.shared.acl_out.free_capacity() }

    /// Waits until the link layer takes a fragment from the queue, the
    /// central acknowledges fragments, which lowers [`Self::in_flight`], or
    /// the link ends: each can give room. One task waits.
    #[inline]
    pub async fn tx_room_changed(&self) { self.shared.tx_room.wait().await; }

    /// Runs `change` on the advertising settings unless advertising filters
    /// on the accept list.
    fn with_filter_list(self, change: impl FnOnce(&mut LegacySettings) -> Result<(), Error>) -> Result<(), Error> {
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.legacy_enabled && state.legacy.filter_policy != 0 {
                return Err(Error::Disallowed);
            }
            change(&mut state.legacy)
        })
    }

    /// Runs `change` on the advertising settings unless advertising runs.
    fn with_idle_advertising(self, change: impl FnOnce(&mut LegacySettings) -> Result<(), Error>) -> Result<(), Error> {
        self.shared.state.lock(|cell| {
            let mut state = cell.borrow_mut();
            if state.legacy_enabled {
                return Err(Error::Disallowed);
            }
            change(&mut state.legacy)
        })
    }
}

/// The data length for `octets` and `time`, the time limited to what this
/// side can use on LE 1M and 2M.
fn data_length(octets: u16, time: u16) -> Result<[u16; 2], Error> {
    let [max_octets, max_time] = LENGTH_MAX;
    let [default_octets, default_time] = LENGTH_DEFAULT;
    if !(default_octets..=max_octets).contains(&octets) || !(default_time..=0x4290).contains(&time) {
        return Err(Error::Invalid);
    }
    Ok([octets, time.min(max_time)])
}

/// The transmit and receive PHY preferences: bit 0 for LE 1M, bit 1 for
/// LE 2M, all of them without a preference.
fn phy_preferences(tx: Option<u8>, rx: Option<u8>) -> Result<[u8; 2], Error> {
    let check = |phys: Option<u8>| match phys {
        None => Ok(3),
        Some(bits) if bits & !0b111 != 0 || bits == 0 => Err(Error::Invalid),
        // LE 2M and LE Coded are missing on the nRF51.
        Some(bits) if !crate::chip::PHY_2M && bits & 0b110 != 0 => Err(Error::Unsupported),
        Some(bits) if bits & 0b100 != 0 => Err(Error::Invalid),
        Some(bits) => Ok(bits),
    };
    Ok([check(tx)?, check(rx)?])
}

#[cfg(test)] mod tests;
