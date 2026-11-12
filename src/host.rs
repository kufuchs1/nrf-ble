//! A minimal Bluetooth LE host for Linux and `BlueZ`.
//!
//! The host serves one connection as a peripheral: L2CAP with the fixed
//! channels for ATT, signalling and the security manager, a GATT server over
//! a constant attribute table, LE Secure Connections pairing as responder
//! (Just Works, and with the feature `passkey` Passkey Entry as a keyboard)
//! with bonding, and connectable advertising. It talks to the link layer
//! through the typed API of [`crate::link`], not through HCI.
//!
//! Three optional features add to the host, each off by default so a device
//! without it builds as before: `param-requests` (the application's own
//! connection parameter requests, `Conn::request_params`, and
//! `ConnEvent::ParamsRejected`), `key-missing` (a reconnection whose central
//! has no key of the bond ends at once, `ConnEvent::KeyMissing`) and
//! `passkey` (Passkey Entry: [`engine::Config`]'s security,
//! `ConnEvent::PasskeyRequested`, `Conn::enter_passkey`, and attributes that
//! need an authenticated link).
//!
//! The protocol core ([`l2cap`], [`signal`], [`att`], [`gatt`], [`smp`], with
//! its cryptography in [`smp::toolbox`] and [`smp::ecc`], and the [`engine`]
//! that joins them) holds no futures and touches no peripheral, so it runs in
//! the host tests on the PC. Our identity ([`identity`]), the advertising data
//! and modes ([`adv`]) and the bond ([`bond`]) are plain data too. Only the
//! async glue of this module, [`Host`] and [`Conn`], waits for anything, and
//! it reaches the link layer through [`Port`], which [`crate::link::Link`]
//! implements. Every buffer is a fixed array: no heap and no allocation.
//!
//! # Tasks
//!
//! The firmware runs three tasks of the thread executor on one static
//! [`Host`]; the link layer's own task runs in an interrupt executor above
//! them:
//!
//! - [`Host::run`] feeds the [`engine::Engine`] with whatever comes first: the
//!   link layer's next event or fragment, the engine's next deadline, the
//!   return of room in the link layer's queue or an acknowledgement while
//!   output or the engine waits for one, or a wake-up from another task. After
//!   each, it makes the calls of the link layer the engine asks for and queues
//!   the fragments the engine has, as long as there is room.
//! - [`Host::crypto`] runs the P-256 jobs of pairing, each a multiplication
//!   that blocks the thread for about 3 s on the nRF51, with the firmware's
//!   watchdog hook right before each multiplication and a yield between two
//!   jobs. No lock is held meanwhile; the link layer keeps the link.
//! - The application advertises with [`Host::advertise`], reads the link's
//!   events with [`Conn::next`] and sends its reports with [`Conn::notify`].
//!
//! [`Conn::notify`] sends from the application's task, not through the run
//! task, and paces by acknowledgement: it waits while
//! [`engine::Config::notify_depth`] fragments of the link are in flight
//! ([`crate::link::Link::in_flight`]), two by default, so one report is
//! always queued when the central acknowledges the previous one, and while
//! the link layer's queue has fewer than two free places, which keeps one for
//! the ATT responses, the security manager and signalling. A depth of three
//! queues a button or key report behind the two movement reports before it;
//! the queue is the same, so it costs no RAM. On the nRF52832 the report can
//! then ride their connection event if the central keeps it open (MD); the
//! nRF51 sends one new PDU per event, so there it goes out at a later event.
//!
//! # Thread mode
//!
//! Every call into the host comes from thread mode, as its state sits behind
//! a thread mode mutex ([`StateMutex`]) rather than a critical section, which
//! would hold off the link layer for the whole of the longer AES computations
//! of pairing. Each AES block on the ECB still holds a critical section for
//! that one block, as [`crate::crypto::encrypt_block`] shares the ECB with the
//! link layer: f5, which runs three CMACs, takes 13 AES blocks and so holds
//! interrupts off 13 times, each for about 7 us on the nRF52832.
//!
//! # Advertising
//!
//! [`Host::advertise`] sets the link layer up for its mode
//! ([`adv::Advertising::configure`]) and runs the phases of its schedule
//! until a central connects, returning the [`Conn`]. In pairing mode it first
//! waits for the key pair of the next pairing, so the multiplication never
//! runs while a central waits; a reconnection never computes one. A central
//! may connect after the call's future was dropped: [`engine::Config`] says
//! whether that link is kept for the next call or ended.
//!
//! # A device
//!
//! The device crate defines what is its own, which this crate knows nothing
//! about: its attribute table with the [`gatt!`](crate::gatt) macro, its
//! name and appearance, its connection parameters, what it advertises
//! ([`adv::Content`]) and on which schedules ([`adv::Schedule`]), and the
//! [`engine::Config`] of its host. The example below keeps them in a module
//! `my_device`, as a firmware keeps them in a module of its own.
//!
//! It then wires the link layer, the host's tasks, advertising, the bond and
//! the reports as shown. In the firmware each `async fn` below is an
//! `#[embassy_executor::task]` of the thread executor, and the link layer's
//! task, [`crate::controller::run`], runs in an interrupt executor on
//! [`SHARED`](crate::link::Shared).
//!
//! The firmware keeps two records in flash: the bond ([`bond::BOND_LEN`]
//! octets) and, apart from it, the generation of our identity that the last
//! pairing mode took ([`identity::Variant`]). Pairing mode takes the next
//! generation and stores it before it advertises, so it never brings back an
//! identity Linux may still hold a bond with: not after the bond was cleared
//! or lost, nor after a pairing Linux completed whose bond the device never
//! stored. Erasing the bond never erases the generation.
//!
//! The application reads the link's events and the key presses in one task,
//! so it stores each bond as it comes and sees the end of the link at once.
//! It sends reports only after [`ConnEvent::Ready`] and a settle time, which
//! gives `BlueZ` the moment it needs to create its input device; the settle
//! time is to be measured on the hardware.
//!
//! ```no_run
//! use embassy_futures::select::{Either, select};
//! use embassy_time::{Duration, Timer};
//! use nrf_ble::{
//!     host::{
//!         Battery,
//!         ConnEvent,
//!         Hardware,
//!         Host,
//!         NotifyError,
//!         adv::Mode,
//!         bond::{BOND_LEN, Bond},
//!         gatt::{AttError, Handler, ValueId},
//!         identity::{DeviceSecret, LocalIdentity, Variant},
//!     },
//!     link::{Link, Shared},
//! };
//!
//! /// What is the device's own: its table, advertising and configuration.
//! mod my_device {
//!     use embassy_time::Duration;
//!     use nrf_ble::{
//!         host::{
//!             adv::{
//!                 Advertising,
//!                 BATTERY_SERVICE,
//!                 Content,
//!                 HID_SERVICE,
//!                 Mode,
//!                 Overflow,
//!                 Phase,
//!                 Schedule,
//!             },
//!             engine::{Config, Unclaimed},
//!             gatt::{Value, ValueId, ppcp},
//!         },
//!         link::ParamRange,
//!     };
//!
//!     /// The device name: the Device Name characteristic and the advertised
//!     /// name.
//!     pub const NAME: &[u8] = b"My Remote";
//!     /// Appearance: a keyboard (0x03C1).
//!     pub const APPEARANCE: u16 = 0x03C1;
//!     /// The connection parameters it asks for: 15 ms, a latency of 30
//!     /// events, 6 s.
//!     pub const PARAMS: ParamRange = ParamRange::new(12, 12, 30, 600);
//!     /// The battery level, which the application's handler reads.
//!     pub const BATTERY_LEVEL_VALUE: ValueId = ValueId::new(0);
//!     /// The Peripheral Preferred Connection Parameters of [`PARAMS`].
//!     const PPCP: [u8; 8] = ppcp(PARAMS);
//!     /// The HID report descriptor: a keyboard, report ID 1.
//!     const REPORT_MAP: [u8; 2] = [0x05, 0x01]; // and the rest of it
//!
//!     nrf_ble::gatt! {
//!         /// The attribute table.
//!         pub const DB;
//!         service 0x1800 {
//!             char 0x2A00 [read] = Value::Const(NAME);
//!             char 0x2A01 [read] = Value::Const(&APPEARANCE.to_le_bytes());
//!             char 0x2A04 [read] = Value::Const(&PPCP);
//!         }
//!         service 0x1801 {
//!             char 0x2B2A [read] = Value::Hash;
//!         }
//!         service 0x180F {
//!             /// The battery level, which the application notifies.
//!             char BATTERY_LEVEL: 0x2A19 [read, notify] = Value::Dynamic(BATTERY_LEVEL_VALUE);
//!             ccc;
//!         }
//!         service 0x1812 {
//!             char 0x2A4A [read] = Value::Const(&[0x11, 0x01, 0x00, 0x03]);
//!             char 0x2A4B [read] = Value::Const(&REPORT_MAP);
//!             char 0x2A4C [write_without_response] = Value::Sink;
//!             /// The keyboard input report, ID 1.
//!             char KEYBOARD: 0x2A4D [read, notify; encrypted] = Value::Zeros(8);
//!             ccc;
//!             desc 0x2908 [read] = Value::Const(&[1, 1]);
//!         }
//!     }
//!
//!     /// 20 ms for 3 s, 50 ms for 12 s, 400 ms for 45 s.
//!     const PHASES: [Phase; 3] = [
//!         Phase::new(32, Duration::from_secs(3)),
//!         Phase::new(80, Duration::from_secs(12)),
//!         Phase::new(640, Duration::from_secs(45)),
//!     ];
//!     /// Pairing: 60 s to pair.
//!     const PAIRING: Schedule = Schedule::new(&PHASES, Duration::from_secs(60));
//!     /// Reconnection: 20 s for the bonded central to encrypt.
//!     const RECONNECT: Schedule = Schedule::new(&PHASES, Duration::from_secs(20));
//!     /// What it advertises.
//!     const CONTENT: Content<'static> =
//!         Content::new(NAME, APPEARANCE, &[HID_SERVICE, BATTERY_SERVICE]);
//!     /// The host's configuration: ask for [`PARAMS`], keep a link nobody
//!     /// waits for.
//!     pub const CONFIG: Config = Config::new(Some(PARAMS), Unclaimed::Keep);
//!
//!     /// The advertising of `mode`.
//!     pub fn advertising(mode: Mode<'_>) -> Result<Advertising<'_>, Overflow> {
//!         let schedule = if mode.pairable() { &PAIRING } else { &RECONNECT };
//!         Advertising::new(mode, schedule, &CONTENT)
//!     }
//! }
//!
//! /// The state the link layer task and the host share.
//! static SHARED: Shared = Shared::new();
//! /// The host over the link layer, with the device's table.
//! static HOST: Host<Link<'static>> =
//!     Host::new(Link::new(&SHARED), &my_device::DB, my_device::CONFIG);
//! /// The battery level, which the table reads and the host notifies.
//! static BATTERY: Battery = Battery::new(my_device::BATTERY_LEVEL, 100);
//! /// The time `BlueZ` gets after [`ConnEvent::Ready`] before the first
//! /// report: to be measured.
//! const SETTLE: Duration = Duration::from_millis(200);
//!
//! /// The application's side of the table's dynamic values. It runs inside
//! /// the host, so it never calls into it.
//! struct App;
//!
//! impl Handler for App {
//!     fn read(&self, id: ValueId, out: &mut [u8]) -> Result<usize, AttError> {
//!         if id == my_device::BATTERY_LEVEL_VALUE {
//!             BATTERY.read(out)
//!         } else {
//!             Err(AttError::UNLIKELY_ERROR)
//!         }
//!     }
//!
//!     fn write(&self, _id: ValueId, _data: &[u8], _with_response: bool) -> Result<(), AttError> {
//!         Err(AttError::WRITE_NOT_PERMITTED)
//!     }
//! }
//!
//! /// The host: links, deadlines and sending.
//! async fn host_task() -> ! { HOST.run(&App, &mut Hardware::default()).await }
//!
//! /// The P-256 jobs of pairing.
//! async fn crypto_task() -> ! { HOST.crypto(&mut Hardware::default(), feed_watchdog).await }
//!
//! /// Advertising, the bond and the reports, from the two flash records.
//! async fn app_task(stored: [u8; BOND_LEN], mut generation: u8) {
//!     let secret = DeviceSecret::from_ficr();
//!     let mut bond = Bond::from_bytes(&stored);
//!     loop {
//!         let variant = match bond.as_ref() {
//!             Some(bond) => bond.local,
//!             None => {
//!                 // Pairing mode: a new generation, stored before it is
//!                 // used.
//!                 generation = generation.wrapping_add(1);
//!                 store_generation(generation);
//!                 Variant::new(0, generation)
//!             },
//!         };
//!         let mode = bond.as_ref().map_or(Mode::Pairing, Mode::Reconnect);
//!         let identity = LocalIdentity::derive(&Hardware::default(), &secret, variant);
//!         let Ok(advertising) = my_device::advertising(mode) else { return };
//!         let Ok(conn) = HOST.advertise(&advertising, &identity).await else {
//!             wait_for_key_press().await;
//!             continue;
//!         };
//!         // The press that woke the device waits for discovery.
//!         let mut ready = false;
//!         let mut waiting = None;
//!         loop {
//!             let report = match select(conn.next(), wait_for_key_press()).await {
//!                 Either::First(ConnEvent::Bonded(new) | ConnEvent::BondUpdated(new)) => {
//!                     store_bond(&new.to_bytes());
//!                     bond = Some(new);
//!                     continue;
//!                 },
//!                 Either::First(ConnEvent::Ready) => {
//!                     ready = true;
//!                     Timer::after(SETTLE).await;
//!                     let Some(report) = waiting.take() else { continue };
//!                     report
//!                 },
//!                 Either::First(ConnEvent::Disconnected(_)) => break,
//!                 Either::First(_) => continue,
//!                 Either::Second(report) if !ready => {
//!                     waiting = Some(report);
//!                     continue;
//!                 },
//!                 Either::Second(report) => report,
//!             };
//!             // A report nobody subscribed to, or one the link is not yet
//!             // secure enough for, is skipped; only the end of the link ends
//!             // the reports.
//!             if conn.notify(my_device::KEYBOARD, &report).await == Err(NotifyError::Disconnected)
//!             {
//!                 break;
//!             }
//!             let _ = BATTERY.update(&conn, measure_battery()).await;
//!         }
//!     }
//! }
//!
//! # fn feed_watchdog() {}
//! # fn store_bond(_bytes: &[u8; BOND_LEN]) {}
//! # fn store_generation(_generation: u8) {}
//! # fn measure_battery() -> u8 { 90 }
//! # async fn wait_for_key_press() -> [u8; 8] { [0; 8] }
//! # fn main() {}
//! ```

/// Connectable advertising and the advertising data writer.
pub mod adv;
/// The attribute protocol: requests, responses, notifications, indications.
pub mod att;
/// The bond with the one central and its stored form.
pub mod bond;
/// The protocol engine, without input or output of its own.
pub mod engine;
/// The GATT server's attribute table.
pub mod gatt;
/// The device's own identity address and identity resolving key.
pub mod identity;
/// The L2CAP fixed channels: demultiplexing, reassembly and fragmenting.
pub mod l2cap;
/// The L2CAP signalling channel.
pub mod signal;
/// The security manager: LE Secure Connections pairing as responder.
pub mod smp;

use crate::{
    crypto::{encrypt_block, wipe},
    host::{
        adv::{Advertising, Call, Control, Mode},
        att::NotifyError as AttNotifyError,
        bond::Bond,
        engine::{Command, Engine},
        gatt::{AttError, Char, Db, Handler, Sec},
        identity::LocalIdentity,
        smp::{Random, Reason},
    },
    link::{self, AclIn, ConnectionParams, Epoch, Event, Info, Link, Rx},
    rng,
};
use core::{
    cell::RefCell,
    fmt,
    future::{Future, pending},
    sync::atomic::{AtomicU8, Ordering},
};
use embassy_futures::{
    select::{Either, Either4, select, select4},
    yield_now,
};
#[cfg(not(all(target_arch = "arm", target_os = "none")))]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[cfg(all(target_arch = "arm", target_os = "none"))]
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::{blocking_mutex::Mutex, mutex::Mutex as AsyncMutex, signal::Signal};
use embassy_time::{Instant, Timer};

/// The mutex around the host's state: a thread mode mutex on the chip, so no
/// critical section ever holds off the link layer for the engine's work.
#[cfg(all(target_arch = "arm", target_os = "none"))]
pub type StateMutex = ThreadModeRawMutex;
/// The mutex around the host's state: a critical section on the PC, which
/// has no thread mode, for the host tests.
#[cfg(not(all(target_arch = "arm", target_os = "none")))]
pub type StateMutex = CriticalSectionRawMutex;

/// An event of the host for the application, with [`Engine::take_event`]
/// or [`Conn::next`].
///
/// Events of one kind coalesce until they are taken. They come in this
/// order: `PasskeyRequested` (feature `passkey`), [`Self::PairingFailed`],
/// `KeyMissing` (feature `key-missing`), [`Self::Encrypted`],
/// [`Self::Bonded`], [`Self::BondUpdated`], [`Self::ParamsUpdated`],
/// `ParamsRejected` (feature `param-requests`), [`Self::Ready`], and
/// [`Self::Disconnected`] last, after every other event of its link.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConnEvent {
    /// The bonded central changed its subscriptions: the bond to store in
    /// place of the stored one.
    BondUpdated(Bond),
    /// A pairing made this bond, which the firmware stores: reported once
    /// the central acknowledged our identity keys.
    Bonded(Bond),
    /// The link ended, with the reason; 0 if it is no longer known.
    Disconnected(u8),
    /// The link is encrypted: with the bond's key, or with a new pairing's.
    Encrypted {
        /// With the key of the bond the advertising was set up with.
        bonded: bool,
    },
    /// The central of a reconnection asked to encrypt with a key the host
    /// does not have: the bond's central lost its key, or holds one of
    /// another pairing. The host answered with the negative reply and ends
    /// the link at once with [`engine::SECURITY_FAILURE`]; the bond stays as it
    /// is.
    #[cfg(feature = "key-missing")]
    KeyMissing,
    /// A pairing failed, with the reason; the link ends.
    PairingFailed(Reason),
    /// The central rejected a connection parameter request.
    ///
    /// The request was the engine's own ([`engine::Config::params`]) or one of
    /// [`Conn::request_params`], and the central answered with
    /// a Connection Parameter Update Response that refuses it, or a Command
    /// Reject. An accepted
    /// request has no event of its own: [`Self::ParamsUpdated`] follows once
    /// the central updated the link. A request the central never answers
    /// gives neither; after [`engine::SIGNALLING_TIMEOUT`] the next one may go
    /// out.
    #[cfg(feature = "param-requests")]
    ParamsRejected,
    /// The connection parameters changed to these.
    ParamsUpdated(ConnectionParams),
    /// Passkey Entry asks for the passkey the central displays.
    ///
    /// The user types it on the device; give it with
    /// [`Conn::enter_passkey`], or `None` to refuse. It comes
    /// first among the link's events; [`Self::PairingFailed`] or the end of
    /// the link ends the entry.
    #[cfg(feature = "passkey")]
    PasskeyRequested,
    /// Discovery is over: the link is encrypted, the central has our
    /// response to its last input report configuration write, and ATT has
    /// been idle for [`engine::INPUTS_IDLE`] since (or, without such a write,
    /// for [`engine::READY_IDLE`]). `BlueZ` still needs a moment to create its
    /// input device: the application waits a settle time, measured on the
    /// hardware, before its first report.
    Ready,
}

/// Why [`Engine::request_params`] sent no request.
#[cfg(feature = "param-requests")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum RequestError {
    /// A request waits for its response, or for its place in the link
    /// layer's queue: one at a time.
    Busy,
    /// The link ended, or is ending.
    Gone,
    /// The range is out of the specification's ranges: an interval of 7.5 ms
    /// to 4 s, the shortest at most the longest, and a latency and timeout
    /// that fit the longest.
    Invalid,
}

/// Why a notification cannot be sent now, or at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum NotifyError {
    /// No room now: a PDU of several fragments is being sent, the link layer
    /// lacks two free places, or [`engine::Config::notify_depth`] fragments are
    /// in flight.
    Busy,
    /// The link ended.
    Disconnected,
    /// The link lacks the security the characteristic needs.
    Insecure,
    /// The client has not enabled notifications, or the characteristic
    /// cannot notify.
    NotSubscribed,
    /// The value is longer than [`att::NOTIFY_MAX`].
    TooLong,
}

/// Why a passkey was not taken.
#[cfg(feature = "passkey")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum PasskeyError {
    /// The link ended, or is ending.
    Gone,
    /// The passkey has more than six decimal digits.
    Invalid,
    /// No pairing waits for a passkey: none asked for one, it was given
    /// already, or the pairing ended.
    NotWaiting,
}

/// AES-128 encryption of one block, the only block cipher the host needs: the
/// CMAC of pairing, the key derivation of the identity and the resolvable
/// private addresses are all built on it.
///
/// The firmware uses the hardware ECB through [`Ecb`] or [`Hardware`]; the
/// host tests use the software AES of the `aes` crate.
pub trait Aes {
    /// `block` encrypted with `key`, both most significant octet first.
    fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16];
}

/// The link layer and the time as the host's tasks use them:
/// [`crate::link::Link`] with Embassy's time in the firmware, a stand-in in
/// the host tests.
///
/// Each call is the [`crate::link::Link`] call its documentation names,
/// under a name of the host's own.
///
/// It is [`Sync`], as a [`Host`] in a static needs it to be, so the host's
/// futures are [`Send`].
pub trait Port: Control + Sync {
    /// [`crate::link::Link::ltk_reply`].
    ///
    /// # Errors
    ///
    /// As [`crate::link::Link::ltk_reply`].
    fn answer_ltk(&self, epoch: Epoch, key: Option<[u8; 16]>) -> Result<(), link::Error>;

    /// [`crate::link::Link::disconnect`].
    ///
    /// # Errors
    ///
    /// As [`crate::link::Link::disconnect`].
    fn end_link(&self, epoch: Epoch, reason: u8) -> Result<(), link::Error>;

    /// [`crate::link::Link::in_flight`].
    fn fragments_in_flight(&self, epoch: Epoch) -> usize;

    /// [`crate::link::Link::info`].
    fn link_info(&self) -> Option<Info>;

    /// The time now.
    fn now(&self) -> Instant;

    /// [`crate::link::Link::tx_room`].
    fn queue_room(&self) -> usize;

    /// [`crate::link::Link::tx_room_changed`].
    fn queue_room_returned(&self) -> impl Future<Output = ()>;

    /// [`crate::link::Link::next`].
    fn receive(&self, acl: &mut AclIn) -> impl Future<Output = Rx>;

    /// [`crate::link::Link::try_send`].
    ///
    /// # Errors
    ///
    /// As [`crate::link::Link::try_send`].
    fn send_fragment(&self, epoch: Epoch, start: bool, fragment: &[u8]) -> Result<(), link::Error>;

    /// [`crate::link::Link::hold_latency`].
    fn set_latency_hold(&self, hold: bool);

    /// Waits until `deadline`.
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;
}

/// Why [`Host::advertise`] returned without a link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum AdvertiseError {
    /// A link exists, which an earlier call returned.
    Connected,
    /// The link layer refused the setup or the advertising.
    Setup(adv::Error),
    /// Every phase of the schedule ran without a connection.
    Timeout,
}

/// A value the table reads through the [`Handler`] and the host notifies,
/// such as the battery level: one octet, kept in an atomic so the handler
/// and the application's task share it.
#[non_exhaustive]
pub struct Battery {
    /// The characteristic that notifies it.
    characteristic: Char,
    /// The level in percent.
    level:          AtomicU8,
}

/// The link the application holds: its events, its notifications and its
/// end. A link that ended gives [`ConnEvent::Disconnected`] and
/// [`NotifyError::Disconnected`], also once another link exists.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct Conn<'host, P> {
    /// The link.
    epoch: Epoch,
    /// The host.
    host:  &'host Host<P>,
}

/// AES-128 on the hardware ECB, through [`crate::crypto::encrypt_block`].
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct Ecb;

/// The chip's AES and random numbers for the host's tasks: the ECB and the
/// hardware random number generator ([`crate::rng::fill`]).
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct Hardware;

/// The host: the [`Engine`] behind a thread mode mutex, the [`Port`] to the
/// link layer and the signals between the tasks. See the module
/// documentation.
#[non_exhaustive]
pub struct Host<P> {
    /// A link arrived or the key pair is ready, for [`Host::advertise`].
    advertised: Signal<StateMutex, ()>,
    /// Events arrived, for [`Conn::next`].
    events:     Signal<StateMutex, ()>,
    /// A job waits, for [`Host::crypto`].
    jobs:       Signal<StateMutex, ()>,
    /// One notification at a time, so one task waits for room.
    notifier:   AsyncMutex<StateMutex, ()>,
    /// The link layer.
    port:       P,
    /// Room returned to the link layer's queue, for [`Conn::notify`].
    room:       Signal<StateMutex, ()>,
    /// The engine and the glue's own state.
    state:      Mutex<StateMutex, RefCell<State>>,
    /// Wakes [`Host::run`].
    wake:       Signal<StateMutex, ()>,
}

/// The state behind the host's mutex.
struct State {
    /// The protocol engine.
    engine:         Engine,
    /// Whether [`Conn::notify`] waits for room.
    notify_waiting: bool,
}

/// What an advertising call finds before it sets anything up.
enum Before {
    /// No link: it advertises.
    Free,
    /// A link kept from a call whose future was dropped: it returns it.
    Kept(Epoch),
    /// A link the call cannot take yet: it is ending, or the run task has
    /// not given it to the engine. The call waits.
    Pending,
    /// A link an earlier call returned: the call fails.
    Returned,
}

/// Ends the wait of an advertising call, also when its future is dropped:
/// stops advertising and lets the engine keep or end a link that arrived
/// for nobody.
struct Waiting<'host, P: Port> {
    /// The host.
    host:   &'host Host<P>,
    /// Whether the call returned a link: advertising ended with it.
    linked: bool,
}

impl fmt::Debug for ConnEvent {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BondUpdated(_) => f.debug_tuple("BondUpdated").finish_non_exhaustive(),
            Self::Bonded(_) => f.debug_tuple("Bonded").finish_non_exhaustive(),
            Self::Disconnected(reason) => f.debug_tuple("Disconnected").field(&reason).finish(),
            Self::Encrypted { bonded } => f.debug_struct("Encrypted").field("bonded", &bonded).finish(),
            #[cfg(feature = "key-missing")]
            Self::KeyMissing => f.write_str("KeyMissing"),
            Self::PairingFailed(reason) => f.debug_tuple("PairingFailed").field(&reason).finish(),
            #[cfg(feature = "param-requests")]
            Self::ParamsRejected => f.write_str("ParamsRejected"),
            Self::ParamsUpdated(params) => f.debug_tuple("ParamsUpdated").field(&params).finish(),
            #[cfg(feature = "passkey")]
            Self::PasskeyRequested => f.write_str("PasskeyRequested"),
            Self::Ready => f.write_str("Ready"),
        }
    }
}

impl From<AttNotifyError> for NotifyError {
    #[inline]
    fn from(error: AttNotifyError) -> Self {
        match error {
            AttNotifyError::Insecure => Self::Insecure,
            AttNotifyError::NotSubscribed => Self::NotSubscribed,
            AttNotifyError::Pending => Self::Busy,
            AttNotifyError::TooLong => Self::TooLong,
        }
    }
}

impl Aes for Ecb {
    #[inline]
    fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16] { encrypt_block(key, block) }
}

impl Aes for Hardware {
    #[inline]
    fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16] { encrypt_block(key, block) }
}

impl Battery {
    /// The level in percent.
    #[inline]
    #[must_use = "the level is only read"]
    pub fn level(&self) -> u8 { self.level.load(Ordering::Relaxed) }

    /// A value of `level` percent, which `characteristic` notifies.
    #[inline]
    #[must_use = "the value is only built"]
    pub const fn new(characteristic: Char, level: u8) -> Self { Self { characteristic, level: AtomicU8::new(level) } }

    /// Writes the level for a read through the [`Handler`] and returns its
    /// length.
    ///
    /// # Errors
    ///
    /// Unlikely Error (0x0E) without room for the octet.
    #[inline]
    pub fn read(&self, out: &mut [u8]) -> Result<usize, AttError> {
        let slot = out.first_mut().ok_or(AttError::UNLIKELY_ERROR)?;
        *slot = self.level();
        Ok(1)
    }

    /// Sets the level and, if it changed and the client of `conn` enabled
    /// notifications, notifies it.
    ///
    /// # Errors
    ///
    /// As [`Conn::notify`]; a level that did not change, or that nobody
    /// subscribed to, is no error.
    #[inline]
    pub async fn update<P>(&self, conn: &Conn<'_, P>, level: u8) -> Result<(), NotifyError>
    where
        P: Port,
    {
        let changed = self.level() != level;
        self.level.store(level, Ordering::Relaxed);
        if !changed || !conn.is_subscribed(self.characteristic) {
            return Ok(());
        }
        conn.notify(self.characteristic, &[level]).await
    }
}

impl<P> Conn<'_, P>
where
    P: Port,
{
    /// Ends the link with reason 0x13, remote user terminated the
    /// connection; [`ConnEvent::Disconnected`] follows.
    ///
    /// # Errors
    ///
    /// [`crate::link::Error::Gone`] if the link already ended.
    #[inline]
    pub fn disconnect(&self) -> Result<(), link::Error> { self.host.port.end_link(self.epoch, engine::REMOTE_USER) }

    /// Gives the passkey the user typed after [`ConnEvent::PasskeyRequested`].
    ///
    /// The six digits as a number, or `None` if the user gave up, which
    /// fails the pairing with Passkey Entry Failed (0x01):
    /// [`ConnEvent::PairingFailed`] follows. The run task hands it to the
    /// security manager, which then goes on with Passkey Entry.
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Gone`] once the link ended or is ending,
    /// [`PasskeyError::NotWaiting`] unless the pairing waits for the passkey
    /// and has none yet, [`PasskeyError::Invalid`] above 999 999.
    #[cfg(feature = "passkey")]
    #[inline]
    pub fn enter_passkey(&self, passkey: Option<u32>) -> Result<(), PasskeyError> {
        let result = self.host.with(|state| state.engine.enter_passkey(self.epoch, passkey));
        if result.is_ok() {
            self.host.wake.signal(());
        }
        result
    }

    /// The link.
    #[inline]
    #[must_use = "the link is only read"]
    pub const fn epoch(&self) -> Epoch { self.epoch }

    /// What the link layer said about the link, with the parameters it has
    /// now; `None` once it ended.
    #[inline]
    #[must_use = "the information is only read"]
    pub fn info(&self) -> Option<Info> { self.host.with(|state| state.engine.info(self.epoch)) }

    /// Whether the client enabled notifications of `characteristic`, on this
    /// link or, after encryption with the bond's key, before.
    #[inline]
    #[must_use = "the state is only read"]
    pub fn is_subscribed(&self, characteristic: Char) -> bool {
        self.host.with(|state| state.engine.is_subscribed(self.epoch, characteristic))
    }

    /// Waits for the next event of the link: see [`ConnEvent`]. One task
    /// reads them; dropping the future loses no event.
    #[inline]
    pub async fn next(&self) -> ConnEvent {
        loop {
            if let Some(event) = self.host.with(|state| state.engine.take_event(self.epoch)) {
                return event;
            }
            self.host.events.wait().await;
        }
    }

    /// Notifies `data` for `characteristic`, waiting while
    /// [`engine::Config::notify_depth`] fragments of the link are in flight,
    /// while the link layer's queue has fewer than two free places, or while
    /// a PDU of several fragments is being sent.
    ///
    /// # Errors
    ///
    /// Why it cannot be sent: never [`NotifyError::Busy`].
    #[inline]
    pub async fn notify(&self, characteristic: Char, data: &[u8]) -> Result<(), NotifyError> {
        let _turn = self.host.notifier.lock().await;
        loop {
            match self.host.send_notification(self.epoch, characteristic, data) {
                Err(NotifyError::Busy) => {},
                result => return result,
            }
            self.host.wake.signal(());
            self.host.room.wait().await;
        }
    }

    /// Asks the central for the connection parameters `range` with the
    /// L2CAP Connection Parameter Update Request, as
    /// [`engine::Engine::request_params`] says: the engine's own request of
    /// [`engine::Config::params`] is then not made on this link. The central
    /// answers with [`ConnEvent::ParamsRejected`], or updates the link,
    /// which [`ConnEvent::ParamsUpdated`] reports. The policy is the
    /// firmware's: a fallback range after a rejection or an interval that
    /// stays too long, a second request for the latency, with its own
    /// timers.
    ///
    /// ```no_run
    /// # use nrf_ble::{host::{ConnEvent, Conn, Port}, link::ParamRange};
    /// /// 11.25 to 15 ms, a latency of 30 events, 6 s.
    /// const FALLBACK: ParamRange = ParamRange::new(9, 12, 30, 600);
    ///
    /// async fn on_event<P: Port>(conn: &Conn<'_, P>, event: ConnEvent) {
    ///     if event == ConnEvent::ParamsRejected {
    ///         // Busy only while a request waits: the rejected one is done.
    ///         let _ = conn.request_params(FALLBACK);
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// [`RequestError::Gone`] once the link ended or is ending,
    /// [`RequestError::Invalid`] for a range out of the specification's,
    /// [`RequestError::Busy`] while an earlier request, the engine's or this
    /// one's, waits for its response.
    #[cfg(feature = "param-requests")]
    #[inline]
    pub fn request_params(&self, range: link::ParamRange) -> Result<(), RequestError> {
        let result = self.host.with(|state| state.engine.request_params(self.epoch, range));
        if result.is_ok() {
            // The run task queues it.
            self.host.wake.signal(());
        }
        result
    }

    /// The security of the link: encrypted once it is with a key the host
    /// gave, `None` once it ended. With the feature `passkey`,
    /// [`Sec::Authenticated`] when that key is the one of a Passkey Entry
    /// pairing, or of a bond whose `authenticated` is set; a reconnection
    /// with an unauthenticated bond stays encrypted.
    #[inline]
    #[must_use = "the security is only read"]
    pub fn security(&self) -> Option<Sec> { self.host.with(|state| state.engine.security(self.epoch)) }

    /// Notifies `data` for `characteristic` if there is room now, as
    /// [`Self::notify`] would.
    ///
    /// # Errors
    ///
    /// Why it cannot be sent: [`NotifyError::Busy`] without room now.
    #[inline]
    pub fn try_notify(&self, characteristic: Char, data: &[u8]) -> Result<(), NotifyError> {
        self.host.send_notification(self.epoch, characteristic, data)
    }
}

impl<P> Host<P>
where
    P: Port,
{
    /// Advertises as `advertising` says, under our `identity`, until a
    /// central connects, and returns the link; see the module documentation.
    ///
    /// In pairing mode it waits for the key pair of the next pairing first,
    /// and pairing distributes `identity`; in reconnection mode only the
    /// bonded central connects and may encrypt with the bond's key. A link
    /// kept from a call whose future was dropped is returned at once,
    /// without advertising. Before it sets anything up, the call waits for
    /// a link that nobody returned and that is ending, and for a connection
    /// the link layer made that the run task has not taken yet, so a link
    /// never sees the setup of a later call. One call at a time.
    ///
    /// # Errors
    ///
    /// [`AdvertiseError::Timeout`] after the last phase,
    /// [`AdvertiseError::Connected`] while a link this host returned
    /// exists, [`AdvertiseError::Setup`] if the link layer refused.
    #[inline]
    pub async fn advertise(
        &self,
        advertising: &Advertising<'_>,
        identity: &LocalIdentity,
    ) -> Result<Conn<'_, P>, AdvertiseError> {
        loop {
            let before = self.with(|state| {
                let engine = &mut state.engine;
                engine.claim().map_or_else(
                    || {
                        if engine.has_claimed_link() {
                            Before::Returned
                        } else if engine.has_link() || self.port.link_info().is_some() {
                            // A link that is ending, or one the run task has
                            // not given the engine yet: setting the engine up
                            // for this call now would change it under that
                            // link.
                            Before::Pending
                        } else {
                            Before::Free
                        }
                    },
                    Before::Kept,
                )
            });
            match before {
                Before::Free => break,
                Before::Kept(epoch) => return Ok(Conn { epoch, host: self }),
                Before::Pending => self.advertised.wait().await,
                Before::Returned => return Err(AdvertiseError::Connected),
            }
        }
        let mode = advertising.mode();
        let bond = match mode {
            Mode::Pairing => None,
            Mode::Reconnect(bond) => Some(bond.clone()),
        };
        let security = advertising.schedule().security_deadline;
        self.with(|state| state.engine.advertise(mode.pairable(), identity, bond, security));
        let mut waiting = Waiting { host: self, linked: false };
        self.jobs.signal(());
        while mode.pairable() && !self.with(|state| state.engine.has_key_pair()) {
            self.advertised.wait().await;
        }
        advertising.configure(&self.port, identity).map_err(AdvertiseError::Setup)?;
        let mut end = self.port.now();
        for phase in advertising.schedule().phases {
            match advertising.start(&self.port, phase) {
                // A central connected: its link is on the way.
                Ok(()) | Err(adv::Error::Link(link::Error::Disallowed)) => {},
                Err(error) => return Err(AdvertiseError::Setup(error)),
            }
            end = end.checked_add(phase.duration).unwrap_or(Instant::MAX);
            match select(self.link_arrived(advertising, phase), self.port.sleep_until(end)).await {
                Either::First(Ok(epoch)) => {
                    waiting.linked = true;
                    return Ok(Conn { epoch, host: self });
                },
                Either::First(Err(error)) => return Err(AdvertiseError::Setup(error)),
                Either::Second(()) => {},
            }
        }
        Err(AdvertiseError::Timeout)
    }

    /// Runs the P-256 jobs of pairing, with `crypto`'s random numbers and
    /// AES, calling `before_multiplication` right before each
    /// multiplication, for the watchdog, and yielding between two jobs.
    /// Spawn it as a task of its own; both are [`Send`], so its future is.
    #[inline]
    pub async fn crypto<C, F>(&self, crypto: &mut C, mut before_multiplication: F) -> !
    where
        C: Aes + Random + Send,
        F: FnMut() + Send,
    {
        loop {
            let Some(job) = self.with(|state| state.engine.take_job()) else {
                self.jobs.wait().await;
                continue;
            };
            // No lock is held during the multiplication.
            let result = job.run(crypto, &mut before_multiplication);
            let now = self.port.now();
            self.with(|state| state.engine.job_done(crypto, result, now));
            self.wake.signal(());
            self.advertised.signal(());
            yield_now().await;
        }
    }

    /// Makes the calls of the link layer the engine asks for and queues its
    /// fragments while there is room, then returns the next deadline and
    /// whether to wait for room.
    fn flush(&self, state: &mut State) -> (Option<Instant>, bool) {
        let now = self.port.now();
        let engine = &mut state.engine;
        engine.on_time(now);
        let in_flight = engine.epoch().map_or(0, |epoch| self.port.fragments_in_flight(epoch));
        while let Some(command) = engine.take_command(in_flight, now) {
            // A link that ended needs no answer: its event follows.
            let _gone: Result<(), link::Error> = match command {
                Command::Disconnect { epoch, reason } => self.port.end_link(epoch, reason),
                Command::HoldLatency(hold) => {
                    self.port.set_latency_hold(hold);
                    Ok(())
                },
                Command::LtkReply { epoch, mut key } => {
                    let result = self.port.answer_ltk(epoch, key);
                    if let Some(bytes) = key.as_mut() {
                        wipe(bytes);
                    }
                    result
                },
            };
        }
        while let Some(epoch) = engine.epoch()
            && let Some(fragment) = engine.next_fragment(self.port.queue_room())
            && self.port.send_fragment(epoch, fragment.start(), fragment.bytes()).is_ok()
        {
            engine.fragment_sent(now);
        }
        if engine.has_job() {
            self.jobs.signal(());
        }
        if engine.take_events_changed() {
            self.events.signal(());
        }
        (engine.next_deadline(), engine.has_output() || state.notify_waiting)
    }

    /// Waits until a link arrived for the advertising call, and claims it.
    /// The link layer stops advertising when a central connects: if that
    /// link ended before the run task gave it to the engine, or before the
    /// call claimed it, it advertises again for the rest of `phase`.
    ///
    /// # Errors
    ///
    /// If the link layer refused to advertise again.
    async fn link_arrived(&self, advertising: &Advertising<'_>, phase: &adv::Phase) -> Result<Epoch, adv::Error> {
        let mut woken = false;
        loop {
            let (claimed, linkless) =
                self.with(|state| (state.engine.claim(), !state.engine.has_link() && self.port.link_info().is_none()));
            if let Some(epoch) = claimed {
                return Ok(epoch);
            }
            if woken && linkless {
                match advertising.start(&self.port, phase) {
                    // Another central connected meanwhile.
                    Ok(()) | Err(adv::Error::Link(link::Error::Disallowed)) => {},
                    Err(error) => return Err(error),
                }
            }
            self.advertised.wait().await;
            woken = true;
        }
    }

    /// The host over `port`, with the table `db`, doing as `config` says.
    ///
    /// # Panics
    ///
    /// With the feature `passkey`, if the table has an attribute that needs
    /// authentication and `config` pairs with Just Works only: the attribute
    /// could never be reached. In a `static`, this fails the build.
    #[inline]
    #[must_use = "the host is only built"]
    pub const fn new(port: P, db: &'static Db, config: engine::Config) -> Self {
        #[cfg(feature = "passkey")]
        assert!(
            !db.needs_authentication() || config.security.protects(),
            "a table with authenticated attributes needs a configuration that pairs with Passkey Entry"
        );
        Self {
            advertised: Signal::new(),
            events: Signal::new(),
            jobs: Signal::new(),
            notifier: AsyncMutex::new(()),
            port,
            room: Signal::new(),
            state: Mutex::new(RefCell::new(State { engine: Engine::new(db, config), notify_waiting: false })),
            wake: Signal::new(),
        }
    }

    /// The port to the link layer.
    #[inline]
    #[must_use = "the port is only read"]
    pub const fn port(&self) -> &P { &self.port }

    /// Takes what the link layer gave, a fragment in `acl`, with `crypto`
    /// for the security manager and `app` for the dynamic values.
    fn receive<C>(&self, rx: Rx, acl: &AclIn, app: &dyn Handler, crypto: &mut C)
    where
        C: Aes + Random,
    {
        let now = self.port.now();
        let arrived = self.with(|state| match rx {
            Rx::Acl => {
                state.engine.on_acl(crypto, app, acl, now);
                false
            },
            Rx::Event(Event::Connected(epoch)) => {
                if let Some(info) = self.port.link_info().filter(|info| info.epoch == epoch) {
                    state.engine.connected(&info, now);
                }
                true
            },
            Rx::Event(event) => {
                state.engine.on_event(&event, now);
                matches!(event, Event::Disconnected(_))
            },
        });
        if arrived {
            // A link for the advertising call; or one that ended, whose
            // notifier learns it.
            self.advertised.signal(());
            self.room.signal(());
        }
    }

    /// Runs the host: see the module documentation. `app` serves the table's
    /// dynamic values, `crypto` gives the security manager its random
    /// numbers and AES. Spawn it as a task of its own; `app` is [`Sync`] and
    /// `crypto` [`Send`], so its future is [`Send`].
    ///
    /// `app` runs inside the host's state, so it must not call into the
    /// host: no [`Conn`] method, no [`Battery::update`] and no other
    /// [`Host`] method, or the second borrow of the state panics. It may read
    /// and write atomics and signal other tasks, as [`Battery::read`] does.
    #[inline]
    pub async fn run<C>(&self, app: &(dyn Handler + Sync), crypto: &mut C) -> !
    where
        C: Aes + Random + Send,
    {
        // Where the link layer puts a received fragment.
        let mut acl = AclIn::EMPTY;
        loop {
            // The passkey the application gave, for the security manager.
            #[cfg(feature = "passkey")]
            self.with(|state| state.engine.take_passkey(crypto, self.port.now()));
            let (deadline, room) = self.with(|state| self.flush(state));
            let timer = async {
                match deadline {
                    Some(at) => self.port.sleep_until(at).await,
                    None => pending().await,
                }
            };
            let room_changed = async {
                if room {
                    self.port.queue_room_returned().await;
                } else {
                    pending::<()>().await;
                }
            };
            let woken = select4(self.port.receive(&mut acl), timer, room_changed, self.wake.wait()).await;
            match woken {
                Either4::First(rx) => self.receive(rx, &acl, app, crypto),
                Either4::Third(()) => {
                    self.with(|state| state.notify_waiting = false);
                    self.room.signal(());
                },
                Either4::Second(()) | Either4::Fourth(()) => {},
            }
        }
    }

    /// Sends a notification on the link `epoch` if there is room now.
    fn send_notification(&self, epoch: Epoch, characteristic: Char, data: &[u8]) -> Result<(), NotifyError> {
        self.with(|state| {
            let result = state.engine.notification(epoch, characteristic, data).and_then(|fragment| {
                if self.port.queue_room() < 2 || self.port.fragments_in_flight(epoch) >= state.engine.notify_depth() {
                    return Err(NotifyError::Busy);
                }
                self.port.send_fragment(epoch, fragment.start(), fragment.bytes()).map_err(|error| match error {
                    link::Error::Full => NotifyError::Busy,
                    link::Error::Disallowed
                    | link::Error::Gone
                    | link::Error::Invalid
                    | link::Error::Unsupported
                    | link::Error::UnsupportedRemote => NotifyError::Disconnected,
                })
            });
            if result == Err(NotifyError::Busy) {
                state.notify_waiting = true;
            }
            result
        })
    }

    /// Runs `change` on the state behind the mutex.
    fn with<R>(&self, change: impl FnOnce(&mut State) -> R) -> R {
        self.state.lock(|cell| change(&mut cell.borrow_mut()))
    }
}

impl Port for Link<'_> {
    #[inline]
    fn answer_ltk(&self, epoch: Epoch, key: Option<[u8; 16]>) -> Result<(), link::Error> { self.ltk_reply(epoch, key) }

    #[inline]
    fn end_link(&self, epoch: Epoch, reason: u8) -> Result<(), link::Error> { self.disconnect(epoch, reason) }

    #[inline]
    fn fragments_in_flight(&self, epoch: Epoch) -> usize { self.in_flight(epoch) }

    #[inline]
    fn link_info(&self) -> Option<Info> { self.info() }

    #[inline]
    fn now(&self) -> Instant { Instant::now() }

    #[inline]
    fn queue_room(&self) -> usize { self.tx_room() }

    #[inline]
    fn queue_room_returned(&self) -> impl Future<Output = ()> { self.tx_room_changed() }

    #[inline]
    fn receive(&self, acl: &mut AclIn) -> impl Future<Output = Rx> { self.next(acl) }

    #[inline]
    fn send_fragment(&self, epoch: Epoch, start: bool, fragment: &[u8]) -> Result<(), link::Error> {
        self.try_send(epoch, start, fragment)
    }

    #[inline]
    fn set_latency_hold(&self, hold: bool) { self.hold_latency(hold); }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> { Timer::at(deadline) }
}

impl Random for Hardware {
    #[inline]
    fn fill(&mut self, out: &mut [u8]) { rng::fill(out); }
}

impl<P> Drop for Waiting<'_, P>
where
    P: Port,
{
    #[inline]
    fn drop(&mut self) {
        if !self.linked {
            let _stopped: Result<(), link::Error> = self.host.port.call(Call::StopAdvertising);
        }
        self.host.with(|state| state.engine.stop_waiting());
        self.host.wake.signal(());
    }
}

/// Software AES-128 in place of the ECB, for the host tests of every module.
#[cfg(test)]
pub(crate) mod test_aes {
    use super::Aes;
    use aes::{
        Aes128,
        cipher::{BlockCipherEncrypt as _, KeyInit as _},
    };

    /// Software AES-128 from the `aes` crate.
    pub(crate) struct Software;

    impl Aes for Software {
        fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
            let mut data = block.into();
            Aes128::new(&key.into()).encrypt_block(&mut data);
            data.into()
        }
    }
}

#[cfg(test)] mod example;
#[cfg(test)] mod tests;
