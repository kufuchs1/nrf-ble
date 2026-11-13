//! The protocol engine: all of the host's protocol state for one link,
//! without futures and without input or output of its own.
//!
//! [`Engine`] owns the L2CAP reassembly, the LE signalling channel, the ATT
//! server with the link's client characteristic configuration, the security
//! manager and the bond. The async glue of [`crate::host`] feeds it and
//! carries out what it asks for; the tests feed it the same way, with a time
//! of their own.
//!
//! # Input
//!
//! - The link layer's events ([`Engine::on_event`]), with the link's
//!   [`crate::link::Info`] for [`Event::Connected`] ([`Engine::connected`]).
//! - The received fragments ([`Engine::on_acl`]), with the application's
//!   [`Handler`] for the dynamic values.
//! - The time ([`Engine::on_time`]), once the deadline it gave
//!   ([`Engine::next_deadline`]) has passed.
//! - The results of the P-256 jobs ([`Engine::job_done`]).
//!
//! # Output
//!
//! - Fragments, pulled one at a time ([`Engine::next_fragment`]) with the room
//!   the link layer has, and confirmed once the link layer took each
//!   ([`Engine::fragment_sent`]). Nothing waits in a transmit buffer: the
//!   security manager renders its PDU again for each fragment, the ATT response
//!   and the signalling commands sit in one slot each. Responses and the
//!   security manager may take the last free place of the link layer's queue;
//!   the connection parameter request, which nothing waits for, leaves one
//!   free, as notifications do.
//! - Calls of the link layer ([`Engine::take_command`]): the long term key
//!   reply, the latency hold and disconnections.
//! - Jobs for the crypto task ([`Engine::take_job`]).
//! - Events for the application ([`Engine::take_event`]).
//!
//! # What it does on a link
//!
//! - It holds the peripheral latency off from the connection until discovery is
//!   over, then reports [`ConnEvent::Ready`] and lets the latency go. Linux
//!   reconnects with the latency it stored, and every ATT round trip would
//!   otherwise wait for it. Discovery is over on an encrypted link once the
//!   central acknowledged our Write Response to the write that left every input
//!   report's client characteristic configuration written on this link, and ATT
//!   has been idle for [`INPUTS_IDLE`] since: `BlueZ` creates its input device
//!   only once it received that response, and drops the reports before it.
//!   Without such a write, as with a table without input reports, ATT is to be
//!   idle for [`READY_IDLE`] on the encrypted link.
//! - Once ATT has been idle for [`PARAMS_IDLE`], it asks for the connection
//!   parameters of its [`Config`] with the L2CAP request, once per link and
//!   only if the link has others: the same constant as the Peripheral Preferred
//!   Connection Parameters, so `BlueZ` never finds the two disagreeing. Asked
//!   earlier, the update would stretch discovery. With the feature
//!   `param-requests` the application may ask itself
//!   (`host::Conn::request_params`), for a fallback or a second try, and learns
//!   of each rejection (`ConnEvent::ParamsRejected`); the engine's own request
//!   is then not made on that link.
//! - It answers a long term key request with EDIV 0 and Rand 0 only: with the
//!   key of the pairing under way, or with the bond's if the central is the
//!   bonded one, by its resolved identity or its identity address on the air.
//!   Any other request gets the negative reply.
//! - It gives the ATT server, for each request, the security the request was
//!   received with: encrypted only if each of its fragments was received
//!   encrypted ([`crate::link::AclIn::encrypted`]) on a link whose key the
//!   engine handed over itself. The encryption event may come later than the
//!   first encrypted request.
//! - It restores the bond's client characteristic configuration
//!   ([`crate::host::att::Server::restore`]) only once the link is encrypted
//!   with the bond's key, never at the connection: nothing is notified before
//!   the encryption, which also keeps the link layer's buffers free for the
//!   pairing's burst. Whatever the bonded central writes later goes into the
//!   bond, and [`ConnEvent::BondUpdated`] hands it to the application to store
//!   when it changed.
//! - It gives the security manager the identity the advertising was set up with
//!   ([`Engine::advertise`]), so pairing distributes the identity our
//!   resolvable private address was made from, and builds the bond from the
//!   pairing's outcome: the central's identity from
//!   [`crate::host::smp::Bonded::identity`], or its address when it sent none,
//!   and our variant. It reports [`ConnEvent::Bonded`] only once the central
//!   acknowledged every fragment sent so far, our Identity Address Information
//!   among them: the kernel stores its bond only when that PDU arrives, and a
//!   bond the firmware stored without it would make every reconnection fail.
//!   The [`crate::host::smp::Bonded`] it gets is `Copy`, so the engine
//!   overwrites its copy of the keys once the [`Bond`] holds them; the security
//!   manager overwrites its own Diffie-Hellman key, `MacKey` and long term key.
//! - It ends the link: [`SECURITY_FAILURE`] when the link is not encrypted
//!   within the advertising schedule's security deadline (with the feature
//!   `key-missing`, at once when the central of a reconnection asks for a key
//!   the host does not have, `ConnEvent::KeyMissing`), or when a pairing failed
//!   (once our Pairing Failed was acknowledged, or after [`FLUSH_TIMEOUT`]),
//!   and [`REMOTE_USER`] when the pairing timed out.
//!
//! The bonded central's resolving list entry replaces the one of pairing
//! mode, which carries our key under an all zero central address, when the
//! next advertising call sets the link layer up for reconnection
//! ([`crate::host::adv::Advertising::configure`]); a link that exists needs
//! neither.
//!
//! # A link that nobody waits for
//!
//! A central can connect after the advertising call that started the
//! advertising was dropped, for instance by the timeout of its phase while
//! the thread was busy. The [`Config`] says what happens to such a link
//! ([`Unclaimed`]): kept for the next advertising call, which returns it at
//! once, or ended with [`REMOTE_USER`].
//!
//! Not served: indications, with the Service Changed indication, its ordering
//! after the Write Response and its 30 s confirmation timer (for a table
//! with Service Changed); the LE credit based channels; and an MTU
//! above 23.

#[cfg(feature = "passkey")]
use crate::host::PasskeyError;
#[cfg(feature = "param-requests")]
use crate::host::RequestError;
use crate::{
    crypto::wipe,
    host::{
        Aes,
        ConnEvent,
        NotifyError,
        att::{MTU, Server, WRITE_COMMAND, WRITE_REQUEST, WRITE_RESPONSE},
        bond::Bond,
        gatt::{CCCD_MAX, Char, Db, Handler, Sec},
        identity::{self, Variant},
        l2cap::{Channel, Fragment, RX_MAX, Reassembly, Segmenter},
        signal::{self, Action, Signalling},
        smp::{self, Job, JobResult, Outcome, Random, Reason, Responder},
    },
    link::{AclIn, ConnectionParams, Epoch, Event, Info, ParamRange},
};
use core::mem;
use embassy_time::{Duration, Instant};

/// The time ATT is to be idle before discovery counts as over.
///
/// It counts on an encrypted link once the central acknowledged the Write
/// Response that completed the input reports' configuration; then comes
/// [`ConnEvent::Ready`], and the latency hold ends.
pub const INPUTS_IDLE: Duration = Duration::from_millis(100);
/// The time ATT is to be idle before discovery counts as over without that
/// write.
///
/// It is the fallback of [`INPUTS_IDLE`] on an encrypted link, longer than
/// the gaps of `BlueZ`'s discovery, so a reconnection whose writes come late
/// still waits for them.
pub const READY_IDLE: Duration = Duration::from_millis(1000);
/// The time ATT is to be idle before the connection parameters are asked
/// for.
pub const PARAMS_IDLE: Duration = Duration::from_millis(1500);
/// How many fragments of the link may be in flight for a notification to go
/// out, by default: one report is always queued when the central
/// acknowledges the one before ([`Config::with_notify_depth`]).
pub const NOTIFY_DEPTH: u8 = 2;
/// The longest wait for the response to our connection parameter request.
pub const SIGNALLING_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest wait for our Pairing Failed to be acknowledged before the
/// link ends.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(1);
/// Disconnection reason: authentication failure.
pub const SECURITY_FAILURE: u8 = 0x05;
/// Disconnection reason: remote user terminated the connection.
pub const REMOTE_USER: u8 = 0x13;

/// Event flag: a pairing failed.
const EV_PAIRING_FAILED: Flags = 0x01;
/// Event flag: the link is encrypted.
const EV_ENCRYPTED: Flags = 0x02;
/// Event flag, with [`EV_ENCRYPTED`]: with the bond's key.
const EV_WITH_BOND: Flags = 0x04;
/// Event flag: a pairing made a bond.
const EV_BONDED: Flags = 0x08;
/// Event flag: the bond's subscriptions changed.
const EV_BOND_UPDATED: Flags = 0x10;
/// Event flag: the connection parameters changed.
const EV_PARAMS: Flags = 0x20;
/// Event flag: discovery is over.
const EV_READY: Flags = 0x40;
/// Event flag: the central rejected a connection parameter request.
#[cfg(feature = "param-requests")]
const EV_PARAMS_REJECTED: Flags = 0x80;
/// Event flag: the bonded central asked for a key the host does not have.
#[cfg(feature = "key-missing")]
const EV_KEY_MISSING: Flags = 0x100;
/// Event flag: Passkey Entry asks for the passkey.
#[cfg(feature = "passkey")]
const EV_PASSKEY: Flags = 0x200;
/// What the user typed for Passkey Entry when they gave up: out of the
/// range of passkeys, as [`smp::NO_PASSKEY`] is.
#[cfg(feature = "passkey")]
const REFUSED: u32 = smp::NO_PASSKEY - 1;

/// The events waiting, one `EV_` bit each: eight fit without the optional
/// events.
#[cfg(not(any(feature = "key-missing", feature = "passkey")))]
type Flags = u8;
/// The events waiting, one `EV_` bit each.
#[cfg(any(feature = "key-missing", feature = "passkey"))]
type Flags = u16;

/// A call of the link layer the engine asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Command {
    /// [`crate::link::Link::disconnect`].
    Disconnect {
        /// The link.
        epoch:  Epoch,
        /// The reason.
        reason: u8,
    },
    /// [`crate::link::Link::hold_latency`].
    HoldLatency(bool),
    /// [`crate::link::Link::ltk_reply`]; the caller overwrites the key once
    /// it was given.
    LtkReply {
        /// The link.
        epoch: Epoch,
        /// The key, least significant octet first, or `None` for the
        /// negative reply.
        key:   Option<[u8; 16]>,
    },
}

/// The calls of the link layer that wait to be made.
struct Commands {
    /// The disconnection to ask for, with the link and the reason.
    disconnect: Option<(Epoch, u8)>,
    /// The latency hold, if it changed.
    hold:       Option<bool>,
    /// The long term key reply, with the link.
    ltk:        Option<(Epoch, Option<[u8; 16]>)>,
}

/// What the engine does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Config {
    /// How many fragments of the link may be in flight, queued or on the air
    /// and not acknowledged, for a notification to go out:
    /// [`NOTIFY_DEPTH`] unless [`Self::with_notify_depth`] changes it.
    pub notify_depth: u8,
    /// The connection parameters to ask for once ATT is idle, `None` to keep
    /// the central's.
    pub params:       Option<ParamRange>,
    /// What pairing protects against: Just Works by default, Passkey Entry
    /// as a keyboard with [`Self::with_security`].
    #[cfg(feature = "passkey")]
    pub security:     smp::Security,
    /// What happens to a link that arrives while no advertising call waits.
    pub unclaimed:    Unclaimed,
}

/// The protocol state of the host: see the module documentation.
pub struct Engine {
    /// The attribute server of the link.
    att:           Server,
    /// The bond: the one the advertising was set up with, or the one the
    /// pairing on the link made.
    bond:          Option<Bond> = None,
    /// The calls of the link layer that wait.
    commands:      Commands = Commands { disconnect: None, hold: None, ltk: None },
    /// What the engine does.
    config:        Config,
    /// The table.
    db:            &'static Db,
    /// The events for the application.
    events:        Events,
    /// The link, while one exists.
    link:          Option<LinkState> = None,
    /// The passkey the application gave, or [`REFUSED`], until the run task
    /// hands it to the security manager; otherwise [`smp::NO_PASSKEY`],
    /// which overwrites all of its digits.
    #[cfg(feature = "passkey")]
    passkey_input: u32 = smp::NO_PASSKEY,
    /// The ATT response waiting to be sent.
    response:      Option<Slot> = None,
    /// The reassembly of received fragments.
    rx:            Reassembly = Reassembly::new(),
    /// Time from a connection until it has to be encrypted.
    security:      Duration = Duration::MAX,
    /// The PDU being sent, with its fragments so far.
    sending:       Option<(Source, Segmenter)> = None,
    /// Our signalling reply waiting to be sent.
    sig_reply:     Option<signal::Command> = None,
    /// Our connection parameter request waiting to be sent.
    sig_req:       Option<signal::Command> = None,
    /// The signalling channel.
    signal:        Signalling = Signalling::new(),
    /// The security manager.
    smp:           Responder,
    /// The variant of our identity the advertising was set up with.
    variant:       Variant = Variant::new(0, 0),
    /// Whether an advertising call waits for a link.
    waiting:       bool = false,
}

/// The events for the application, of the link that last connected.
struct Events {
    /// Whether an event arrived since [`Engine::take_events_changed`].
    changed: bool,
    /// The link that ended last, with the reason.
    ended:   Option<(Epoch, u8)>,
    /// The link the events belong to.
    epoch:   Option<Epoch>,
    /// The events waiting, as `EV_` flags.
    flags:   Flags,
    /// The connection parameters of [`EV_PARAMS`].
    params:  ConnectionParams,
    /// The reason of [`EV_PAIRING_FAILED`].
    reason:  Reason,
}

/// Where a link is after the encryption.
struct Discovery {
    /// Whether a pairing bonded and [`ConnEvent::Bonded`] waits until
    /// nothing is in flight.
    bonding:  bool = false,
    /// Whether discovery is over.
    ready:    bool = false,
    /// Whether the bond's subscriptions were restored, or need not be.
    restored: bool = false,
}

/// Who holds a link, and whether it is to end: a link that no advertising
/// call took may be ended for nobody ([`Unclaimed::Disconnect`]).
struct Fate {
    /// Whether an advertising call returned the link.
    claimed: bool = false,
    /// Whether the disconnection was asked for; the link layer's event
    /// follows.
    closing: bool = false,
    /// Whether the link is to end once the security manager sent its last
    /// PDU, our Pairing Failed.
    failing: bool = false,
}

/// Where the link is with the configuration of its input reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Inputs {
    /// The central acknowledged the Write Response that completed it.
    Acked,
    /// The Write Response that completes it waits in the response slot.
    Answering,
    /// Not complete on this link yet.
    Open,
    /// The Write Response that completed it was queued: the next time
    /// nothing is in flight, the central has it.
    Sent,
}

/// Which key the host gave the link layer for the link.
#[derive(Clone, Copy, Debug, Eq)]
#[derive_const(PartialEq)]
enum Key {
    /// The bond's.
    Bond,
    /// The pairing's under way.
    Pairing,
    /// The pairing's under way, which is Passkey Entry: recorded when the
    /// key went to the link layer, so a later Pairing Request on the link
    /// cannot change it.
    #[cfg(feature = "passkey")]
    Passkey,
}

/// The state of the link.
struct LinkState {
    /// When ATT last received or sent a PDU, or the link became encrypted.
    activity:  Instant,
    /// Whether the connection parameters were asked for.
    asked:     bool,
    /// When our connection parameter request times out.
    asking:    Option<Instant>,
    /// Where the link is after the encryption.
    discovery: Discovery,
    /// Whether the link is encrypted with a key the host gave.
    encrypted: bool,
    /// Ending once the link layer has no fragment in flight, or at the
    /// instant: the reason.
    ending:    Option<(u8, Instant)>,
    /// Who holds the link, and whether it is to end.
    fate:      Fate,
    /// What the link layer said about the link.
    info:      Info,
    /// The configuration of the input reports on this link.
    inputs:    Inputs,
    /// The key the host gave for the link.
    key:       Option<Key>,
    /// The connection parameters.
    params:    ConnectionParams,
    /// When the link has to be encrypted.
    security:  Option<Instant>,
}

/// One PDU's payload, rendered for a fragment.
struct Payload {
    /// The octets, of which the first `len` count.
    bytes: [u8; smp::PDU_MAX],
    /// Their number.
    len:   usize,
}

/// One PDU in a slot: its octets and their number.
#[derive(Clone, Copy)]
struct Slot {
    /// The octets.
    bytes: [u8; MTU],
    /// Their number.
    len:   u8,
}

/// Where the PDU being sent comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Source {
    /// The ATT response slot.
    Att,
    /// Our signalling reply.
    Reply,
    /// Our connection parameter request.
    Request,
    /// The security manager.
    Smp,
}

/// What happens to a link that arrives while no advertising call waits for
/// one, because the call's future was dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unclaimed {
    /// It ends at once with [`REMOTE_USER`].
    Disconnect,
    /// The next advertising call returns it without advertising.
    Keep,
}

impl Unclaimed {
    /// The name of the choice, for a defmt log line (`{=istr}`): interned,
    /// so the string stays in the `.defmt` section, which takes no flash.
    #[cfg(feature = "defmt")]
    #[inline]
    #[must_use = "the name is only read"]
    pub fn name(self) -> defmt::Str {
        match self {
            Self::Disconnect => defmt::intern!("Disconnect"),
            Self::Keep => defmt::intern!("Keep"),
        }
    }
}

impl Config {
    /// A configuration asking for `params` and treating a link nobody waits
    /// for as `unclaimed` says.
    #[inline]
    #[must_use = "the configuration is only built"]
    pub const fn new(params: Option<ParamRange>, unclaimed: Unclaimed) -> Self {
        Self {
            notify_depth: NOTIFY_DEPTH,
            params,
            #[cfg(feature = "passkey")]
            security: smp::Security::JUST_WORKS,
            unclaimed,
        }
    }

    /// This configuration, letting a notification go out while fewer than
    /// `depth` fragments of the link are in flight, at least one: 3 queues a
    /// button or key report behind two movement reports, where
    /// [`NOTIFY_DEPTH`] holds it until the central acknowledged one of them.
    /// On the nRF52832, which prepares the next PDU while its answer goes out,
    /// it can then join them in the same connection event if the central
    /// keeps the event open (MD); the nRF51 sends one new PDU per event, so
    /// there it only waits in the queue and goes out at a later event. The
    /// link layer's queue bounds it too, as a notification always leaves one
    /// place free.
    #[inline]
    #[must_use = "the configuration is only built"]
    pub const fn with_notify_depth(self, depth: u8) -> Self {
        Self { notify_depth: if depth == 0 { 1 } else { depth }, ..self }
    }

    /// This configuration, pairing with `security`: for a keyboard,
    /// `Security::new(IoCapability::KeyboardOnly, true)`, Passkey Entry
    /// only.
    #[cfg(feature = "passkey")]
    #[inline]
    #[must_use = "the configuration is only built"]
    pub const fn with_security(self, security: smp::Security) -> Self { Self { security, ..self } }
}

impl Engine {
    /// Sets the engine up for an advertising call: whether a Pairing Request
    /// is taken, our `identity` for the security manager, the `bond` whose
    /// central may encrypt with its key, and the time a link gets to become
    /// encrypted. A pairable call asks for a key pair at once, so pairing
    /// never waits for one; the call waits for it before it advertises
    /// ([`Self::has_key_pair`]).
    #[inline]
    pub fn advertise(&mut self, pairable: bool, identity: &identity::Local, bond: Option<Bond>, security: Duration) {
        self.smp.set_pairable(pairable);
        self.smp.set_identity(identity.irk(), identity.address());
        self.variant = identity.variant();
        self.bond = bond;
        self.security = security;
        self.waiting = true;
        if pairable {
            self.smp.prepare_key_pair();
        }
    }

    /// Answers an ATT PDU received `encrypted` or not.
    fn att_pdu(&mut self, app: &dyn Handler, pdu: &[u8], encrypted: bool, now: Instant) {
        let Some(link) = self.link.as_mut() else { return };
        link.activity = now;
        let received = if encrypted && link.key.is_some() { Sec::Encrypted } else { Sec::Open };
        if received == Sec::Encrypted {
            // Proof of the encryption, which its event may follow later.
            link.encrypted = true;
            link.security = None;
            self.restore();
        }
        #[cfg(feature = "passkey")]
        let level = self.raised(received);
        #[cfg(not(feature = "passkey"))]
        let level = received;
        let mut out: [u8; MTU] = [0; MTU];
        if let Some(len) = self.att.handle(pdu, level, app, &mut out) {
            if self.response.is_none() {
                self.response = Some(Slot { bytes: out, len: u8::try_from(len).unwrap_or_default() });
                if pdu.first() == Some(&WRITE_REQUEST)
                    && out.first() == Some(&WRITE_RESPONSE)
                    && self.inputs_written()
                    && let Some(answering) = self.link.as_mut()
                    && answering.inputs == Inputs::Open
                {
                    answering.inputs = Inputs::Answering;
                }
            } else {
                // A client waits for each response before its next request.
                info!("att: a request before the response to the previous one");
            }
        }
        if matches!(pdu.first(), Some(&(WRITE_REQUEST | WRITE_COMMAND))) {
            self.update_bond();
        }
    }

    /// Whether the link is encrypted with a key of authenticated pairing:
    /// that of a Passkey Entry pairing, as it was when the key went to the
    /// link layer, or the bond's, if its pairing was.
    #[cfg(feature = "passkey")]
    const fn authenticated(&self) -> bool {
        match self.link.as_ref().and_then(const |link| link.key) {
            Some(Key::Bond) => self.bond.as_ref().is_some_and(const |bond| bond.authenticated),
            Some(Key::Passkey) => true,
            Some(Key::Pairing) | None => false,
        }
    }

    /// The bond.
    #[inline]
    #[must_use = "the bond is only read"]
    pub const fn bond(&self) -> Option<&Bond> { self.bond.as_ref() }

    /// The key the bond gives the link layer's request with `ediv` and
    /// `rand`: only EDIV 0 and Rand 0, and only for the bonded central.
    const fn bond_key(&self, ediv: u16, rand: [u8; 8]) -> Option<[u8; 16]> {
        let bond = self.bond.as_ref()?;
        let info = &self.link.as_ref()?.info;
        let bonded = info.identity == Some(bond.peer) || info.peer == bond.peer;
        (ediv == 0 && rand == [0; 8] && bonded).then_some(bond.ltk)
    }

    /// Returns the link that arrived for the advertising call that waits, or
    /// for a call that was dropped, once; never one that is ending.
    #[inline]
    pub const fn claim(&mut self) -> Option<Epoch> {
        let link = self
            .link
            .as_mut()
            .filter(const |link| !link.fate.claimed && !link.fate.closing && link.ending.is_none())?;
        link.fate.claimed = true;
        Some(link.info.epoch)
    }

    /// Starts the link described by `info`, at `now`.
    #[inline]
    pub fn connected(&mut self, info: &Info, now: Instant) {
        if let Some(link) = self.link.as_ref() {
            // The link layer reports each end before the next start.
            let epoch = link.info.epoch;
            self.disconnected(epoch, 0);
        }
        self.smp.connected(info);
        let security = now.checked_add(self.security).unwrap_or(Instant::MAX);
        self.link = Some(LinkState {
            activity:  now,
            asked:     false,
            asking:    None,
            discovery: Discovery { .. },
            encrypted: false,
            ending:    None,
            fate:      Fate { .. },
            info:      *info,
            inputs:    Inputs::Open,
            key:       None,
            params:    info.params,
            security:  Some(security),
        });
        self.events.epoch = Some(info.epoch);
        self.events.flags = 0;
        self.commands.hold = Some(true);
        if !self.waiting && self.config.unclaimed == Unclaimed::Disconnect {
            info!("a link nobody waits for ends");
            self.commands.disconnect = Some((info.epoch, REMOTE_USER));
            if let Some(link) = self.link.as_mut() {
                link.fate.closing = true;
            }
        }
    }

    /// Forgets the link `epoch`, which ended for `reason`.
    fn disconnected(&mut self, epoch: Epoch, reason: u8) {
        if self.link.as_ref().is_none_or(|link| link.info.epoch != epoch) {
            return;
        }
        self.link = None;
        self.events.ended = Some((epoch, reason));
        self.events.changed = true;
        self.smp.disconnected();
        self.att = Server::new(self.db);
        self.signal = Signalling::new();
        self.rx = Reassembly::new();
        self.response = None;
        self.sending = None;
        self.sig_reply = None;
        self.sig_req = None;
        #[cfg(feature = "passkey")]
        smp::forget(&mut self.passkey_input, smp::NO_PASSKEY);
        self.commands.disconnect = None;
        if let Some(entry) = self.commands.ltk.as_mut()
            && let Some(key) = entry.1.as_mut()
        {
            wipe(key);
        }
        self.commands.ltk = None;
        self.commands.hold = Some(false);
    }

    /// Takes the encryption of the link, as the link layer reports it.
    fn encryption(&mut self, on: bool, refresh: bool, now: Instant) {
        let outcome = if refresh { None } else { self.smp.encryption_changed(on) };
        if let Some(link) = self.link.as_mut()
            && let Some(key) = link.key
        {
            if on {
                link.encrypted = true;
                link.security = None;
                link.activity = now;
                if !refresh {
                    self.events.flags |= EV_ENCRYPTED | if key == Key::Bond { EV_WITH_BOND } else { 0 };
                    self.events.changed = true;
                }
                self.restore();
            } else {
                info!("encryption failed");
            }
        }
        #[cfg(feature = "key-missing")]
        if !on
            && !refresh
            && !self.smp.is_pairable()
            && self.bond.is_some()
            && let Some(link) = self.link.as_mut()
            && link.key.is_none()
            && !link.fate.closing
        {
            // A reconnection: only the bonded central connects, and it has
            // no key the host knows. Waiting for the security deadline
            // would only keep it connected without encryption.
            info!("the central has no key of the bond: the link ends");
            link.fate.closing = true;
            link.security = None;
            self.commands.disconnect = Some((link.info.epoch, SECURITY_FAILURE));
            self.events.flags |= EV_KEY_MISSING;
            self.events.changed = true;
        }
        self.outcome(outcome, now);
    }

    /// Takes the passkey the user typed for the pairing on the link `epoch`.
    ///
    /// `None` means the user gave up, which fails the pairing with Passkey
    /// Entry Failed (0x01). The security manager gets it from
    /// [`Self::take_passkey`].
    ///
    /// # Errors
    ///
    /// [`PasskeyError::Gone`] without the link,
    /// [`PasskeyError::NotWaiting`] unless the pairing waits for the
    /// passkey and has none yet, [`PasskeyError::Invalid`] above
    /// [`smp::PASSKEY_MAX`].
    #[cfg(feature = "passkey")]
    #[inline]
    pub fn enter_passkey(&mut self, epoch: Epoch, passkey: Option<u32>) -> Result<(), PasskeyError> {
        self.link
            .as_ref()
            .filter(|link| link.info.epoch == epoch && !link.fate.closing && link.ending.is_none())
            .ok_or(PasskeyError::Gone)?;
        if self.passkey_input != smp::NO_PASSKEY || !self.smp.awaits_passkey() {
            return Err(PasskeyError::NotWaiting);
        }
        if passkey.is_some_and(|value| value > smp::PASSKEY_MAX) {
            return Err(PasskeyError::Invalid);
        }
        self.passkey_input = passkey.unwrap_or(REFUSED);
        Ok(())
    }

    /// The link, if one exists.
    #[inline]
    #[must_use = "the link is only read"]
    pub const fn epoch(&self) -> Option<Epoch> { self.link.as_ref().map(const |link| link.info.epoch) }

    /// Notes that the fragment [`Self::next_fragment`] gave was queued by the
    /// link layer, at `now`.
    #[inline]
    pub fn fragment_sent(&mut self, now: Instant) {
        let Some((source, mut segmenter)) = self.sending.take() else { return };
        segmenter.advance();
        if !segmenter.is_done() {
            self.sending = Some((source, segmenter));
            return;
        }
        match source {
            Source::Att => {
                self.response = None;
                if let Some(link) = self.link.as_mut() {
                    link.activity = now;
                    if link.inputs == Inputs::Answering {
                        link.inputs = Inputs::Sent;
                    }
                }
            },
            Source::Reply => self.sig_reply = None,
            Source::Request => {
                self.sig_req = None;
                if let Some(link) = self.link.as_mut() {
                    link.asking = Some(now.checked_add(SIGNALLING_TIMEOUT).unwrap_or(Instant::MAX));
                }
            },
            Source::Smp => {
                let outcome = self.smp.pdu_sent(now);
                self.outcome(outcome, now);
                if let Some(link) = self.link.as_mut()
                    && link.fate.failing
                    && !self.smp.has_output()
                {
                    link.fate.failing = false;
                    link.ending = Some((SECURITY_FAILURE, now.checked_add(FLUSH_TIMEOUT).unwrap_or(Instant::MAX)));
                }
            },
        }
    }

    /// Whether a link exists that an advertising call returned.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn has_claimed_link(&self) -> bool { self.link.as_ref().is_some_and(const |link| link.fate.claimed) }

    /// Whether a job waits for the crypto task.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn has_job(&self) -> bool { self.smp.has_job() }

    /// Whether a key pair is ready for the next pairing.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn has_key_pair(&self) -> bool { self.smp.has_key_pair() }

    /// Whether a link exists, claimed or not.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn has_link(&self) -> bool { self.link.is_some() }

    /// Whether output waits for room in the link layer's queue, or something
    /// waits for the fragments in flight to be acknowledged (a
    /// disconnection, [`ConnEvent::Bonded`], the end of discovery): then the
    /// glue also waits for [`crate::link::Link::tx_room_changed`], which an
    /// acknowledgement wakes too.
    #[inline]
    #[must_use = "the state is only read"]
    pub fn has_output(&self) -> bool {
        self.link.as_ref().is_some_and(|link| {
            link.ending.is_some()
                || link.discovery.bonding
                || link.inputs == Inputs::Sent
                || self.sending.is_some()
                || self.smp.has_output()
                || self.response.is_some()
                || self.sig_reply.is_some()
                || self.sig_req.is_some()
        })
    }

    /// The link `epoch`'s information, with the parameters it has now.
    #[inline]
    #[must_use = "the information is only read"]
    pub fn info(&self, epoch: Epoch) -> Option<Info> {
        let link = self.link.as_ref().filter(|link| link.info.epoch == epoch)?;
        let mut info = link.info;
        info.params = link.params;
        Some(info)
    }

    /// Whether the client wrote, on this link, the configuration of every
    /// input report of the table that notifies; false for a table without
    /// one.
    fn inputs_written(&self) -> bool {
        let inputs = self.db.input_reports();
        let subscriptions = self.att.subscriptions();
        inputs != 0
            && (0..CCCD_MAX)
                .all(|index| inputs.wrapping_shr(u32::from(index)) & 1 == 0 || subscriptions.is_written(index))
    }

    /// Whether the client of the link `epoch` enabled notifications of
    /// `characteristic`, restored ones included.
    #[inline]
    #[must_use = "the state is only read"]
    pub fn is_subscribed(&self, epoch: Epoch, characteristic: Char) -> bool {
        self.link.as_ref().is_some_and(|link| link.info.epoch == epoch)
            && characteristic.cccd().is_some_and(|index| self.att.subscriptions().notifying(index))
    }

    /// Takes the result of a job, at `now`.
    #[inline]
    pub fn job_done<C>(&mut self, crypto: &mut C, result: JobResult, now: Instant)
    where
        C: Aes + Random,
    {
        let outcome = self.smp.job_done(crypto, result);
        self.outcome(outcome, now);
    }

    /// Answers the link layer's long term key request.
    fn ltk_request(&mut self, ediv: u16, rand: [u8; 8]) {
        #[cfg(not(feature = "passkey"))]
        let pairing = self.smp.ltk_request(ediv, rand).map(|key| (key, Key::Pairing));
        // Passkey Entry or not, as it is now: a later Pairing Request on the
        // link cannot change it.
        #[cfg(feature = "passkey")]
        let kind = if self.smp.is_authenticating() { Key::Passkey } else { Key::Pairing };
        #[cfg(feature = "passkey")]
        let pairing = self.smp.ltk_request(ediv, rand).map(|key| (key, kind));
        let answer = pairing.or_else(|| self.bond_key(ediv, rand).map(|key| (key, Key::Bond)));
        let Some(link) = self.link.as_mut() else { return };
        link.key = answer.map(|(_, source)| source);
        if answer.is_none() {
            info!("no key for the central's request");
        }
        self.commands.ltk = Some((link.info.epoch, answer.map(|(key, _)| key)));
    }

    /// An engine over the table `db`, with no link, no bond and no
    /// identity.
    #[inline]
    #[must_use = "the engine is only built"]
    pub const fn new(db: &'static Db, config: Config) -> Self {
        Self {
            att: Server::new(db),
            config,
            db,
            events: Events {
                changed: false,
                ended:   None,
                epoch:   None,
                flags:   0,
                params:  ConnectionParams::new(0, 0, 0),
                reason:  Reason::UNSPECIFIED,
            },
            #[cfg(not(feature = "passkey"))]
            smp: Responder::new(),
            #[cfg(feature = "passkey")]
            smp: Responder::with_security(config.security),
            ..
        }
    }

    /// The next instant to give to [`Self::on_time`], if any.
    #[inline]
    #[must_use = "the deadline is only read"]
    pub fn next_deadline(&self) -> Option<Instant> {
        let link = self.link.as_ref()?;
        let ready = (link.encrypted && !link.discovery.ready).then(|| link.activity.checked_add(link.ready_idle()));
        let params = (link.discovery.ready && !link.asked && self.config.params.is_some())
            .then(|| link.activity.checked_add(PARAMS_IDLE));
        [
            self.smp.deadline(),
            link.security,
            ready.flatten(),
            params.flatten(),
            link.asking,
            link.ending.map(|end| end.1),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The next fragment to queue, given the `room` in the link layer's
    /// queue; `None` without one, or without room for it. Call
    /// [`Self::fragment_sent`] once the link layer took it, and nothing else
    /// that changes the engine in between.
    #[inline]
    pub fn next_fragment(&mut self, room: usize) -> Option<Fragment> {
        if room == 0 || self.link.is_none() {
            return None;
        }
        let (source, payload) = match self.sending {
            Some((source, _)) => (source, self.payload(source)?),
            None => [Source::Smp, Source::Reply, Source::Att, Source::Request]
                .into_iter()
                .filter(|&source| source != Source::Request || room >= 2)
                .find_map(|source| self.payload(source).map(|payload| (source, payload)))?,
        };
        let bytes = payload.bytes.get(..payload.len)?;
        let segmenter = match self.sending {
            Some((_, segmenter)) => segmenter,
            None => Segmenter::new(source.channel(), bytes.len())?,
        };
        self.sending = Some((source, segmenter));
        segmenter.fragment(bytes)
    }

    /// The notification of `data` for `characteristic` on the link `epoch`,
    /// as the one fragment it fits.
    ///
    /// # Errors
    ///
    /// Why it cannot be sent: [`NotifyError::Busy`] while a PDU of several
    /// fragments is being sent, so the two never interleave. The room in the
    /// link layer's queue is the caller's to check.
    #[inline]
    pub fn notification(&self, epoch: Epoch, characteristic: Char, data: &[u8]) -> Result<Fragment, NotifyError> {
        let link = self
            .link
            .as_ref()
            .filter(|link| link.info.epoch == epoch && !link.fate.closing && link.ending.is_none())
            .ok_or(NotifyError::Disconnected)?;
        let encryption = if link.encrypted { Sec::Encrypted } else { Sec::Open };
        #[cfg(feature = "passkey")]
        let level = self.raised(encryption);
        #[cfg(not(feature = "passkey"))]
        let level = encryption;
        let mut out: [u8; MTU] = [0; MTU];
        let len = self.att.notify(characteristic, data, level, &mut out).map_err(NotifyError::from)?;
        if self.sending.is_some_and(|(_, segmenter)| segmenter.is_mid_pdu()) {
            return Err(NotifyError::Busy);
        }
        let bytes = out.get(..len).ok_or(NotifyError::TooLong)?;
        Segmenter::new(Channel::Att, len).and_then(|segmenter| segmenter.fragment(bytes)).ok_or(NotifyError::TooLong)
    }

    /// How many fragments of the link may be in flight for a notification to
    /// go out ([`Config::notify_depth`]), at least one.
    #[inline]
    #[must_use = "the depth is only read"]
    pub const fn notify_depth(&self) -> usize { usize::from(self.config.notify_depth.max(1)) }

    /// Takes a fragment the link layer received, at `now`, with `crypto` for
    /// the security manager and `app` for the dynamic values.
    #[inline]
    pub fn on_acl<C>(&mut self, crypto: &mut C, app: &dyn Handler, acl: &AclIn, now: Instant)
    where
        C: Aes + Random,
    {
        if self.link.is_none() {
            return;
        }
        let mut buffer: [u8; RX_MAX] = [0; RX_MAX];
        let Some((channel, encrypted, len)) = self.rx.push_acl(acl).map(|pdu| {
            let len = pdu.payload.len().min(RX_MAX);
            if let (Some(target), Some(source)) = (buffer.get_mut(..len), pdu.payload.get(..len)) {
                target.copy_from_slice(source);
            }
            (pdu.channel, pdu.encrypted, len)
        }) else {
            return;
        };
        let pdu = buffer.get(..len).unwrap_or_default();
        match channel {
            Channel::Att => self.att_pdu(app, pdu, encrypted, now),
            Channel::SecurityManager => {
                let outcome = self.smp.receive(crypto, pdu, encrypted, now);
                self.outcome(outcome, now);
            },
            Channel::Signalling => match self.signal.receive(pdu) {
                Some(Action::Reply(command)) => {
                    if self.sig_reply.is_none() {
                        self.sig_reply = Some(command);
                    }
                },
                Some(Action::Outcome(outcome)) => {
                    if let Some(link) = self.link.as_mut() {
                        link.asking = None;
                    }
                    if outcome == signal::Outcome::Rejected {
                        info!("the central rejected our connection parameters");
                        #[cfg(feature = "param-requests")]
                        {
                            self.events.flags |= EV_PARAMS_REJECTED;
                            self.events.changed = true;
                        }
                    }
                },
                None => {},
            },
        }
        wipe(&mut buffer);
    }

    /// Takes an event of the link layer at `now`, but for
    /// [`Event::Connected`], which comes with the link's information to
    /// [`Self::connected`].
    #[inline]
    pub fn on_event(&mut self, event: &Event, now: Instant) {
        match *event {
            Event::Disconnected(reason) => {
                if let Some(epoch) = self.epoch() {
                    self.disconnected(epoch, reason);
                }
            },
            Event::Encryption { on, refresh, status: _status } => self.encryption(on, refresh, now),
            Event::LtkRequest { ediv, rand } => self.ltk_request(ediv, rand),
            Event::ParamsUpdated { params, status } => {
                if let Some(link) = self.link.as_mut()
                    && status == 0
                {
                    link.params = params;
                    self.events.params = params;
                    self.events.flags |= EV_PARAMS;
                    self.events.changed = true;
                }
            },
            Event::AdvertisingTimeout
            | Event::Connected(_)
            | Event::DataLength(_)
            | Event::ParamsRequested(_)
            | Event::PayloadTimeout
            | Event::RemoteVersion(_) => {},
            Event::PhyUpdated { rx: _rx, status: _status, tx: _tx } => {},
            Event::RemoteFeatures { features: _features, status: _status } => {},
        }
    }

    /// Takes the time, `now`, once [`Self::next_deadline`] has passed.
    #[inline]
    pub fn on_time(&mut self, now: Instant) {
        let outcome = self.smp.on_time(now);
        self.outcome(outcome, now);
        let Some(link) = self.link.as_mut() else { return };
        if link.security.is_some_and(|deadline| now >= deadline) {
            info!("the link was not encrypted in time");
            link.security = None;
            link.fate.closing = true;
            self.commands.disconnect = Some((link.info.epoch, SECURITY_FAILURE));
        }
        if link.asking.is_some_and(|deadline| now >= deadline) {
            link.asking = None;
            self.signal.cancel();
        }
        let idle = now.checked_duration_since(link.activity).unwrap_or(Duration::MIN);
        if link.encrypted && !link.discovery.ready && idle >= link.ready_idle() {
            link.discovery.ready = true;
            self.events.flags |= EV_READY;
            self.events.changed = true;
            self.commands.hold = Some(false);
        }
        if link.discovery.ready && !link.asked && idle >= PARAMS_IDLE {
            link.asked = true;
            if let Some(range) = self.config.params
                && !fits(range, link.params)
            {
                self.sig_req = self.signal.request_params(range);
            }
        }
    }

    /// Takes what a step of the security manager came to, at `now`.
    fn outcome(&mut self, step: Option<Outcome>, now: Instant) {
        let Some(outcome) = step else { return };
        let Some(link) = self.link.as_mut() else { return };
        match outcome {
            Outcome::Bonded(mut bonded) => {
                // A central without a key of its own that sends its identity
                // address sends an all-zero key, as the Core specification
                // allows: that is no key, so that the bond is stored and
                // directed advertising reaches the central.
                let (peer, irk) = match bonded.identity {
                    Some(identity) => (identity.address, (identity.irk != [0; 16]).then_some(identity.irk)),
                    None => (link.info.identity.unwrap_or(link.info.peer), None),
                };
                let mut bond = Bond::new(peer, irk, bonded.ltk, self.variant, self.db);
                bond.cccd = self.att.subscriptions().bits();
                #[cfg(feature = "passkey")]
                bond.set_authenticated(bonded.authenticated);
                wipe(&mut bonded.ltk);
                if let Some(identity) = bonded.identity.as_mut() {
                    wipe(&mut identity.irk);
                }
                self.bond = Some(bond);
                link.key = Some(Key::Bond);
                link.discovery.restored = true;
                // Reported once the central has our identity: see
                // `take_command`.
                link.discovery.bonding = true;
            },
            Outcome::Failed { by_central, reason } => {
                self.events.flags |= EV_PAIRING_FAILED;
                self.events.reason = reason;
                if by_central {
                    link.ending = Some((SECURITY_FAILURE, now));
                } else {
                    link.fate.failing = true;
                }
            },
            #[cfg(feature = "passkey")]
            Outcome::PasskeyRequested => {
                info!("pairing: the passkey is asked for");
                self.events.flags |= EV_PASSKEY;
            },
            Outcome::Started => info!("pairing"),
            Outcome::TimedOut => {
                info!("pairing timed out");
                link.fate.closing = true;
                self.commands.disconnect = Some((link.info.epoch, REMOTE_USER));
            },
        }
        self.events.changed = true;
    }

    /// The payload of the PDU from `source`, if one waits there.
    fn payload(&mut self, source: Source) -> Option<Payload> {
        let mut payload = Payload { bytes: [0; smp::PDU_MAX], len: 0 };
        let output = match source {
            Source::Att => self.response.map(|slot| (slot.bytes, usize::from(slot.len))),
            Source::Reply | Source::Request => {
                let command = if source == Source::Reply { self.sig_reply } else { self.sig_req }?;
                let mut bytes: [u8; MTU] = [0; MTU];
                let len = command.bytes().len().min(MTU);
                bytes.get_mut(..len)?.copy_from_slice(command.bytes().get(..len)?);
                Some((bytes, len))
            },
            Source::Smp => {
                let pdu = self.smp.next_pdu()?;
                let len = pdu.bytes().len();
                payload.bytes.get_mut(..len)?.copy_from_slice(pdu.bytes());
                payload.len = len;
                return Some(payload);
            },
        };
        let (bytes, len) = output?;
        payload.bytes.get_mut(..len)?.copy_from_slice(bytes.get(..len)?);
        payload.len = len;
        Some(payload)
    }

    /// `level`, raised to authenticated if the key of the link is one of
    /// authenticated pairing.
    #[cfg(feature = "passkey")]
    const fn raised(&self, level: Sec) -> Sec {
        if level == Sec::Encrypted && self.authenticated() { Sec::Authenticated } else { level }
    }

    /// Asks the central of the link `epoch` for the connection parameters
    /// `range` with the L2CAP Connection Parameter Update Request, whatever
    /// the link has now. The engine's own request of [`Config::params`] is
    /// then not made on this link, so the two never race. The outcome comes
    /// as [`ConnEvent::ParamsRejected`], or as [`ConnEvent::ParamsUpdated`]
    /// once the central updated the link.
    ///
    /// # Errors
    ///
    /// [`RequestError::Gone`] without the link, [`RequestError::Invalid`] for
    /// a range out of the specification's, [`RequestError::Busy`] while an
    /// earlier request waits for its response (at most
    /// [`SIGNALLING_TIMEOUT`]).
    #[cfg(feature = "param-requests")]
    #[inline]
    pub fn request_params(&mut self, epoch: Epoch, range: ParamRange) -> Result<(), RequestError> {
        let link = self
            .link
            .as_mut()
            .filter(|link| link.info.epoch == epoch && !link.fate.closing && link.ending.is_none())
            .ok_or(RequestError::Gone)?;
        if !range.is_valid() {
            return Err(RequestError::Invalid);
        }
        let command = self.signal.request_params(range).ok_or(RequestError::Busy)?;
        self.sig_req = Some(command);
        link.asked = true;
        Ok(())
    }

    /// Restores the bond's subscriptions, once the link is encrypted with
    /// the bond's key.
    const fn restore(&mut self) {
        let Some(link) = self.link.as_mut() else { return };
        if link.discovery.restored || link.key != Some(Key::Bond) {
            return;
        }
        link.discovery.restored = true;
        if let Some(bond) = self.bond.as_ref() {
            self.att.restore(bond.subscriptions(self.db));
        }
    }

    /// The security of the link `epoch`: encrypted once it is with a key the
    /// host gave, `None` without the link. With the feature `passkey`,
    /// [`Sec::Authenticated`] when that key is the one of a Passkey Entry
    /// pairing, or of a bond whose `authenticated` is set; a reconnection
    /// with an unauthenticated bond stays encrypted.
    #[inline]
    #[must_use = "the security is only read"]
    pub fn security(&self, epoch: Epoch) -> Option<Sec> {
        let link = self.link.as_ref().filter(|link| link.info.epoch == epoch)?;
        let encryption = if link.encrypted { Sec::Encrypted } else { Sec::Open };
        #[cfg(feature = "passkey")]
        let level = self.raised(encryption);
        #[cfg(not(feature = "passkey"))]
        let level = encryption;
        Some(level)
    }

    /// Notes that no advertising call waits for a link any more: the call
    /// returned, or its future was dropped. A link that arrived for it and
    /// was not returned is kept or ended, as the [`Config`] says.
    #[inline]
    pub fn stop_waiting(&mut self) {
        self.waiting = false;
        if self.config.unclaimed == Unclaimed::Disconnect
            && let Some(link) = self.link.as_mut()
            && !link.fate.claimed
            && !link.fate.closing
        {
            info!("a link nobody waits for ends");
            link.fate.closing = true;
            self.commands.disconnect = Some((link.info.epoch, REMOTE_USER));
        }
    }

    /// The next call of the link layer to make, given the fragments of the
    /// link `in_flight` and the time, `now`. With nothing in flight, what
    /// waited for the central's acknowledgement goes on: the end of
    /// discovery counts from then, and [`ConnEvent::Bonded`] is reported.
    #[inline]
    pub fn take_command(&mut self, in_flight: usize, now: Instant) -> Option<Command> {
        if in_flight == 0
            && let Some(link) = self.link.as_mut()
        {
            if link.inputs == Inputs::Sent {
                link.inputs = Inputs::Acked;
            }
            if link.discovery.bonding {
                link.discovery.bonding = false;
                self.events.flags |= EV_BONDED;
                self.events.changed = true;
            }
        }
        if let Some(hold) = self.commands.hold.take() {
            return Some(Command::HoldLatency(hold));
        }
        if let Some((epoch, key)) = self.commands.ltk.take() {
            return Some(Command::LtkReply { epoch, key });
        }
        if let Some((epoch, reason)) = self.commands.disconnect.take() {
            return Some(Command::Disconnect { epoch, reason });
        }
        let link = self.link.as_mut()?;
        let (reason, deadline) = link.ending?;
        if in_flight != 0 && now < deadline {
            return None;
        }
        link.ending = None;
        link.fate.closing = true;
        Some(Command::Disconnect { epoch: link.info.epoch, reason })
    }

    /// The next event for the link `epoch`, if one waits: see [`ConnEvent`].
    /// Once the link ended, [`ConnEvent::Disconnected`] comes after its other
    /// events, every time; also for a link the engine knows no more.
    #[inline]
    pub fn take_event(&mut self, epoch: Epoch) -> Option<ConnEvent> {
        let ended = self.events.ended.filter(|&(ended, _)| ended == epoch).map(|(_, reason)| reason);
        if self.events.epoch == Some(epoch) {
            let flags = &mut self.events.flags;
            for flag in [
                #[cfg(feature = "passkey")]
                EV_PASSKEY,
                EV_PAIRING_FAILED,
                #[cfg(feature = "key-missing")]
                EV_KEY_MISSING,
                EV_ENCRYPTED,
                EV_BONDED,
                EV_BOND_UPDATED,
                EV_PARAMS,
                #[cfg(feature = "param-requests")]
                EV_PARAMS_REJECTED,
                EV_READY,
            ] {
                if *flags & flag == 0 {
                    continue;
                }
                *flags &= !flag;
                let event = match flag {
                    EV_PAIRING_FAILED => Some(ConnEvent::PairingFailed(self.events.reason)),
                    #[cfg(feature = "key-missing")]
                    EV_KEY_MISSING => Some(ConnEvent::KeyMissing),
                    EV_ENCRYPTED => {
                        let bonded = *flags & EV_WITH_BOND != 0;
                        *flags &= !EV_WITH_BOND;
                        Some(ConnEvent::Encrypted { bonded })
                    },
                    EV_BONDED => self.bond.clone().map(ConnEvent::Bonded),
                    EV_BOND_UPDATED => self.bond.clone().map(ConnEvent::BondUpdated),
                    EV_PARAMS => Some(ConnEvent::ParamsUpdated(self.events.params)),
                    #[cfg(feature = "passkey")]
                    EV_PASSKEY => Some(ConnEvent::PasskeyRequested),
                    #[cfg(feature = "param-requests")]
                    EV_PARAMS_REJECTED => Some(ConnEvent::ParamsRejected),
                    _ => Some(ConnEvent::Ready),
                };
                if event.is_some() {
                    return event;
                }
            }
        } else if self.epoch() != Some(epoch) && ended.is_none() {
            return Some(ConnEvent::Disconnected(0));
        } else {
            // The link's events are gone with a later link.
        }
        ended.map(ConnEvent::Disconnected)
    }

    /// Whether an event arrived since the last call.
    #[inline]
    pub const fn take_events_changed(&mut self) -> bool { mem::replace(&mut self.events.changed, false) }

    /// The next job for the crypto task, if one waits.
    #[inline]
    pub fn take_job(&mut self) -> Option<Job> { self.smp.take_job() }

    /// Hands the passkey of [`Self::enter_passkey`] to the security manager,
    /// with `crypto` for its confirm value, at `now`. A passkey whose
    /// pairing ended meanwhile is dropped.
    #[cfg(feature = "passkey")]
    #[inline]
    pub fn take_passkey<C>(&mut self, crypto: &mut C, now: Instant)
    where
        C: Aes + Random,
    {
        let typed = self.passkey_input;
        if typed == smp::NO_PASSKEY {
            return;
        }
        smp::forget(&mut self.passkey_input, smp::NO_PASSKEY);
        let passkey = (typed != REFUSED).then_some(typed);
        let outcome = self.smp.passkey(crypto, passkey, now).unwrap_or_default();
        self.outcome(outcome, now);
    }

    /// Puts the live subscriptions into the bond, if the link is encrypted
    /// with its key and they changed. A bond not yet reported carries them
    /// in [`ConnEvent::Bonded`].
    const fn update_bond(&mut self) {
        let Some(link) = self.link.as_ref().filter(const |link| link.key == Some(Key::Bond)) else { return };
        let bits = self.att.subscriptions().bits();
        if let Some(bond) = self.bond.as_mut()
            && bond.cccd != bits
        {
            bond.cccd = bits;
            if !link.discovery.bonding {
                self.events.flags |= EV_BOND_UPDATED;
                self.events.changed = true;
            }
        }
    }
}

impl LinkState {
    /// The time ATT is to be idle before discovery counts as over.
    const fn ready_idle(&self) -> Duration {
        match self.inputs {
            Inputs::Acked => INPUTS_IDLE,
            Inputs::Answering | Inputs::Open | Inputs::Sent => READY_IDLE,
        }
    }
}

impl Source {
    /// The channel its PDUs go to.
    const fn channel(self) -> Channel {
        match self {
            Self::Att => Channel::Att,
            Self::Reply | Self::Request => Channel::Signalling,
            Self::Smp => Channel::SecurityManager,
        }
    }
}

/// Whether the connection parameters `params` are those of `range`.
const fn fits(range: ParamRange, params: ConnectionParams) -> bool {
    params.interval >= range.interval_min
        && params.interval <= range.interval_max
        && params.latency == range.latency
        && params.timeout == range.timeout
}

#[cfg(test)] mod tests;
