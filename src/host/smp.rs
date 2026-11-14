//! The security manager: LE Secure Connections pairing as responder, with
//! Just Works and bonding.
//!
//! With the feature `passkey`, also Passkey Entry: see [Passkey
//! Entry](#passkey-entry).
//!
//! [`Responder`] is a state machine without input or output of its own: the
//! engine gives it the PDUs of the security manager channel (CID 6), the
//! link's encryption, the time and the results of the P-256 jobs, and takes
//! from it the PDUs to send, the jobs, the deadline, the long term key for
//! [`crate::link::Link::ltk_reply`] and the outcome of each pairing. The
//! cryptography is that of [`toolbox`] and [`ecc`].
//!
//! # Pairing
//!
//! The sequence is that of a Linux central, the kernel's own (Core
//! specification, volume 3, part H, section 2.3.5.6.2):
//!
//! 1. Pairing Request, answered with the Pairing Response: no input and no
//!    output (0x03), no out of band data, `AuthReq` 0x09 (bonding and Secure
//!    Connections, never protection against a man in the middle, on which
//!    `BlueZ` would fail Just Works), a key size of 16 octets, and of each key
//!    distribution only the identity keys (0x02) the central offered.
//! 2. The central's public key, checked with [`ecc::check_public_key`],
//!    answered with ours and the confirm value Cb = f4(PKbx, PKax, Nb, 0).
//! 3. The central's nonce Na, answered with ours, Nb.
//! 4. The central's `DHKey` check Ea, verified with the `MacKey` and long term
//!    key of f5, answered with ours, Eb. A and B in f5 and f6 are the addresses
//!    on the air with their types, never the identities: A the central's
//!    ([`crate::link::Info::peer`]) and B our own
//!    ([`crate::link::Info::local`]), the resolvable private address with
//!    privacy.
//! 5. The central encrypts the link with the long term key, which
//!    [`Responder::ltk_request`] gives least significant octet first, as
//!    [`crate::link::Link::ltk_reply`] takes it, for EDIV 0 and Rand 0 only.
//! 6. Once the link is encrypted, our identity resolving key and static random
//!    identity address (Identity Information and Identity Address Information),
//!    then the central's, if it offered them, which `BlueZ` sends only after it
//!    received ours.
//! 7. [`Outcome::Bonded`] with the long term key and the central's identity.
//!
//! A request without Secure Connections or without bonding is refused with
//! Authentication Requirements (0x03), a key size under 16 octets with
//! Encryption Key Size (0x06), out of band data from the central with OOB Not
//! Available (0x02), a value out of its range with Invalid Parameters (0x0A),
//! and any request while pairing is not allowed with Pairing Not Supported
//! (0x05). A code the security manager does not know gets Command Not
//! Supported (0x07); a PDU it does not expect now, Unspecified Reason (0x08);
//! a PDU of the wrong length, Invalid Parameters; a public key that is not a
//! point of the curve, or is the debug key or our own reflected, and a `DHKey`
//! check that fails, `DHKey` Check Failed (0x0B). A Pairing Failed from the
//! central ends the pairing and is never answered. A failed pairing reports
//! [`Outcome::Failed`]; the engine disconnects once the Pairing Failed went
//! out.
//!
//! # The timer
//!
//! A pairing has to complete within 30 s of the last PDU the security manager
//! queued, the Pairing Response first ([`TIMEOUT`]). The engine drives the
//! timer: it gives the time to [`Responder::on_time`] once
//! [`Responder::deadline`] has passed, and on [`Outcome::TimedOut`]
//! disconnects. After a timeout the security manager sends nothing more and
//! ignores every PDU until the next link, as the specification requires.
//!
//! # P-256 jobs
//!
//! Each scalar multiplication blocks the thread for about 2.7 s to 3.3 s on
//! the nRF51 (emulated, by build; the readme gives the figures), so
//! the state machine never runs one: it gives a [`Job`], which the firmware
//! runs on a task of its own with [`Job::run`], calling its watchdog hook right
//! before each multiplication and yielding between two jobs, and takes the
//! [`JobResult`] back with [`Responder::job_done`].
//!
//! # The key pair slot
//!
//! A slot holds our key pair: empty, ready and unused, or used by the pairing
//! under way. A key pair job fills it, from fresh random octets:
//!
//! - [`Responder::prepare_key_pair`], before pairable advertising starts, which
//!   waits for it, so no central waits for the multiplication. A reconnection
//!   computes nothing.
//! - A pairing that finds the slot empty at the central's public key.
//! - The refill, in idle time: after a pairing that used the key pair ended
//!   without a bond (failed by either side, timed out or cut by the end of the
//!   link), while Pairing Requests are taken, as soon as no job waits or runs
//!   and no pairing is under way. The engine ends a link whose pairing failed,
//!   and the next attempt follows on a new link, so the refill runs while the
//!   link ends and the next pairable advertising starts at once. After a bond
//!   nothing is computed: the link is in use (the central discovers the table,
//!   the application sends its input), and the next pairing needs pairable
//!   advertising again, which makes the key pair before it advertises.
//!
//! A key pair serves one pairing at most. It becomes the pairing's when its
//! public key is queued for the central; from then on the Diffie-Hellman job
//! takes it, or the end of the pairing drops it, and the next pairing gets a
//! new one. A pairing that ends before its public key went out (the central's
//! key refused, the pairing failed or the link ended earlier) leaves the key
//! pair in the slot, as nothing of it was disclosed. The Core specification
//! (volume 3, part H) does not require a new key pair for each pairing; the
//! security manager makes one anyway, so no two centrals, and no two attempts
//! of one central, ever see the same public key, and a private key never
//! outlives its pairing.
//!
//! The Diffie-Hellman job starts once our public key and confirm value are
//! queued, so the multiplication never holds them back; a `DHKey` check that
//! arrives before the Diffie-Hellman key waits for it. A result that arrives
//! after its pairing ended is dropped.
//!
//! # Secrets
//!
//! The Diffie-Hellman key is overwritten once f5 derived the keys from it, the
//! `MacKey` once both check values are computed, and the long term key once the
//! pairing ends: handed over in [`Bonded`], or failed. The private key is
//! [`ecc::KeyPair`]'s to overwrite, when the Diffie-Hellman job drops it, or
//! the end of its pairing does.
//!
//! # Byte order
//!
//! The PDUs carry every value least significant octet first, and the toolbox
//! takes them most significant octet first: the nonces, confirm and check
//! values and each coordinate of the public keys are reversed on the way in
//! and out. The long term key and the identity resolving keys stay least
//! significant octet first, as the link layer takes them.
//!
//! # Passkey Entry
//!
//! With the feature `passkey` and a `Security` of
//! `IoCapability::KeyboardOnly` (the engine's
//! `crate::host::engine::Config::with_security`), the responder is a
//! keyboard: the Pairing Response carries IO capability 0x02 and `AuthReq`
//! 0x0D (bonding, protection against a man in the middle and Secure
//! Connections), and the method follows the Core specification, volume 3,
//! part H, section 2.3.5.1: a central with a display or a keyboard
//! (DisplayOnly, DisplayYesNo, KeyboardOnly, KeyboardDisplay) pairs with
//! Passkey Entry, the user typing on the device the passkey the central
//! displays (or both typing the same); a central without input or output
//! pairs with Just Works, or, with `Security::require_mitm`, is refused
//! with Authentication Requirements (0x03) at its Pairing Request.
//!
//! Passkey Entry (section 2.3.5.6.3) follows the exchange of the public keys:
//!
//! 1. Our public key goes out alone, and `Outcome::PasskeyRequested` asks the
//!    application for the six digits (`Responder::passkey`). The Diffie-Hellman
//!    job starts at once, so it runs while the user types.
//! 2. Twenty rounds, one for each bit `r_i` of the passkey, least significant
//!    first: the central's confirm value `Cai`, answered with ours, `Cbi =
//!    f4(PKbx, PKax, Nbi, 0x80 | r_i)` with a fresh nonce `Nbi`; then the
//!    central's nonce `Nai`, which has to give `Cai = f4(PKax, PKbx, Nai, 0x80
//!    | r_i)`, or the pairing fails with Confirm Value Failed (0x04) in that
//!    round, answered with `Nbi`. The first `Cai` may arrive before the
//!    passkey: it waits for it.
//! 3. The `DHKey` checks as with Just Works, with the nonces of the last round
//!    and R the passkey as a 128-bit value, in place of zero.
//!
//! The pairing's bond is then authenticated (`Bonded::authenticated`). No
//! passkey (`Responder::passkey` with `None`) fails it with Passkey Entry
//! Failed (0x01). The timer pauses while the device waits for the user
//! before the central's first confirm value: the central may wait for its own
//! user too. It runs again from that confirm value and from the passkey, so
//! the user has [`TIMEOUT`] from the central's first confirm value; the
//! advertising schedule's security deadline still bounds the whole pairing.
//! Keypress Notifications are never asked for; one the central sends during
//! Passkey Entry is ignored.
//!
//! Not supported: legacy pairing, numeric comparison, out of band data, the
//! Security Request, sending Keypress Notifications and signing keys; without
//! the feature `passkey`, Passkey Entry.

/// P-256: the key pair, the check of the central's public key and the
/// Diffie-Hellman key.
pub mod ecc;
/// The cryptographic functions of pairing: f4, f5, f6, g2 and ah.
pub mod toolbox;

#[cfg(feature = "passkey")]
use crate::{bytes::be32_bytes, host::PasskeyError};
use crate::{crypto::wipe, host::Aes, link::Info, pdu::Peer};
use core::{array::TryFromSliceError, fmt, iter, mem};
#[cfg(feature = "passkey")]
use core::{
    hint::black_box,
    sync::atomic::{Ordering, compiler_fence},
};
use ecc::{KEY_LEN, KeyError, KeyPair, PUBLIC_KEY_LEN, check_public_key};
use embassy_time::{Duration, Instant};
use toolbox::{address, f4, f5, f6};

/// Code of a Pairing Request.
pub const PAIRING_REQUEST: u8 = 0x01;
/// Code of a Pairing Response.
pub const PAIRING_RESPONSE: u8 = 0x02;
/// Code of a Pairing Confirm.
pub const PAIRING_CONFIRM: u8 = 0x03;
/// Code of a Pairing Random.
pub const PAIRING_RANDOM: u8 = 0x04;
/// Code of a Pairing Failed.
pub const PAIRING_FAILED: u8 = 0x05;
/// Code of an Encryption Information, of legacy pairing.
pub const ENCRYPTION_INFORMATION: u8 = 0x06;
/// Code of a Central Identification, of legacy pairing.
pub const CENTRAL_IDENTIFICATION: u8 = 0x07;
/// Code of an Identity Information.
pub const IDENTITY_INFORMATION: u8 = 0x08;
/// Code of an Identity Address Information.
pub const IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
/// Code of a Signing Information.
pub const SIGNING_INFORMATION: u8 = 0x0A;
/// Code of a Security Request.
pub const SECURITY_REQUEST: u8 = 0x0B;
/// Code of a Pairing Public Key.
pub const PAIRING_PUBLIC_KEY: u8 = 0x0C;
/// Code of a Pairing `DHKey` Check.
pub const PAIRING_DHKEY_CHECK: u8 = 0x0D;
/// Code of a Keypress Notification.
pub const KEYPRESS_NOTIFICATION: u8 = 0x0E;
/// Longest PDU the security manager sends or takes: a Pairing Public Key.
pub const PDU_MAX: usize = 1 + PUBLIC_KEY_LEN;
/// The time a pairing has from the last PDU the security manager queued.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// IO capability: no input and no output, which makes pairing Just Works.
pub const NO_INPUT_NO_OUTPUT: u8 = 0x03;
/// IO capability: a keyboard without a display.
pub const KEYBOARD_ONLY: u8 = 0x02;
/// The largest passkey: six decimal digits.
#[cfg(feature = "passkey")]
pub const PASSKEY_MAX: u32 = 999_999;
/// The rounds of Passkey Entry: one for each of the passkey's 20 bits.
#[cfg(feature = "passkey")]
const PASSKEY_ROUNDS: u8 = 20;
/// No passkey: above [`PASSKEY_MAX`], so never one the user gave.
#[cfg(feature = "passkey")]
pub(crate) const NO_PASSKEY: u32 = u32::MAX;
/// `AuthReq` bit: bonding.
pub const AUTH_BONDING: u8 = 0x01;
/// `AuthReq` bit: protection against a man in the middle.
pub const AUTH_MITM: u8 = 0x04;
/// `AuthReq` bit: LE Secure Connections.
pub const AUTH_SECURE_CONNECTIONS: u8 = 0x08;
/// Key distribution bit: the identity resolving key and identity address.
pub const KEY_DIST_ID: u8 = 0x02;
/// The only key size the security manager takes, in octets.
pub const KEY_SIZE: u8 = 16;
/// Our `AuthReq`: bonding and Secure Connections, without MITM.
const AUTH_REQ: u8 = AUTH_BONDING | AUTH_SECURE_CONNECTIONS;
/// Our `IOcap` for f6: `AuthReq`, OOB data flag, IO capability.
#[cfg(not(feature = "passkey"))]
const IO_CAP_B: [u8; 3] = [AUTH_REQ, 0, NO_INPUT_NO_OUTPUT];
/// The largest IO capability: keyboard and display.
const IO_CAPABILITY_MAX: u8 = 0x04;
/// The smallest key size a request may give.
const KEY_SIZE_MIN: u8 = 7;
/// R of f6, zero for Just Works.
const R_ZERO: [u8; 16] = [0; 16];
/// Output: the Pairing Response.
const OUT_RESPONSE: u8 = 0x01;
/// Output: our Pairing Public Key.
const OUT_PUBLIC_KEY: u8 = 0x02;
/// Output: our Pairing Confirm, Cb.
const OUT_CONFIRM: u8 = 0x04;
/// Output: our Pairing Random, Nb.
const OUT_RANDOM: u8 = 0x08;
/// Output: our Pairing `DHKey` Check, Eb.
const OUT_CHECK: u8 = 0x10;
/// Output, and in [`Responder::received`] input: an Identity Information.
const ID_INFO: u8 = 0x20;
/// Output, and in [`Responder::received`] input: an Identity Address
/// Information.
const ID_ADDRESS: u8 = 0x40;
/// Output: a Pairing Failed.
const OUT_FAILED: u8 = 0x80;

/// The bond a pairing made.
///
/// Its [`core::fmt::Debug`] leaves the keys out.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct Bonded {
    /// Whether the pairing protected against a man in the middle: Passkey
    /// Entry.
    #[cfg(feature = "passkey")]
    pub authenticated: bool,
    /// The central's identity, if it distributed one that is public or
    /// static random. Without it the central is known by its address on
    /// the air.
    pub identity:      Option<Identity>,
    /// The long term key, least significant octet first, as
    /// [`crate::link::Link::ltk_reply`] takes it.
    pub ltk:           [u8; 16],
}

/// Whether the Diffie-Hellman key of the pairing was asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dh {
    /// The job is queued or running.
    Asked,
    /// The key is in [`Responder::dh_key`].
    Ready,
    /// Not yet.
    Unasked,
}

/// The central's identity: its identity address and identity resolving key.
///
/// Its [`core::fmt::Debug`] leaves the key out.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct Identity {
    /// The identity address: public, or static random.
    pub address: Peer,
    /// The identity resolving key, least significant octet first, as
    /// [`crate::link::Link::add_peer`] takes it.
    pub irk:     [u8; 16],
}

/// Our IO capability, as the Pairing Response gives it.
#[cfg(feature = "passkey")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IoCapability {
    /// A keyboard without a display (0x02): Passkey Entry with any central
    /// that has a display or a keyboard.
    KeyboardOnly,
    /// No input and no output (0x03): Just Works only.
    NoInputNoOutput,
}

/// A P-256 job for the firmware's crypto task: run it with [`Self::run`]
/// and give the result to [`Responder::job_done`].
#[non_exhaustive]
pub struct Job {
    /// What to compute.
    kind: JobKind,
}

/// What a job computes.
enum JobKind {
    /// The Diffie-Hellman key of the key pair and the central's public key.
    DhKey {
        /// The key pair, which the job drops once it is used.
        pair:   KeyPair,
        /// The central's public key, X then Y.
        peer:   [u8; PUBLIC_KEY_LEN],
        /// The number of the job.
        serial: u8,
    },
    /// A new key pair.
    KeyPair,
}

/// The result of a [`Job`].
#[non_exhaustive]
pub struct JobResult {
    /// The result.
    kind: JobOutput,
}

/// The result of a job.
enum JobOutput {
    /// The Diffie-Hellman key, or why the central's key was refused.
    DhKey {
        /// The key, most significant octet first.
        key:    Result<[u8; KEY_LEN], KeyError>,
        /// The number of the job.
        serial: u8,
    },
    /// A new key pair.
    KeyPair(KeyPair),
}

/// What a pairing came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Outcome {
    /// Pairing completed and made a bond, which the firmware stores.
    Bonded(Bonded),
    /// Pairing failed, or a Pairing Request was refused. Unless the central
    /// sent the Pairing Failed, ours waits in [`Responder::next_pdu`].
    Failed {
        /// Whether the central sent the Pairing Failed.
        by_central: bool,
        /// The reason.
        reason:     Reason,
    },
    /// Passkey Entry needs the passkey the user types: give it with
    /// [`Responder::passkey`].
    #[cfg(feature = "passkey")]
    PasskeyRequested,
    /// A Pairing Request was taken: pairing has started.
    Started,
    /// The 30 s timer expired: the security manager sends nothing more on
    /// this link, which the engine is to end.
    TimedOut,
}

/// One PDU to send on the security manager channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Output {
    /// The PDU, of which the first `len` octets count.
    data: [u8; PDU_MAX],
    /// Its length.
    len:  u8,
}

/// A reason of a Pairing Failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Reason(u8);

/// The security manager of the peripheral: LE Secure Connections pairing
/// as responder, one link at a time, and the key pair between pairings.
pub struct Responder {
    /// Our own static random identity address, least significant octet
    /// first.
    address:        [u8; 6] = [0; 6],
    /// Whether the pairing under way is Passkey Entry.
    #[cfg(feature = "passkey")]
    authenticating: bool = false,
    /// The central's address on the air: A of f5 and f6.
    central:        Peer = Peer::new([0; 6], false),
    /// The central's `DHKey` check Ea, most significant octet first, until
    /// it is verified; then ours, Eb.
    check:          [u8; 16] = [0; 16],
    /// Our confirm value Cb, most significant octet first.
    confirm:        [u8; 16] = [0; 16],
    /// When the pairing times out.
    deadline:       Option<Instant> = None,
    /// Whether the Diffie-Hellman key was asked for.
    dh:             Dh = Dh::Unasked,
    /// The Diffie-Hellman key, most significant octet first, once
    /// [`Self::dh`] is ready, until f5 used it.
    dh_key:         [u8; KEY_LEN] = [0; KEY_LEN],
    /// The central's identity keys the pairing distributes: 0 or
    /// [`KEY_DIST_ID`].
    init_dist:      u8 = 0,
    /// The central's `IOcap` for f6: `AuthReq`, OOB data flag, IO
    /// capability.
    io_cap:         [u8; 3] = [0; 3],
    /// Our own identity resolving key, least significant octet first.
    irk:            [u8; 16] = [0; 16],
    /// The job waiting to be taken.
    job:            Option<Task> = None,
    /// The output whose PDU is being sent, 0 or one bit: it stays the next
    /// PDU until [`Self::pdu_sent`], so its fragments never change.
    latched:        u8 = 0,
    /// Our own address on the air: B of f5 and f6.
    local:          Peer = Peer::new([0; 6], false),
    /// The long term key, least significant octet first, from the `DHKey`
    /// check until the pairing ends.
    ltk:            [u8; 16] = [0; 16],
    /// The central's nonce Na, most significant octet first.
    na:             [u8; 16] = [0; 16],
    /// Our nonce Nb, most significant octet first.
    nb:             [u8; 16] = [0; 16],
    /// Our public key in the pairing under way, X then Y, most significant
    /// octet first, from the moment it is queued: the Pairing Public Key PDU
    /// is rendered from it and the confirm values take its X, so neither
    /// depends on the key pair slot. Public, so never overwritten.
    own_key:        [u8; PUBLIC_KEY_LEN] = [0; PUBLIC_KEY_LEN],
    /// Whether a Pairing Request is taken.
    pairable:       bool = false,
    /// The passkey of Passkey Entry, once the user gave it; otherwise
    /// [`NO_PASSKEY`], which overwrites all of its digits.
    #[cfg(feature = "passkey")]
    passkey:        u32 = NO_PASSKEY,
    /// The central's confirm value of the round of Passkey Entry, most
    /// significant octet first.
    #[cfg(feature = "passkey")]
    peer_confirm:   [u8; 16] = [0; 16],
    /// The central's identity address, once it arrived.
    peer_identity:  Option<Peer> = None,
    /// The central's identity resolving key, least significant octet
    /// first, once it arrived.
    peer_irk:       [u8; 16] = [0; 16],
    /// The central's public key, X then Y, most significant octet first.
    peer_key:       [u8; PUBLIC_KEY_LEN] = [0; PUBLIC_KEY_LEN],
    /// The PDUs to send, one bit each, sent from the lowest bit up.
    pending:        u8 = 0,
    /// The reason of our Pairing Failed.
    reason:         Reason = Reason::UNSPECIFIED,
    /// The central's identity keys received: [`ID_INFO`] and
    /// [`ID_ADDRESS`].
    received:       u8 = 0,
    /// Whether the slot is refilled in idle time ([`Self::refill_due`]): set
    /// when a pairing takes the key pair, cleared when it bonds or the slot
    /// is filled. So only a pairing that used its key pair and ended without
    /// a bond leads to a refill.
    refill:         bool = false,
    /// Our identity keys the pairing distributes: 0 or [`KEY_DIST_ID`].
    resp_dist:      u8 = 0,
    /// The job being run, with its number.
    running:        Option<(Task, u8)> = None,
    /// What our side of pairing protects against.
    #[cfg(feature = "passkey")]
    security:       Security = Security::JUST_WORKS,
    /// The number of the last Diffie-Hellman job.
    serial:         u8 = 0,
    /// The key pair slot: at most one key pair.
    slot:           Slot = Slot::Empty,
    /// Where the pairing stands.
    state:          State = State::Idle,
}

/// What our side of pairing can protect against, and what it requires.
#[cfg(feature = "passkey")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Security {
    /// Our IO capability.
    pub io_capability: IoCapability,
    /// Whether a pairing without protection against a man in the middle is
    /// refused: a central without input or output then gets Authentication
    /// Requirements (0x03) at its Pairing Request.
    pub require_mitm:  bool,
}

/// The key pair slot: our key pair, from its job to the Diffie-Hellman job.
enum Slot {
    /// No key pair: the crypto task refills the slot in idle time
    /// ([`Responder::refill_due`]).
    Empty,
    /// A key pair, ready and unused, for the next pairing.
    Ready(KeyPair),
    /// The key pair of the pairing under way, whose public key was queued
    /// for the central, until the Diffie-Hellman job takes it. It never
    /// serves another pairing: the end of the pairing drops it, which
    /// overwrites its private key.
    Used(KeyPair),
}

/// Where a pairing stands.
#[derive(Clone, Copy, Debug, Eq)]
#[derive_const(PartialEq)]
enum State {
    /// Nb is queued: waiting for the central's `DHKey` check and the
    /// Diffie-Hellman key, whichever is still missing; with whether the
    /// check arrived.
    Check(bool),
    /// Passkey Entry, round 0 to 19: waiting for the central's confirm value
    /// of the round, and in round 0 for the passkey too, if it is missing.
    #[cfg(feature = "passkey")]
    Confirm(u8),
    /// Eb is queued: waiting for the central to encrypt the link with the
    /// long term key.
    Encryption,
    /// No pairing on the link.
    Idle,
    /// Passkey Entry: the central's first confirm value arrived before the
    /// passkey, which the pairing waits for.
    #[cfg(feature = "passkey")]
    Input,
    /// The central's public key arrived before our key pair.
    KeyPair,
    /// The link is encrypted with the new key: the identity keys go both
    /// ways.
    Keys,
    /// Passkey Entry: our confirm value of the round is queued; waiting for
    /// the central's nonce.
    #[cfg(feature = "passkey")]
    Nonce(u8),
    /// The Pairing Response is queued: waiting for the central's public
    /// key.
    PublicKey,
    /// Our public key and Cb are queued: waiting for the central's nonce.
    Random,
    /// The timer expired: nothing more until the next link.
    TimedOut,
}

/// A job, as the state machine keeps track of it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Task {
    /// The Diffie-Hellman key.
    DhKey,
    /// A key pair.
    KeyPair,
}

/// Random numbers for pairing: our nonce and the private keys.
pub trait Random {
    /// Fills `out` with octets of a cryptographically secure random number
    /// generator.
    fn fill(&mut self, out: &mut [u8]);
}

impl fmt::Debug for Bonded {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bonded").field("identity", &self.identity).finish_non_exhaustive()
    }
}

impl fmt::Debug for Identity {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("address", &self.address.address)
            .field("random", &self.address.random)
            .finish_non_exhaustive()
    }
}

impl Job {
    /// Whether the job makes a key pair, rather than the Diffie-Hellman key.
    #[inline]
    #[must_use = "the kind is only read"]
    pub const fn is_key_pair(&self) -> bool { matches!(self.kind, JobKind::KeyPair) }

    /// Runs the job: one scalar multiplication, which blocks the thread for
    /// about 2.7 s to 3.3 s on the nRF51, with `before_multiplication` called
    /// right before it, for the watchdog. A key pair takes its private key from
    /// `random`, and draws again in the rare case it is refused.
    #[inline]
    #[must_use = "the result goes to the security manager"]
    pub fn run<R, F>(self, random: &mut R, mut before_multiplication: F) -> JobResult
    where
        R: Random,
        F: FnMut(),
    {
        let kind = match self.kind {
            JobKind::DhKey { pair, peer, serial } => {
                // The key pair is dropped, which overwrites its private key.
                JobOutput::DhKey { key: pair.dh_key(&peer, before_multiplication), serial }
            },
            JobKind::KeyPair => loop {
                let mut secret = [0; KEY_LEN];
                random.fill(&mut secret);
                if let Some(pair) = KeyPair::generate(&mut secret, &mut before_multiplication) {
                    break JobOutput::KeyPair(pair);
                }
            },
        };
        JobResult { kind }
    }
}

impl Output {
    /// The PDU for the security manager channel.
    #[inline]
    #[must_use = "the PDU is only read"]
    pub const fn bytes(&self) -> &[u8] { self.data.get(..usize::from(self.len)).unwrap_or_default() }

    /// A PDU with `code` and the parameters `parts` in order.
    fn new(code: u8, parts: &[&[u8]]) -> Self {
        let mut data: [u8; PDU_MAX] = [0; PDU_MAX];
        let mut len: usize = 0;
        for &byte in iter::once(&code).chain(parts.iter().flat_map(|part| part.iter())) {
            if let Some(slot) = data.get_mut(len) {
                *slot = byte;
                len = len.saturating_add(1);
            }
        }
        Self { data, len: u8::try_from(len).unwrap_or_default() }
    }
}

impl Reason {
    /// The central's request lacks Secure Connections or bonding.
    pub const AUTHENTICATION_REQUIREMENTS: Self = Self(0x03);
    /// A code the security manager does not know.
    pub const COMMAND_NOT_SUPPORTED: Self = Self(0x07);
    /// The confirm value does not match.
    pub const CONFIRM_VALUE_FAILED: Self = Self(0x04);
    /// The `DHKey` check failed, or the public key is refused.
    pub const DHKEY_CHECK_FAILED: Self = Self(0x0B);
    /// The key size is below 16 octets.
    pub const ENCRYPTION_KEY_SIZE: Self = Self(0x06);
    /// A value is out of its range, or a PDU has the wrong length.
    pub const INVALID_PARAMETERS: Self = Self(0x0A);
    /// The central has out of band data, which we lack.
    pub const OOB_NOT_AVAILABLE: Self = Self(0x02);
    /// Pairing is not allowed now.
    pub const PAIRING_NOT_SUPPORTED: Self = Self(0x05);
    /// The user gave no passkey.
    pub const PASSKEY_ENTRY_FAILED: Self = Self(0x01);
    /// Too many pairing attempts in too short a time.
    pub const REPEATED_ATTEMPTS: Self = Self(0x09);
    /// A PDU the security manager does not expect now.
    pub const UNSPECIFIED: Self = Self(0x08);

    /// The code a Pairing Failed carries.
    #[inline]
    #[must_use = "the code is only read"]
    pub const fn code(self) -> u8 { self.0 }

    /// The reason with the code `code`, as a central's Pairing Failed
    /// carries it.
    #[inline]
    #[must_use = "the reason is only built"]
    pub const fn from_code(code: u8) -> Self { Self(code) }
}

impl Responder {
    /// Answers the central's public key with ours and Cb, once both the
    /// central's key and our key pair are there.
    fn answer_public_key<C>(&mut self, crypto: &mut C) -> Result<Option<Outcome>, Reason>
    where
        C: Aes + Random,
    {
        let pair = match mem::replace(&mut self.slot, Slot::Empty) {
            Slot::Ready(pair) => pair,
            other @ (Slot::Empty | Slot::Used(_)) => {
                self.slot = other;
                return Err(Reason::UNSPECIFIED);
            },
        };
        if check_public_key(&self.peer_key, pair.public_key()).is_err() {
            // Nothing of it was shown: it stays for the next pairing.
            self.slot = Slot::Ready(pair);
            return Err(Reason::DHKEY_CHECK_FAILED);
        }
        // From here on the key pair is this pairing's: its public key goes to
        // the central, and it serves no other pairing.
        self.own_key = *pair.public_key();
        self.slot = Slot::Used(pair);
        // Should it end without a bond, the slot is refilled.
        self.refill = true;
        #[cfg(feature = "passkey")]
        if self.authenticating {
            // Passkey Entry: our public key alone; the confirm values follow
            // in the rounds.
            self.pending |= OUT_PUBLIC_KEY;
            self.state = State::Confirm(0);
            return Ok(Some(Outcome::PasskeyRequested));
        }
        let own_x = self.own_key.first_chunk::<KEY_LEN>().ok_or(Reason::UNSPECIFIED)?;
        let peer_x = self.peer_key.first_chunk::<KEY_LEN>().ok_or(Reason::UNSPECIFIED)?;
        crypto.fill(&mut self.nb);
        self.confirm = f4(&*crypto, own_x, peer_x, &self.nb, 0);
        self.pending |= OUT_PUBLIC_KEY | OUT_CONFIRM;
        self.state = State::Random;
        Ok(None)
    }

    /// Whether the pairing waits for the user's passkey:
    /// [`Outcome::PasskeyRequested`] came, and [`Self::passkey`] did not yet.
    #[cfg(feature = "passkey")]
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn awaits_passkey(&self) -> bool {
        self.authenticating && self.passkey == NO_PASSKEY && matches!(self.state, State::Confirm(0) | State::Input)
    }

    /// Starts on a new link, with the addresses on the air of
    /// [`crate::link::Link::info`]; forgets the previous link as
    /// [`Self::disconnected`] does.
    #[inline]
    pub fn connected(&mut self, info: &Info) {
        self.disconnected();
        self.central = info.peer;
        self.local = info.local;
    }

    /// The deadline of the pairing's timer, if one runs: give the time to
    /// [`Self::on_time`] once it passed.
    #[inline]
    #[must_use = "the deadline is only read"]
    pub const fn deadline(&self) -> Option<Instant> { self.deadline }

    /// Takes the central's `DHKey` check.
    fn dhkey_check<A>(&mut self, aes: &A, params: &[u8]) -> Result<Option<Outcome>, Reason>
    where
        A: Aes,
    {
        if self.state != (State::Check(false)) || self.queued(OUT_RANDOM) {
            return Err(Reason::UNSPECIFIED);
        }
        self.check = reversed(params.try_into().map_err(|_error: TryFromSliceError| Reason::INVALID_PARAMETERS)?);
        self.state = State::Check(true);
        if self.dh == Dh::Ready { self.verify(aes) } else { Ok(None) }
    }

    /// Forgets the link: its pairing and its secrets. A key pair whose public
    /// key went to the central is dropped, a ready one stays, and so do the
    /// jobs being run; a result for this link is dropped.
    #[inline]
    pub fn disconnected(&mut self) {
        self.end();
        self.state = State::Idle;
        self.pending = 0;
        self.latched = 0;
    }

    /// Takes the encryption of the link, after the long term key went to
    /// the link layer: `on` once it is encrypted, not `on` if encryption
    /// failed, which fails the pairing.
    #[inline]
    pub fn encryption_changed(&mut self, on: bool) -> Option<Outcome> {
        if self.state != State::Encryption {
            return None;
        }
        if !on {
            return self.fail(Reason::UNSPECIFIED, true);
        }
        self.state = State::Keys;
        if self.resp_dist != 0 {
            self.pending |= ID_INFO | ID_ADDRESS;
        }
        self.finish()
    }

    /// Ends the pairing, with its secrets and its timer.
    fn end(&mut self) {
        wipe(&mut self.dh_key);
        wipe(&mut self.ltk);
        wipe(&mut self.peer_irk);
        self.peer_identity = None;
        self.received = 0;
        self.dh = Dh::Unasked;
        if matches!(self.slot, Slot::Used(_)) {
            // Its public key went to the central: it serves no other pairing.
            // Dropping it overwrites its private key.
            self.slot = Slot::Empty;
        }
        if self.job == Some(Task::DhKey) {
            // Its key pair is gone with the pairing.
            self.job = None;
        }
        if self.running.is_some_and(|(task, _)| task == Task::DhKey) {
            // Its result is dropped when it arrives.
            self.running = None;
        }
        self.deadline = None;
        self.state = State::Idle;
        #[cfg(feature = "passkey")]
        {
            self.authenticating = false;
            forget(&mut self.passkey, NO_PASSKEY);
            wipe(&mut self.peer_confirm);
        }
    }

    /// Fails the pairing for `reason`: our Pairing Failed follows the PDU
    /// being sent, and replaces the others. `report` it as the outcome if a
    /// pairing ends, or a request is refused.
    fn fail(&mut self, reason: Reason, report: bool) -> Option<Outcome> {
        self.end();
        self.pending = (self.pending & self.latched) | OUT_FAILED;
        self.reason = reason;
        report.then_some(Outcome::Failed { by_central: false, reason })
    }

    /// Bonds once the link is encrypted, our identity keys are queued and
    /// the central's arrived.
    fn finish(&mut self) -> Option<Outcome> {
        if self.state != State::Keys
            || self.queued(ID_INFO | ID_ADDRESS)
            || (self.init_dist != 0 && self.received & ID_ADDRESS == 0)
        {
            return None;
        }
        let identity = self.peer_identity.map(|address| Identity { address, irk: self.peer_irk });
        let bonded = Bonded {
            identity,
            ltk: self.ltk,
            #[cfg(feature = "passkey")]
            authenticated: self.authenticating,
        };
        // No refill after a bond: the link is in use, and the next pairing
        // needs pairable advertising again, which makes its key pair first.
        self.refill = false;
        self.end();
        Some(Outcome::Bonded(bonded))
    }

    /// Whether a job waits to be taken with [`Self::take_job`]: one a pairing
    /// or [`Self::prepare_key_pair`] asked for, or the refill of the key pair
    /// slot after a pairing that used its key pair ended unbonded (see [the key
    /// pair slot](self#the-key-pair-slot)).
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn has_job(&self) -> bool { self.job.is_some() || self.refill_due() }

    /// Whether a key pair is ready and unused, so the next pairing needs
    /// only the Diffie-Hellman job.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn has_key_pair(&self) -> bool { matches!(self.slot, Slot::Ready(_)) }

    /// Whether a PDU waits to be sent with [`Self::next_pdu`].
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn has_output(&self) -> bool { self.pending != 0 }

    /// Takes the central's identity address, after its identity resolving
    /// key.
    fn identity_address(&mut self, params: &[u8], encrypted: bool) -> Result<Option<Outcome>, Reason> {
        if !self.takes_keys(encrypted) || self.received != ID_INFO {
            return Err(Reason::UNSPECIFIED);
        }
        let &[kind, a0, a1, a2, a3, a4, a5] = params else { return Err(Reason::INVALID_PARAMETERS) };
        let address = [a0, a1, a2, a3, a4, a5];
        let random = match kind {
            0 => false,
            1 => true,
            _ => return Err(Reason::INVALID_PARAMETERS),
        };
        self.received |= ID_ADDRESS;
        // An identity address is public or static random, with the two most
        // significant bits set. Linux drops any other, with its key, and so
        // does the bond: the central is then known by its address on the
        // air.
        if !random || a5 & 0xC0 == 0xC0 {
            self.peer_identity = Some(Peer::new(address, random));
        } else {
            wipe(&mut self.peer_irk);
        }
        Ok(self.finish())
    }

    /// Takes the central's identity resolving key.
    const fn identity_information(&mut self, params: &[u8], encrypted: bool) -> Result<Option<Outcome>, Reason> {
        if !self.takes_keys(encrypted) || self.received != 0 {
            return Err(Reason::UNSPECIFIED);
        }
        self.peer_irk = params.try_into().map_err(const |_error: TryFromSliceError| Reason::INVALID_PARAMETERS)?;
        self.received = ID_INFO;
        Ok(None)
    }

    /// Whether the pairing under way is Passkey Entry, which protects
    /// against a man in the middle; false once it ended.
    #[cfg(feature = "passkey")]
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn is_authenticating(&self) -> bool { self.authenticating }

    /// Whether a Pairing Request is taken.
    #[cfg(feature = "key-missing")]
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn is_pairable(&self) -> bool { self.pairable }

    /// Whether a pairing is under way: from the Pairing Request until it
    /// bonds, fails or times out.
    #[inline]
    #[must_use = "the state is only read"]
    pub const fn is_pairing(&self) -> bool { !matches!(self.state, State::Idle | State::TimedOut) }

    /// Takes the result of a job from [`Job::run`]. A result whose pairing
    /// ended is dropped; a key pair goes into the empty slot, for the next
    /// pairing (or the one under way, if it waits for it).
    #[inline]
    pub fn job_done<C>(&mut self, crypto: &mut C, result: JobResult) -> Option<Outcome>
    where
        C: Aes + Random,
    {
        let answer = match result.kind {
            JobOutput::KeyPair(pair) => {
                if self.running.is_some_and(|(task, _)| task == Task::KeyPair) {
                    self.running = None;
                }
                if matches!(self.slot, Slot::Empty) {
                    self.slot = Slot::Ready(pair);
                    self.refill = false;
                }
                if self.state == State::KeyPair { self.answer_public_key(crypto) } else { Ok(None) }
            },
            JobOutput::DhKey { mut key, serial } => {
                let current = self.running == Some((Task::DhKey, serial));
                if current {
                    self.running = None;
                }
                let waiting = current && self.dh == Dh::Asked && self.keys_exchanged();
                let answer = match key.as_ref() {
                    Ok(dh_key) if waiting => {
                        self.dh_key = *dh_key;
                        self.dh = Dh::Ready;
                        if self.state == (State::Check(true)) { self.verify(&*crypto) } else { Ok(None) }
                    },
                    Err(_) if waiting => Err(Reason::DHKEY_CHECK_FAILED),
                    Ok(_) | Err(_) => Ok(None),
                };
                if let Ok(dh_key) = key.as_mut() {
                    wipe(dh_key);
                }
                answer
            },
        };
        self.settle(answer)
    }

    /// Whether both public keys are known, so the Diffie-Hellman key may be
    /// computed and its result is awaited.
    #[cfg(not(feature = "passkey"))]
    const fn keys_exchanged(&self) -> bool { matches!(self.state, State::Random | State::Check(_)) }

    /// Whether both public keys are known, so the Diffie-Hellman key may be
    /// computed and its result is awaited.
    #[cfg(feature = "passkey")]
    const fn keys_exchanged(&self) -> bool {
        matches!(self.state, State::Random | State::Check(_) | State::Confirm(_) | State::Input | State::Nonce(_))
    }

    /// The long term key for the link layer's request with `ediv` and
    /// `rand`, least significant octet first: the key of the pairing under
    /// way, for EDIV 0 and Rand 0 only, from our `DHKey` check on. Otherwise
    /// `None`, and the bond's key is the engine's to give.
    #[inline]
    #[must_use = "the key is only read"]
    pub const fn ltk_request(&self, ediv: u16, rand: [u8; 8]) -> Option<[u8; 16]> {
        (ediv == 0 && rand == [0; 8] && matches!(self.state, State::Encryption | State::Keys)).then_some(self.ltk)
    }

    /// A security manager without a key pair, pairing or identity: give it
    /// one with [`Self::set_identity`] before pairing is allowed.
    #[inline]
    #[must_use = "the security manager is only built"]
    pub const fn new() -> Self { Self { .. } }

    /// The next PDU to send: the same one, rendered again, until
    /// [`Self::pdu_sent`] says it was queued, so the fragments of a public
    /// key all come from one PDU.
    #[inline]
    pub fn next_pdu(&mut self) -> Option<Output> {
        if self.latched == 0 {
            self.latched = self.pending & self.pending.wrapping_neg();
        }
        match self.latched {
            OUT_RESPONSE => Some(Output::new(PAIRING_RESPONSE, &[&[
                #[cfg(not(feature = "passkey"))]
                NO_INPUT_NO_OUTPUT,
                #[cfg(feature = "passkey")]
                self.security.io_capability.code(),
                0,
                #[cfg(not(feature = "passkey"))]
                AUTH_REQ,
                #[cfg(feature = "passkey")]
                self.security.auth_req(),
                KEY_SIZE,
                self.init_dist,
                self.resp_dist,
            ]])),
            OUT_PUBLIC_KEY => Some(Output::new(PAIRING_PUBLIC_KEY, &[&flip_coordinates(&self.own_key)])),
            OUT_CONFIRM => Some(Output::new(PAIRING_CONFIRM, &[&reversed(&self.confirm)])),
            OUT_RANDOM => Some(Output::new(PAIRING_RANDOM, &[&reversed(&self.nb)])),
            OUT_CHECK => Some(Output::new(PAIRING_DHKEY_CHECK, &[&reversed(&self.check)])),
            ID_INFO => Some(Output::new(IDENTITY_INFORMATION, &[&self.irk])),
            ID_ADDRESS => Some(Output::new(IDENTITY_ADDRESS_INFORMATION, &[&[1], &self.address])),
            OUT_FAILED => Some(Output::new(PAIRING_FAILED, &[&[self.reason.code()]])),
            _ => None,
        }
    }

    /// Takes the time, `now`: past the deadline the pairing times out.
    #[inline]
    pub fn on_time(&mut self, now: Instant) -> Option<Outcome> {
        if self.deadline.is_none_or(|deadline| now < deadline) {
            return None;
        }
        self.end();
        self.state = State::TimedOut;
        self.pending &= self.latched;
        Some(Outcome::TimedOut)
    }

    /// Takes the central's confirm value of a round of Passkey Entry, at
    /// `now`, and answers it with ours once the passkey is there.
    #[cfg(feature = "passkey")]
    fn pairing_confirm<C>(&mut self, crypto: &mut C, params: &[u8], now: Instant) -> Result<Option<Outcome>, Reason>
    where
        C: Aes + Random,
    {
        // Each confirm value follows our nonce of the round before, and the
        // first our public key.
        let State::Confirm(round) = self.state else { return Err(Reason::UNSPECIFIED) };
        if self.queued(OUT_PUBLIC_KEY | OUT_RANDOM) {
            return Err(Reason::UNSPECIFIED);
        }
        self.peer_confirm =
            reversed(params.try_into().map_err(|_error: TryFromSliceError| Reason::INVALID_PARAMETERS)?);
        if self.passkey == NO_PASSKEY {
            // The user has the time of the timer from now.
            self.state = State::Input;
            self.deadline = Some(now.checked_add(TIMEOUT).unwrap_or(Instant::MAX));
        } else {
            self.send_confirm(crypto, round);
        }
        Ok(None)
    }

    /// Takes the central's Pairing Failed: the pairing ends, unanswered.
    fn pairing_failed(&mut self, params: &[u8]) -> Option<Outcome> {
        if !self.is_pairing() {
            return None;
        }
        self.end();
        self.pending &= self.latched;
        let reason = params.first().map_or(Reason::UNSPECIFIED, |&code| Reason(code));
        Some(Outcome::Failed { by_central: true, reason })
    }

    /// Takes a Pairing Request, received at `now`.
    fn pairing_request(&mut self, params: &[u8], now: Instant) -> Result<Option<Outcome>, Reason> {
        if self.is_pairing() {
            return Err(Reason::UNSPECIFIED);
        }
        let &[io, oob, auth, key_size, init_dist, resp_dist] = params else {
            return Err(Reason::INVALID_PARAMETERS);
        };
        if !self.pairable {
            return Err(Reason::PAIRING_NOT_SUPPORTED);
        }
        if io > IO_CAPABILITY_MAX || oob > 1 || !(KEY_SIZE_MIN..=KEY_SIZE).contains(&key_size) {
            return Err(Reason::INVALID_PARAMETERS);
        }
        if auth & AUTH_SECURE_CONNECTIONS == 0 || auth & AUTH_BONDING == 0 {
            return Err(Reason::AUTHENTICATION_REQUIREMENTS);
        }
        if key_size < KEY_SIZE {
            return Err(Reason::ENCRYPTION_KEY_SIZE);
        }
        if oob != 0 {
            // With Secure Connections, out of band data on one side is
            // enough for that method, which we cannot follow.
            return Err(Reason::OOB_NOT_AVAILABLE);
        }
        // With Secure Connections and our MITM flag, the IO capabilities
        // choose the method: Passkey Entry unless the central has neither
        // input nor output.
        #[cfg(feature = "passkey")]
        let authenticating = self.security.protects() && io != NO_INPUT_NO_OUTPUT;
        #[cfg(feature = "passkey")]
        if self.security.require_mitm && !authenticating {
            return Err(Reason::AUTHENTICATION_REQUIREMENTS);
        }
        self.end();
        #[cfg(feature = "passkey")]
        self.set_authenticating(authenticating);
        // Only the PDU being sent stays from an earlier pairing.
        self.pending &= self.latched;
        self.io_cap = [auth, oob, io];
        self.init_dist = init_dist & KEY_DIST_ID;
        self.resp_dist = resp_dist & KEY_DIST_ID;
        if self.resp_dist == 0 {
            // BlueZ keeps no bond without our identity address.
            info!("smp: the central asks for no identity keys");
        }
        self.pending |= OUT_RESPONSE;
        self.state = State::PublicKey;
        self.deadline = Some(now.checked_add(TIMEOUT).unwrap_or(Instant::MAX));
        self.prepare_key_pair();
        Ok(Some(Outcome::Started))
    }

    /// Takes the passkey the user typed, at `now`, with `crypto` for our
    /// first confirm value, or `None` if the user gave up, which fails the
    /// pairing with Passkey Entry Failed (0x01). The outcome is that of the
    /// pairing: [`Outcome::Failed`] for `None`.
    ///
    /// # Errors
    ///
    /// [`PasskeyError::NotWaiting`] unless [`Self::awaits_passkey`],
    /// [`PasskeyError::Invalid`] above [`PASSKEY_MAX`].
    #[cfg(feature = "passkey")]
    #[inline]
    pub fn passkey<C>(
        &mut self,
        crypto: &mut C,
        passkey: Option<u32>,
        now: Instant,
    ) -> Result<Option<Outcome>, PasskeyError>
    where
        C: Aes + Random,
    {
        if !self.awaits_passkey() {
            return Err(PasskeyError::NotWaiting);
        }
        let Some(value) = passkey else { return Ok(self.fail(Reason::PASSKEY_ENTRY_FAILED, true)) };
        if value > PASSKEY_MAX {
            return Err(PasskeyError::Invalid);
        }
        self.passkey = value;
        self.deadline = Some(now.checked_add(TIMEOUT).unwrap_or(Instant::MAX));
        if self.state == State::Input {
            self.send_confirm(crypto, 0);
        }
        Ok(None)
    }

    /// The Z of f4 in `round` of Passkey Entry: 0x80 with the passkey's bit
    /// of the round, the least significant in round 0.
    #[cfg(feature = "passkey")]
    const fn passkey_bit(&self, round: u8) -> u8 {
        let passkey = if self.passkey == NO_PASSKEY { 0 } else { self.passkey };
        let bit = passkey.checked_shr(u32::from(round)).unwrap_or_default() & 1;
        0x80 | u8::from(bit != 0)
    }

    /// Takes the central's nonce of a round of Passkey Entry: checks its
    /// confirm value of the round with it and answers with our nonce.
    #[cfg(feature = "passkey")]
    fn passkey_random<A>(&mut self, aes: &A, params: &[u8]) -> Result<Option<Outcome>, Reason>
    where
        A: Aes,
    {
        let State::Nonce(round) = self.state else { return Err(Reason::UNSPECIFIED) };
        if self.queued(OUT_CONFIRM) {
            return Err(Reason::UNSPECIFIED);
        }
        let na = reversed(params.try_into().map_err(|_error: TryFromSliceError| Reason::INVALID_PARAMETERS)?);
        let peer_x = self.peer_key.first_chunk::<KEY_LEN>().ok_or(Reason::UNSPECIFIED)?;
        let own_x = self.own_key.first_chunk::<KEY_LEN>().ok_or(Reason::UNSPECIFIED)?;
        let expected = f4(aes, peer_x, own_x, &na, self.passkey_bit(round));
        if !same(&expected, &self.peer_confirm) {
            return Err(Reason::CONFIRM_VALUE_FAILED);
        }
        self.na = na;
        self.pending |= OUT_RANDOM;
        let next = round.saturating_add(1);
        self.state = if next < PASSKEY_ROUNDS { State::Confirm(next) } else { State::Check(false) };
        Ok(None)
    }

    /// Notes that the PDU [`Self::next_pdu`] gave was queued whole, at
    /// `now`, which restarts the pairing's timer.
    #[inline]
    pub fn pdu_sent(&mut self, now: Instant) -> Option<Outcome> {
        if self.latched == 0 {
            return None;
        }
        self.pending &= !self.latched;
        self.latched = 0;
        if self.is_pairing() {
            self.deadline = Some(now.checked_add(TIMEOUT).unwrap_or(Instant::MAX));
        }
        #[cfg(feature = "passkey")]
        if self.state == State::Confirm(0) && self.passkey == NO_PASSKEY {
            // Both sides may wait for their users: the timer runs again
            // from the central's first confirm value or the passkey.
            self.deadline = None;
        }
        if self.keys_exchanged() && self.dh == Dh::Unasked && !self.queued(OUT_PUBLIC_KEY | OUT_CONFIRM) {
            self.dh = Dh::Asked;
            self.job = Some(Task::DhKey);
        }
        self.finish()
    }

    /// Asks for a key pair if the slot is empty and none is being made:
    /// before pairable advertising starts, which then waits for
    /// [`Self::has_key_pair`], and when a pairing finds the slot empty (see
    /// [the key pair slot](self#the-key-pair-slot)).
    #[inline]
    pub fn prepare_key_pair(&mut self) {
        let making = self.running.is_some_and(|(task, _)| task == Task::KeyPair);
        if matches!(self.slot, Slot::Empty) && self.job.is_none() && !making {
            self.job = Some(Task::KeyPair);
        }
    }

    /// Takes the central's public key.
    fn public_key<C>(&mut self, crypto: &mut C, params: &[u8]) -> Result<Option<Outcome>, Reason>
    where
        C: Aes + Random,
    {
        if self.state != State::PublicKey || self.queued(OUT_RESPONSE) {
            return Err(Reason::UNSPECIFIED);
        }
        let key: &[u8; PUBLIC_KEY_LEN] =
            params.try_into().map_err(|_error: TryFromSliceError| Reason::INVALID_PARAMETERS)?;
        self.peer_key = flip_coordinates(key);
        if self.has_key_pair() {
            return self.answer_public_key(crypto);
        }
        self.state = State::KeyPair;
        self.prepare_key_pair();
        Ok(None)
    }

    /// Whether an output of `bits` is queued or being sent.
    const fn queued(&self, bits: u8) -> bool { (self.pending | self.latched) & bits != 0 }

    /// R of f6: the passkey as a 128-bit value for Passkey Entry, zero for
    /// Just Works; most significant octet first.
    #[cfg(feature = "passkey")]
    const fn r_value(&self) -> [u8; 16] {
        let mut value = R_ZERO;
        if self.authenticating
            && self.passkey != NO_PASSKEY
            && let Some(low) = value.last_chunk_mut::<4>()
        {
            *low = be32_bytes(self.passkey);
        }
        value
    }

    /// Takes the central's nonce.
    const fn random(&mut self, params: &[u8]) -> Result<Option<Outcome>, Reason> {
        if self.state != State::Random || self.queued(OUT_PUBLIC_KEY | OUT_CONFIRM) {
            return Err(Reason::UNSPECIFIED);
        }
        self.na = reversed(params.try_into().map_err(const |_error: TryFromSliceError| Reason::INVALID_PARAMETERS)?);
        self.pending |= OUT_RANDOM;
        self.state = State::Check(false);
        Ok(None)
    }

    /// Takes a PDU of the security manager channel, `encrypted` if each of
    /// its fragments was received encrypted, at `now`.
    #[inline]
    pub fn receive<C>(&mut self, crypto: &mut C, pdu: &[u8], encrypted: bool, now: Instant) -> Option<Outcome>
    where
        C: Aes + Random,
    {
        if self.state == State::TimedOut {
            return None;
        }
        let (&code, params) = pdu.split_first()?;
        // A refused request is reported, as is the end of a pairing.
        let report = code == PAIRING_REQUEST || self.is_pairing();
        let answer = match code {
            PAIRING_REQUEST => self.pairing_request(params, now),
            PAIRING_PUBLIC_KEY => self.public_key(crypto, params),
            #[cfg(feature = "passkey")]
            PAIRING_CONFIRM if self.authenticating => self.pairing_confirm(crypto, params, now),
            #[cfg(feature = "passkey")]
            PAIRING_RANDOM if self.authenticating => self.passkey_random(&*crypto, params),
            #[cfg(feature = "passkey")]
            KEYPRESS_NOTIFICATION if self.authenticating && !self.queued(OUT_FAILED) => return None,
            PAIRING_RANDOM => self.random(params),
            PAIRING_DHKEY_CHECK => self.dhkey_check(&*crypto, params),
            IDENTITY_INFORMATION => self.identity_information(params, encrypted),
            IDENTITY_ADDRESS_INFORMATION => self.identity_address(params, encrypted),
            PAIRING_FAILED => return self.pairing_failed(params),
            PAIRING_RESPONSE
            | PAIRING_CONFIRM
            | ENCRYPTION_INFORMATION
            | CENTRAL_IDENTIFICATION
            | SIGNING_INFORMATION
            | SECURITY_REQUEST
            | KEYPRESS_NOTIFICATION => Err(Reason::UNSPECIFIED),
            _ => Err(Reason::COMMAND_NOT_SUPPORTED),
        };
        answer.unwrap_or_else(|reason| self.fail(reason, report))
    }

    /// Whether the crypto task is to fill the key pair slot now, in idle
    /// time: a pairing used the key pair and ended without a bond, Pairing
    /// Requests are taken, the slot is empty, no job waits or runs and no
    /// pairing is under way. Never during a pairing, so it neither delays a
    /// Diffie-Hellman job nor blocks the thread while the user types a
    /// passkey; never after a bond, while the link is in use; and never in
    /// reconnection mode, which takes no Pairing Request.
    const fn refill_due(&self) -> bool {
        self.refill
            && self.pairable
            && matches!(self.slot, Slot::Empty)
            && self.job.is_none()
            && self.running.is_none()
            && !self.is_pairing()
    }

    /// Queues our confirm value of `round` of Passkey Entry, with a fresh
    /// nonce: `Cbi = f4(PKbx, PKax, Nbi, 0x80 | r_i)`.
    #[cfg(feature = "passkey")]
    fn send_confirm<C>(&mut self, crypto: &mut C, round: u8)
    where
        C: Aes + Random,
    {
        crypto.fill(&mut self.nb);
        let bit = self.passkey_bit(round);
        if let Some(peer_x) = self.peer_key.first_chunk::<KEY_LEN>()
            && let Some(own_x) = self.own_key.first_chunk::<KEY_LEN>()
        {
            self.confirm = f4(&*crypto, own_x, peer_x, &self.nb, bit);
        }
        self.pending |= OUT_CONFIRM;
        self.state = State::Nonce(round);
    }

    /// Records whether the pairing under way is Passkey Entry.
    #[cfg(feature = "passkey")]
    const fn set_authenticating(&mut self, authenticating: bool) { self.authenticating = authenticating; }

    /// Sets our own identity, which pairing distributes: the identity
    /// resolving key, least significant octet first as
    /// [`crate::link::Link::add_peer`] takes it, and the static random
    /// identity address, least significant octet first.
    #[inline]
    pub const fn set_identity(&mut self, irk: [u8; 16], address: [u8; 6]) {
        self.irk = irk;
        self.address = address;
    }

    /// Sets whether a Pairing Request is taken; one that is not gets Pairing
    /// Not Supported (0x05). A pairing under way goes on.
    #[inline]
    pub const fn set_pairable(&mut self, pairable: bool) { self.pairable = pairable; }

    /// Fails the pairing with the reason of a failed step.
    fn settle(&mut self, answer: Result<Option<Outcome>, Reason>) -> Option<Outcome> {
        answer.unwrap_or_else(|reason| self.fail(reason, true))
    }

    /// The next job for the crypto task, if one waits: one a pairing asked
    /// for, else the refill of the key pair slot if it is due
    /// (see [the key pair slot](self#the-key-pair-slot)).
    #[inline]
    pub fn take_job(&mut self) -> Option<Job> {
        let task = self.job.take().or_else(|| self.refill_due().then_some(Task::KeyPair))?;
        let kind = match task {
            Task::DhKey => {
                // Only the pairing's own key pair, whose public key went to
                // the central.
                let pair = match mem::replace(&mut self.slot, Slot::Empty) {
                    Slot::Used(pair) => pair,
                    other @ (Slot::Empty | Slot::Ready(_)) => {
                        self.slot = other;
                        return None;
                    },
                };
                self.serial = self.serial.wrapping_add(1);
                self.running = Some((Task::DhKey, self.serial));
                JobKind::DhKey { pair, peer: self.peer_key, serial: self.serial }
            },
            Task::KeyPair => {
                self.running = Some((Task::KeyPair, 0));
                JobKind::KeyPair
            },
        };
        Some(Job { kind })
    }

    /// Whether the central's identity keys are taken now: offered, after
    /// our `DHKey` check and received encrypted. They may overtake the
    /// encryption event, but never the encryption.
    const fn takes_keys(&self, encrypted: bool) -> bool {
        encrypted && self.init_dist != 0 && matches!(self.state, State::Encryption | State::Keys)
    }

    /// Verifies the central's `DHKey` check with the Diffie-Hellman key, and
    /// queues ours.
    fn verify<A>(&mut self, aes: &A) -> Result<Option<Outcome>, Reason>
    where
        A: Aes,
    {
        let (addr_a, addr_b) = (address(self.central), address(self.local));
        #[cfg(not(feature = "passkey"))]
        let (r_value, io_cap_b) = (&R_ZERO, IO_CAP_B);
        #[cfg(feature = "passkey")]
        let (mut r_passkey, io_cap_b) =
            (self.r_value(), [self.security.auth_req(), 0, self.security.io_capability.code()]);
        #[cfg(feature = "passkey")]
        let r_value = &r_passkey;
        let (mut mac_key, mut ltk) = f5(aes, &self.dh_key, (&self.na, &self.nb), (&addr_a, &addr_b));
        wipe(&mut self.dh_key);
        let expected = f6(aes, &mac_key, (&self.na, &self.nb), r_value, self.io_cap, (&addr_a, &addr_b));
        if !same(&expected, &self.check) {
            wipe(&mut mac_key);
            wipe(&mut ltk);
            #[cfg(feature = "passkey")]
            wipe(&mut r_passkey);
            return Err(Reason::DHKEY_CHECK_FAILED);
        }
        self.check = f6(aes, &mac_key, (&self.nb, &self.na), r_value, io_cap_b, (&addr_b, &addr_a));
        wipe(&mut mac_key);
        #[cfg(feature = "passkey")]
        wipe(&mut r_passkey);
        self.ltk = reversed(&ltk);
        wipe(&mut ltk);
        self.pending |= OUT_CHECK;
        self.state = State::Encryption;
        Ok(None)
    }

    /// A security manager as [`Self::new`], with the IO capability and
    /// requirements of `security`.
    #[cfg(feature = "passkey")]
    #[inline]
    #[must_use = "the security manager is only built"]
    pub const fn with_security(security: Security) -> Self {
        let mut responder = Self::new();
        responder.security = security;
        responder
    }
}

#[cfg(feature = "passkey")]
impl IoCapability {
    /// The IO capability's code in the Pairing Response.
    #[inline]
    #[must_use = "the code is only read"]
    pub const fn code(self) -> u8 {
        match self {
            Self::KeyboardOnly => KEYBOARD_ONLY,
            Self::NoInputNoOutput => NO_INPUT_NO_OUTPUT,
        }
    }

    /// The name of the IO capability, for a defmt log line (`{=istr}`):
    /// interned, so the string stays in the `.defmt` section, which takes no
    /// flash.
    #[cfg(feature = "defmt")]
    #[inline]
    #[must_use = "the name is only read"]
    pub fn name(self) -> defmt::Str {
        match self {
            Self::KeyboardOnly => defmt::intern!("KeyboardOnly"),
            Self::NoInputNoOutput => defmt::intern!("NoInputNoOutput"),
        }
    }
}

#[cfg(feature = "passkey")]
impl Security {
    /// No input and no output: Just Works only, the default.
    pub const JUST_WORKS: Self = Self { io_capability: IoCapability::NoInputNoOutput, require_mitm: false };

    /// Our `AuthReq`: bonding and Secure Connections, and protection against
    /// a man in the middle if we can give it.
    #[inline]
    #[must_use = "the value is only read"]
    pub const fn auth_req(self) -> u8 { if self.protects() { AUTH_REQ | AUTH_MITM } else { AUTH_REQ } }

    /// A setting of `io_capability`, which refuses pairing without
    /// protection against a man in the middle if `require_mitm`.
    #[inline]
    #[must_use = "the setting is only built"]
    pub const fn new(io_capability: IoCapability, require_mitm: bool) -> Self { Self { io_capability, require_mitm } }

    /// Whether we can protect against a man in the middle: Passkey Entry
    /// with a central that has a display or a keyboard.
    #[inline]
    #[must_use = "the value is only read"]
    pub const fn protects(self) -> bool { matches!(self.io_capability, IoCapability::KeyboardOnly) }
}

impl Default for Responder {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// A public key with each coordinate in the other byte order, X then Y:
/// the PDU's order from the toolbox's, and back.
fn flip_coordinates(key: &[u8; PUBLIC_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let mut out = *key;
    #[rustc_unroll(never)]
    for coordinate in out.as_chunks_mut::<KEY_LEN>().0 {
        coordinate.reverse();
    }
    out
}

/// Overwrites a passkey with `blank`, out of the range of passkeys, once it
/// is no longer needed, so its digits do not outlive their use in RAM, as
/// [`wipe`] does with key material.
#[cfg(feature = "passkey")]
pub(crate) fn forget(passkey: &mut u32, blank: u32) {
    *passkey = blank;
    // Keeps the compiler from dropping the store.
    black_box(passkey);
    compiler_fence(Ordering::SeqCst);
}

/// `value` in the other byte order.
const fn reversed<const N: usize>(value: &[u8; N]) -> [u8; N] {
    let mut out = *value;
    out.reverse();
    out
}

/// Whether two check values are the same, in a time that does not depend
/// on where they differ.
fn same(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter().zip(right.iter()).fold(0, |difference: u8, (&one, &other)| difference | (one ^ other)) == 0
}

#[cfg(test)] pub(crate) mod tests;
