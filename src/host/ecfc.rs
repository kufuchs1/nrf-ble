//! The credit based channels that carry Enhanced ATT, as the responder.
//!
//! They are L2CAP's Enhanced Credit Based Flow Control mode (Core, Vol 3,
//! Part A, 3.4, 4.24 to 4.28 and 10.2) on the SPSM of EATT, 0x0027.
//!
//! [`Ecfc`] keeps the [`BEARERS`] enhanced bearers of a link, 1 or with the
//! features `eatt-bearers-2` to `eatt-bearers-5` up to 5. Bearer `b`
//! ([`BearerId`]) has our CID 0x0040 + `b`
//! ([`crate::host::l2cap::Channel::Eatt`]), an MTU of [`MTU`] (65, the ATT
//! MTU of [`crate::host::att::ATT_MAX`]), an MPS of [`MPS`] (67, so a peer
//! that segments by our MPS never splits an SDU of 65 octets), and grants
//! [`RX_CREDITS`] (256) K-frames, topped up again by a Flow Control Credit
//! Indication once [`TOP_UP`] (128) or fewer are left. Its ATT MTU is the
//! smaller of 65 and the peer's MTU. The host only answers: it never asks for
//! a credit based channel or a reconfiguration itself.
//!
//! # A Credit Based Connection Request
//!
//! A request (well formed: identifier not 0, data length as its field says)
//! is checked in this order:
//!
//! 0. An identifier that a request still waiting for its answer has: dropped,
//!    as the spec's duplicate, which that answer serves.
//! 1. Less than 10 octets of data or an odd number, more than 5 source CIDs, an
//!    MTU or MPS below 64, or no credits: All Refused, Invalid Parameters
//!    (0x000C), at once.
//! 2. Another SPSM: All Refused, SPSM Not Supported (0x0002), at once.
//! 3. A link not encrypted with a key the host gave the link layer (the
//!    caller's `secure`; a request that itself arrived encrypted counts as
//!    proof): the whole request is held, until [`Ecfc::resolve_holds`] at the
//!    encryption or [`Ecfc::refuse_holds`]. Its bearers are reserved at once
//!    (step 5), so capacity goes first come, first served.
//! 4. Two or more source CIDs not in strictly ascending order: Some Refused,
//!    Insufficient Resources (0x0004), with every destination CID 0. Linux 7.3
//!    sends its source CIDs in another order, and binds our destination CIDs to
//!    its channels shifted by one, so each answer it could get is crossed; a
//!    central whose order is not ascending only gets fewer bearers, which is
//!    legal.
//! 5. Each source CID in turn: outside 0x0040 to 0x007F, Invalid Source CID
//!    (0x0009); a CID one of our bearers already has for the peer, Source CID
//!    Already Allocated (0x000A); no bearer left, Insufficient Resources
//!    (0x0004); otherwise the lowest free bearer. The result is that of the
//!    first source CID refused, or Success; a refused source CID gets
//!    destination CID 0.
//!
//! A held request is answered, at [`Ecfc::resolve_holds`], with steps 4 and
//! 5 as they were decided at its arrival, or, at [`Ecfc::refuse_holds`], with
//! Insufficient Encryption (0x0008) for the bonded central or Insufficient
//! Authentication (0x0005) for another, with every reservation freed: Linux
//! then encrypts, or pairs, and asks again. [`Ecfc::on_time`] refuses them
//! [`HOLD_MAX`] after the first one arrived, unless the encryption is under
//! way; then they wait for it.
//!
//! Every Credit Based Connection Response carries our MTU, MPS and credits,
//! refusals included, and one destination CID for each source CID of its
//! request, up to 5. Up to [`PENDING`] (5) requests wait for their answer at
//! once, whatever the number of bearers: after a refusal for security, Linux
//! sends one request for each of its channels in a burst. A request that finds
//! none free is dropped.
//!
//! # What is sent
//!
//! Nothing waits in a buffer: [`Ecfc::next_signal`] names the next command to
//! send, [`Ecfc::render`] renders it from the bearers' state, and
//! [`Ecfc::signal_sent`] notes that it went. The order is: the connection
//! responses, then the Disconnection Responses to the central, then our
//! Disconnection Requests, then the credits. A bearer becomes open once its
//! connection response went, and a released one free once its Disconnection
//! Response went: a destination CID is never given again while the central
//! may still hold a channel with it. Each command fits one link layer
//! fragment.
//!
//! # Data
//!
//! A K-frame received on an open bearer takes one of its credits and goes to
//! the [`SduRx`] of the link ([`Ecfc::receive`]), which hands on each
//! complete SDU, an ATT PDU. A K-frame without a credit, or one that breaks
//! the channel's rules, closes the bearer, as does a K-frame too long for the
//! reassembly buffer ([`Ecfc::close`]). One buffer serves the split SDUs of
//! all bearers: a bearer that starts one while another bearer's fills it is
//! closed. Data on a bearer that is not open is dropped.
//!
//! An SDU goes out in K-frames ([`Ecfc::kframe`]), each taking one of the
//! peer's credits once its first fragment is queued
//! ([`Ecfc::kframe_queued`]): the first carries the SDU length and up to the
//! peer's MPS less 2 octets, a later one up to its MPS. A bearer without
//! credits waits, as long as the peer gives none.
//!
//! # Other commands
//!
//! - Flow Control Credit Indication for the peer's CID of an open bearer: its
//!   credits grow; a sum above 65535 closes the bearer; 0 credits and other
//!   CIDs are ignored.
//! - Credit Based Reconfigure Request: each CID it lists must be the peer's CID
//!   of an open bearer (else 0x0003), MTU and MPS at least 64 (else 0x0004),
//!   the MTU no lower than any listed bearer's (else 0x0001), the MPS no lower
//!   than any listed bearer's when it lists two or more (else 0x0002).
//!   Otherwise every listed bearer takes them.
//! - Disconnection Request for one of our CIDs: on an open or closing bearer
//!   with the peer's CID as source, the bearer is released and answered; with
//!   another source CID it is dropped (Core, Vol 3, Part A, 4.6); on a bearer
//!   already released, whose answer is still to be sent, it is dropped too; on
//!   a bearer that is free or not yet answered, a Command Reject, invalid CID.
//! - Our Disconnection Request ([`Ecfc::close`]) takes the next identifier of
//!   the signalling channel. Data on the bearer is dropped from then on. A
//!   Disconnection Response with its identifier and CIDs, or a Command Reject
//!   with its identifier, frees the bearer; so does [`CLOSE_TIMEOUT`] (30 s)
//!   after the last one we sent.

use crate::{
    host::{
        att::ATT_MAX,
        l2cap::{Channel, SduRx, Segmenter},
        signal::{
            COMMAND_REJECT,
            CREDIT_BASED_CONNECTION_REQUEST,
            CREDIT_BASED_CONNECTION_RESPONSE,
            CREDIT_BASED_RECONFIGURE_REQUEST,
            Command,
            DISCONNECTION_REQUEST,
            DISCONNECTION_RESPONSE,
            FLOW_CONTROL_CREDIT_IND,
            HEADER_LEN,
            Signalling,
        },
    },
    pdu::concat_into,
};
use embassy_time::{Duration, Instant};

/// The number of enhanced bearers a link may have: the highest of the
/// features `eatt-bearers-2` to `eatt-bearers-5`, 1 without them.
pub const BEARERS: usize = if cfg!(feature = "eatt-bearers-5") {
    5
} else if cfg!(feature = "eatt-bearers-4") {
    4
} else if cfg!(feature = "eatt-bearers-3") {
    3
} else if cfg!(feature = "eatt-bearers-2") {
    2
} else {
    1
};
/// The SPSM of Enhanced ATT.
pub const SPSM: u16 = 0x0027;
/// Our CID of bearer 0; bearer `b` has this plus `b`.
pub const FIRST_CID: u16 = 0x0040;
/// Our MTU on each bearer: the largest SDU we take, an ATT PDU of
/// [`ATT_MAX`] octets.
pub const MTU: u16 = 65;
/// Our MPS on each bearer: the largest K-frame payload we take, the SDU
/// length field and an SDU of [`MTU`] octets.
pub const MPS: u16 = 67;
/// The credits we grant each bearer: at the start and with each top up.
pub const RX_CREDITS: u16 = 256;
/// The credits left at which we top them up to [`RX_CREDITS`] again.
pub const TOP_UP: u16 = 128;
/// The longest wait of a held request for the encryption while nothing is
/// under way that leads to it.
pub const HOLD_MAX: Duration = Duration::from_secs(2);
/// The longest wait for the response to our Disconnection Request.
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(30);
/// The number of connection requests that may wait for their answer at once.
pub const PENDING: usize = 5;
/// The longest command [`Ecfc::render`] renders: a Credit Based Connection
/// Response with 5 destination CIDs.
pub const SIGNAL_MAX: usize = HEADER_LEN.strict_add(8).strict_add(SCIDS_MAX.strict_mul(2));
/// The most source CIDs a request names.
const SCIDS_MAX: usize = 5;
/// The least MTU and MPS of a credit based channel.
const PARAMS_MIN: u16 = 64;
/// The first CID of the dynamically allocated range of LE.
const DYNAMIC_FIRST: u16 = 0x0040;
/// The last CID of the dynamically allocated range of LE.
const DYNAMIC_LAST: u16 = 0x007F;
/// Connection result: All Connections Successful.
const SUCCESS: u8 = 0x00;
/// Connection result: All Refused, SPSM Not Supported.
const SPSM_NOT_SUPPORTED: u8 = 0x02;
/// Connection result: Some Refused, Insufficient Resources Available.
const NO_RESOURCES: u8 = 0x04;
/// Connection result: All Refused, Insufficient Authentication.
const INSUFFICIENT_AUTHENTICATION: u8 = 0x05;
/// Connection result: All Refused, Insufficient Encryption.
const INSUFFICIENT_ENCRYPTION: u8 = 0x08;
/// Connection result: Some Refused, Invalid Source CID.
const INVALID_SCID: u8 = 0x09;
/// Connection result: Some Refused, Source CID Already Allocated.
const SCID_ALLOCATED: u8 = 0x0A;
/// Connection result: All Refused, Invalid Parameters.
const INVALID_PARAMETERS: u8 = 0x0C;
/// Reconfigure result: successful.
const RECONFIGURED: u16 = 0x0000;
/// Reconfigure result: reduction of the MTU not allowed.
const MTU_REDUCED: u16 = 0x0001;
/// Reconfigure result: reduction of the MPS not allowed for more than one
/// channel.
const MPS_REDUCED: u16 = 0x0002;
/// Reconfigure result: a destination CID invalid.
const INVALID_DCID: u16 = 0x0003;
/// Reconfigure result: other unacceptable parameters.
const UNACCEPTABLE: u16 = 0x0004;

// The bearers' CIDs are dynamic ones, the SDU of our MTU is an ATT PDU the
// slots hold, and a K-frame of our MPS holds it whole after the SDU length.
const _: () = assert!(
    BEARERS <= SCIDS_MAX
        && FIRST_CID >= DYNAMIC_FIRST
        && usize::from(FIRST_CID).strict_add(BEARERS) <= usize::from(DYNAMIC_LAST).strict_add(1)
        && usize::from(MTU) == ATT_MAX
        && MPS == MTU.strict_add(2),
    "the bearers' CIDs are dynamic, the MTU is the ATT MTU, the MPS holds it whole"
);

/// One of the [`BEARERS`] enhanced bearers of a link, by its index: bearer
/// `b` has our CID [`FIRST_CID`] + `b`. Only an index below [`BEARERS`] is
/// one.
#[derive(Clone, Copy, Debug, Eq)]
#[derive_const(PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BearerId(u8);

/// The entry of a connection request that waits for its answer, below
/// [`PENDING`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PendingId(u8);

/// A command to send, which [`Ecfc::next_signal`] names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Signal {
    /// Our Disconnection Request for this bearer.
    Close(BearerId),
    /// A Flow Control Credit Indication.
    Credits {
        /// The bearer.
        bearer:  BearerId,
        /// The credits it grants.
        credits: u16,
    },
    /// The Disconnection Response to the central's request for this bearer.
    Released(BearerId),
    /// The Credit Based Connection Response to the request in this
    /// pending entry.
    Response(PendingId),
}

/// The state of one bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Accepted, with its connection response still to send.
    Answer {
        /// The request's identifier.
        ident: u8,
        /// The position of its source CID in the request.
        pos:   u8,
    },
    /// Our Disconnection Request is to be sent, or waits for its response.
    Closing {
        /// Its identifier.
        ident: u8,
        /// Whether it was sent.
        sent:  bool,
    },
    /// Reserved by a request held until the link is encrypted.
    Held {
        /// The request's identifier.
        ident: u8,
        /// The position of its source CID in the request.
        pos:   u8,
    },
    /// Free.
    Idle,
    /// Open: it carries ATT.
    Open,
    /// The central asked to close it; our Disconnection Response is to be
    /// sent.
    Released {
        /// The request's identifier.
        ident: u8,
    },
}

/// One enhanced bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Bearer {
    /// The identifier of the Flow Control Credit Indication to send, 0 if
    /// none is owed.
    owed:       u8,
    /// The peer's CID.
    peer_cid:   u16,
    /// The peer's MPS.
    peer_mps:   u16,
    /// The peer's MTU.
    peer_mtu:   u16,
    /// The credits the peer has left to send to us.
    rx_credits: u16,
    /// The octets of the SDU being sent that went in earlier K-frames.
    sent:       u8,
    /// Its state.
    state:      State,
    /// The credits we have left to send to the peer.
    tx_credits: u16,
}

/// A connection request that waits for its answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pending {
    /// The result.
    code:  u8,
    /// The number of destination CIDs the answer carries.
    count: u8,
    /// Whether it is held until the link is encrypted.
    held:  bool,
    /// The request's identifier, 0 for a free entry.
    ident: u8,
}

/// The credit based channels of one link: the enhanced bearers, the
/// connection requests that wait for their answer, the deadlines and the
/// buffer of a split SDU.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Ecfc {
    /// The bearers.
    bearers:     [Bearer; BEARERS],
    /// When our Disconnection Requests that went have waited long enough.
    close_until: Option<Instant>,
    /// When the held requests have waited long enough, if nothing is under
    /// way.
    hold_until:  Option<Instant>,
    /// The connection requests that wait for their answer.
    pending:     [Pending; PENDING],
    /// The buffer of a split SDU.
    sdu:         SduRx,
}

impl BearerId {
    /// Bearer 0.
    pub(crate) const FIRST: Self = Self(0);

    /// Every bearer, in order.
    #[inline]
    pub fn all() -> impl Iterator<Item = Self> + Clone { (0_u8..).take(BEARERS).map(Self) }

    /// Our CID of the bearer.
    #[inline]
    #[must_use = "the identifier is only read"]
    pub const fn cid(self) -> u16 { FIRST_CID.saturating_add(u16::from(self.0)) }

    /// The bearer with our CID `cid`, if any.
    #[inline]
    #[must_use = "the bearer is only looked up"]
    pub const fn from_cid(cid: u16) -> Option<Self> {
        let Some(index) = cid.checked_sub(FIRST_CID) else { return None };
        Self::new(usize::from(index))
    }

    /// The bearer's index in an array of [`BEARERS`] entries.
    pub(crate) const fn index(self) -> usize { usize::from(self.0) }

    /// The bearer of `index`, if it is below [`BEARERS`].
    pub(crate) const fn new(index: usize) -> Option<Self> {
        if index < BEARERS { Some(Self(index.saturating_cast())) } else { None }
    }

    /// The bearer after this one, bearer 0 after the last.
    pub(crate) const fn next(self) -> Self { Self::new(self.index().saturating_add(1)).unwrap_or(Self::FIRST) }

    /// The bearer of `index`, which a test gives below [`BEARERS`]; it panics
    /// otherwise.
    #[cfg(test)]
    pub(crate) const fn valid(index: u8) -> Self {
        assert!(usize::from(index) < BEARERS, "not a bearer");
        Self(index)
    }
}

impl Bearer {
    /// A free bearer.
    const IDLE: Self = Self {
        owed:       0,
        peer_cid:   0,
        peer_mps:   0,
        peer_mtu:   0,
        rx_credits: 0,
        sent:       0,
        state:      State::Idle,
        tx_credits: 0,
    };

    /// Closes the bearer if it is open: our Disconnection Request is to be
    /// sent, with the next identifier of `signal`.
    const fn close(&mut self, signal: &mut Signalling) {
        if matches!(self.state, State::Open) {
            self.state = State::Closing { ident: signal.next_identifier(), sent: false };
            self.owed = 0;
        }
    }
}

impl Pending {
    /// A free entry.
    const FREE: Self = Self { code: SUCCESS, count: 0, held: false, ident: 0 };
}

impl Ecfc {
    /// Gives each of `scids` in turn the lowest free bearer, `held` or to be
    /// answered, with the peer's values of `template`, and returns the result:
    /// that of the first source CID refused, or success.
    fn allocate(&mut self, identifier: u8, scids: &[[u8; 2]], held: bool, template: Bearer) -> u8 {
        let mut code = SUCCESS;
        for (pos, &scid) in (0_u8..).zip(scids) {
            let peer_cid = u16::from_le_bytes(scid);
            let refusal = if !(DYNAMIC_FIRST..=DYNAMIC_LAST).contains(&peer_cid) {
                Some(INVALID_SCID)
            } else if self.bearers.iter().any(|entry| entry.state != State::Idle && entry.peer_cid == peer_cid) {
                Some(SCID_ALLOCATED)
            } else if let Some(entry) = self.bearers.iter_mut().find(|entry| entry.state == State::Idle) {
                let state = if held {
                    State::Held { ident: identifier, pos }
                } else {
                    State::Answer { ident: identifier, pos }
                };
                *entry = Bearer { peer_cid, state, ..template };
                None
            } else {
                Some(NO_RESOURCES)
            };
            if code == SUCCESS
                && let Some(refused) = refusal
            {
                code = refused;
            }
        }
        code
    }

    /// The bearer's ATT MTU while it is open: the smaller of [`MTU`] and the
    /// peer's.
    #[inline]
    #[must_use = "the ATT MTU is only read"]
    pub fn att_mtu(&self, bearer: BearerId) -> Option<usize> {
        let entry = self.bearers.get(bearer.index()).filter(|entry| entry.state == State::Open)?;
        Some(usize::from(entry.peer_mtu.min(MTU)))
    }

    /// Closes `bearer` if it is open, with our Disconnection Request, which
    /// takes the next identifier of `signal`: for a K-frame too long for the
    /// reassembly buffer ([`crate::host::l2cap::Reassembly::take_overlong`]).
    #[inline]
    pub fn close(&mut self, signal: &mut Signalling, bearer: BearerId) {
        if let Some(entry) = self.bearers.get_mut(bearer.index())
            && entry.state == State::Open
        {
            warn!("ecfc: a K-frame too long; the bearer closes");
            entry.close(signal);
            self.sdu.release(bearer);
        }
    }

    /// Takes a received command of the credit based channels
    /// ([`crate::host::signal::Action::Ecfc`]): its `code`, `identifier` and
    /// `data`, at `now`. `secure` says whether the link is encrypted with a
    /// key the host gave the link layer, or the command itself arrived
    /// encrypted; `signal` gives the identifier of a Disconnection Request
    /// the command leads to. Returns the command to send in answer at once,
    /// if any: a Credit Based Reconfigure Response or a Command Reject. The
    /// other answers are rendered later ([`Self::next_signal`]).
    #[inline]
    pub fn command(
        &mut self,
        signal: &mut Signalling,
        code: u8,
        identifier: u8,
        data: &[u8],
        secure: bool,
        now: Instant,
    ) -> Option<Command> {
        match code {
            CREDIT_BASED_CONNECTION_REQUEST => self.connection_request(identifier, data, secure, now),
            CREDIT_BASED_RECONFIGURE_REQUEST => {
                return Some(Command::reconfigure_response(identifier, self.reconfigure(data)));
            },
            DISCONNECTION_REQUEST => return self.disconnection_request(identifier, data),
            DISCONNECTION_RESPONSE => self.disconnection_response(identifier, data),
            FLOW_CONTROL_CREDIT_IND => self.credits(signal, data),
            COMMAND_REJECT => {
                // The central rejects our Disconnection Request: the channel
                // is gone.
                if let Some(entry) = self
                    .bearers
                    .iter_mut()
                    .find(|entry| matches!(entry.state, State::Closing { ident, sent: _ } if ident == identifier))
                {
                    *entry = Bearer::IDLE;
                }
            },
            _ => {},
        }
        None
    }

    /// Takes a Credit Based Connection Request.
    fn connection_request(&mut self, identifier: u8, data: &[u8], secure: bool, now: Instant) {
        if self.pending.iter().any(|entry| entry.ident == identifier) {
            return;
        }
        let Some(index) = self.pending.iter().position(|entry| entry.ident == 0) else {
            warn!("ecfc: a connection request while every answer is pending; dropped");
            return;
        };
        let (fields, rest) = data.split_first_chunk::<8>().unwrap_or((&[0; 8], &[]));
        let &[spsm0, spsm1, mtu0, mtu1, mps0, mps1, credits0, credits1] = fields;
        let (scids, odd) = rest.as_chunks::<2>();
        let mtu = u16::from_le_bytes([mtu0, mtu1]);
        let mps = u16::from_le_bytes([mps0, mps1]);
        let credits = u16::from_le_bytes([credits0, credits1]);
        let valid = !scids.is_empty()
            && odd.is_empty()
            && scids.len() <= SCIDS_MAX
            && mtu >= PARAMS_MIN
            && mps >= PARAMS_MIN
            && credits > 0;
        let served = u16::from_le_bytes([spsm0, spsm1]) == SPSM;
        let held = valid && served && !secure;
        let code = if !valid {
            INVALID_PARAMETERS
        } else if !served {
            SPSM_NOT_SUPPORTED
        } else if !scids.is_sorted_by(|first, second| u16::from_le_bytes(*first) < u16::from_le_bytes(*second)) {
            info!("ecfc: source CIDs not ascending; refused");
            NO_RESOURCES
        } else {
            let template =
                Bearer { peer_mps: mps, peer_mtu: mtu, rx_credits: RX_CREDITS, tx_credits: credits, ..Bearer::IDLE };
            self.allocate(identifier, scids, held, template)
        };
        if held && self.hold_until.is_none() {
            self.hold_until = Some(now.checked_add(HOLD_MAX).unwrap_or(Instant::MAX));
        }
        if let Some(entry) = self.pending.get_mut(index) {
            *entry = Pending { code, count: scids.len().min(SCIDS_MAX).saturating_cast(), held, ident: identifier };
        }
    }

    /// Takes a Flow Control Credit Indication.
    fn credits(&mut self, signal: &mut Signalling, data: &[u8]) {
        let &[cid0, cid1, credits0, credits1] = data else { return };
        let credits = u16::from_le_bytes([credits0, credits1]);
        let peer_cid = u16::from_le_bytes([cid0, cid1]);
        let Some((bearer, entry)) = BearerId::all()
            .zip(self.bearers.iter_mut())
            .find_map(|(bearer, entry)| {
                (entry.state == State::Open && entry.peer_cid == peer_cid).then_some((bearer, entry))
            })
            .filter(|_| credits > 0)
        else {
            return;
        };
        if let Some(sum) = entry.tx_credits.checked_add(credits) {
            entry.tx_credits = sum;
        } else {
            warn!("ecfc: credits above 65535; the bearer closes");
            entry.close(signal);
            self.sdu.release(bearer);
        }
    }

    /// The next deadline for [`Self::on_time`], if any.
    #[inline]
    #[must_use = "the deadline is only read"]
    pub fn deadline(&self) -> Option<Instant> { [self.hold_until, self.close_until].into_iter().flatten().min() }

    /// Takes a Disconnection Request for one of our CIDs; returns a Command
    /// Reject for a bearer that is free, held or not yet answered.
    fn disconnection_request(&mut self, identifier: u8, data: &[u8]) -> Option<Command> {
        let &[dcid0, dcid1, scid0, scid1] = data else { return None };
        let dcid = u16::from_le_bytes([dcid0, dcid1]);
        let scid = u16::from_le_bytes([scid0, scid1]);
        let bearer = BearerId::from_cid(dcid)?;
        let entry = self.bearers.get_mut(bearer.index())?;
        match entry.state {
            State::Open | State::Closing { ident: _, sent: _ } => {
                if entry.peer_cid == scid {
                    entry.state = State::Released { ident: identifier };
                    entry.owed = 0;
                    self.sdu.release(bearer);
                }
                None
            },
            State::Released { ident: _ } => None,
            State::Answer { ident: _, pos: _ } | State::Held { ident: _, pos: _ } | State::Idle => {
                Some(Command::reject_cid(identifier, dcid, scid))
            },
        }
    }

    /// Takes a Disconnection Response: the one to our request frees its
    /// bearer.
    fn disconnection_response(&mut self, identifier: u8, data: &[u8]) {
        let &[dcid0, dcid1, scid0, scid1] = data else { return };
        let dcid = u16::from_le_bytes([dcid0, dcid1]);
        let scid = u16::from_le_bytes([scid0, scid1]);
        if let Some(entry) = BearerId::all().zip(self.bearers.iter_mut()).find_map(|(bearer, entry)| {
            (matches!(entry.state, State::Closing { ident, sent: _ } if ident == identifier)
                && entry.peer_cid == dcid
                && bearer.cid() == scid)
                .then_some(entry)
        }) {
            *entry = Bearer::IDLE;
        }
    }

    /// Whether `bearer` is open.
    #[inline]
    #[must_use = "the state is only read"]
    pub fn is_open(&self, bearer: BearerId) -> bool {
        self.bearers.get(bearer.index()).is_some_and(|entry| entry.state == State::Open)
    }

    /// The next K-frame of the SDU of `sdu_len` octets that `bearer` sends,
    /// `None` while the bearer is not open or has no credits.
    #[inline]
    #[must_use = "the segmenter is only built"]
    pub fn kframe(&self, bearer: BearerId, sdu_len: usize) -> Option<Segmenter> {
        let entry =
            self.bearers.get(bearer.index()).filter(|entry| entry.state == State::Open && entry.tx_credits > 0)?;
        Segmenter::kframe(Channel::Eatt(bearer), entry.peer_cid, sdu_len, usize::from(entry.sent), entry.peer_mps)
    }

    /// Notes that the first fragment of the K-frame `segmenter` of `bearer`
    /// was queued: it takes a credit. Returns whether it is the SDU's last.
    #[inline]
    pub const fn kframe_queued(&mut self, bearer: BearerId, segmenter: &Segmenter) -> bool {
        let (Some(entry), Some((end, total))) = (self.bearers.get_mut(bearer.index()), segmenter.kframe_end()) else {
            return false;
        };
        entry.tx_credits = entry.tx_credits.saturating_sub(1);
        let last = end >= total;
        entry.sent = if last { 0 } else { end.saturating_cast() };
        last
    }

    /// No bearer, no request, no deadline: a new link's.
    #[inline]
    #[must_use = "the channels are only built"]
    pub const fn new() -> Self {
        Self {
            bearers:     [Bearer::IDLE; BEARERS],
            close_until: None,
            hold_until:  None,
            pending:     [Pending::FREE; PENDING],
            sdu:         SduRx::new(),
        }
    }

    /// The next command to send, if any: the connection responses that are
    /// not held, then the Disconnection Responses, our Disconnection
    /// Requests, and the credits owed.
    #[inline]
    #[must_use = "the command is only named"]
    pub fn next_signal(&self) -> Option<Signal> {
        let response =
            (0_u8..).map(PendingId).zip(self.pending.iter()).find(|&(_, entry)| entry.ident != 0 && !entry.held);
        if let Some((index, _)) = response {
            return Some(Signal::Response(index));
        }
        let mut bearers = BearerId::all().zip(self.bearers.iter());
        let released = bearers.clone().find(|&(_, entry)| matches!(entry.state, State::Released { ident: _ }));
        let closing =
            bearers.clone().find(|&(_, entry)| matches!(entry.state, State::Closing { ident: _, sent: false }));
        let owing = bearers.find(|&(_, entry)| entry.state == State::Open && entry.owed != 0);
        released
            .map(|(bearer, _)| Signal::Released(bearer))
            .or_else(|| closing.map(|(bearer, _)| Signal::Close(bearer)))
            .or_else(|| {
                owing.map(|(bearer, entry)| Signal::Credits {
                    bearer,
                    credits: RX_CREDITS.saturating_sub(entry.rx_credits),
                })
            })
    }

    /// Takes the time `now`, past [`Self::deadline`]. Held requests that
    /// waited [`HOLD_MAX`] are refused ([`Self::refuse_holds`]), unless the
    /// encryption is `under_way` (a key reply or a pairing), when they wait
    /// for it; `bonded` says whether the central is the bonded one. Bearers
    /// whose Disconnection Request waited [`CLOSE_TIMEOUT`] are freed.
    #[inline]
    pub fn on_time(&mut self, now: Instant, under_way: bool, bonded: bool) {
        if self.hold_until.is_some_and(|until| until <= now) {
            if under_way {
                self.hold_until = None;
            } else {
                warn!("ecfc: not encrypted in time; held requests refused");
                self.refuse_holds(bonded);
            }
        }
        if self.close_until.is_some_and(|until| until <= now) {
            self.close_until = None;
            for entry in &mut self.bearers {
                if matches!(entry.state, State::Closing { ident: _, sent: true }) {
                    *entry = Bearer::IDLE;
                }
            }
        }
    }

    /// Takes the payload `kframe` of a K-frame received on `bearer`,
    /// `encrypted` or not, and returns the SDU it completes, if any, and
    /// whether each of its K-frames was received encrypted. A K-frame without
    /// a credit, or one that breaks the channel's rules, closes the bearer,
    /// with the next identifier of `signal`, which also gives the identifier
    /// of the credits that become owed.
    #[inline]
    pub fn receive<'buf>(
        &'buf mut self,
        signal: &mut Signalling,
        bearer: BearerId,
        kframe: &'buf [u8],
        encrypted: bool,
    ) -> Option<(&'buf [u8], bool)> {
        let entry = self.bearers.get_mut(bearer.index()).filter(|entry| entry.state == State::Open)?;
        let Some(credits) = entry.rx_credits.checked_sub(1) else {
            warn!("ecfc: a K-frame without a credit; the bearer closes");
            entry.close(signal);
            self.sdu.release(bearer);
            return None;
        };
        entry.rx_credits = credits;
        if credits <= TOP_UP && entry.owed == 0 {
            entry.owed = signal.next_identifier();
        }
        let Ok(sdu) = self.sdu.push(bearer, kframe, encrypted) else {
            warn!("ecfc: a K-frame breaks the channel's rules; the bearer closes");
            entry.close(signal);
            return None;
        };
        sdu
    }

    /// Takes a Credit Based Reconfigure Request and returns the result.
    fn reconfigure(&mut self, data: &[u8]) -> u16 {
        let Some((&[mtu0, mtu1, mps0, mps1], rest)) = data.split_first_chunk::<4>() else { return UNACCEPTABLE };
        let (cids, odd) = rest.as_chunks::<2>();
        if cids.is_empty() || !odd.is_empty() || cids.len() > SCIDS_MAX {
            return UNACCEPTABLE;
        }
        let mtu = u16::from_le_bytes([mtu0, mtu1]);
        let mps = u16::from_le_bytes([mps0, mps1]);
        let listed = |entry: &Bearer| entry.state == State::Open && cids.contains(&entry.peer_cid.to_le_bytes());
        let known = cids.iter().all(|&peer_cid| {
            self.bearers.iter().any(|entry| entry.state == State::Open && entry.peer_cid.to_le_bytes() == peer_cid)
        });
        let result = if !known {
            INVALID_DCID
        } else if mtu < PARAMS_MIN || mps < PARAMS_MIN {
            UNACCEPTABLE
        } else if self.bearers.iter().any(|entry| listed(entry) && entry.peer_mtu > mtu) {
            MTU_REDUCED
        } else if cids.len() >= 2 && self.bearers.iter().any(|entry| listed(entry) && entry.peer_mps > mps) {
            MPS_REDUCED
        } else {
            RECONFIGURED
        };
        if result == RECONFIGURED {
            for entry in self.bearers.iter_mut().filter(|entry| listed(entry)) {
                entry.peer_mtu = mtu;
                entry.peer_mps = mps;
            }
        }
        result
    }

    /// Answers the held requests with the refusal for security: Insufficient
    /// Encryption (0x0008) if the central is the `bonded` one, else
    /// Insufficient Authentication (0x0005), and frees their reservations.
    /// For an encryption that failed, or one that does not come.
    #[inline]
    pub fn refuse_holds(&mut self, bonded: bool) {
        self.hold_until = None;
        let code = if bonded { INSUFFICIENT_ENCRYPTION } else { INSUFFICIENT_AUTHENTICATION };
        for entry in self.pending.iter_mut().filter(|entry| entry.held) {
            entry.code = code;
            entry.held = false;
        }
        for entry in &mut self.bearers {
            if matches!(entry.state, State::Held { ident: _, pos: _ }) {
                *entry = Bearer::IDLE;
            }
        }
    }

    /// Renders the command `signal` into `out`, which holds [`SIGNAL_MAX`]
    /// octets, as the payload of a PDU on the LE signalling channel. Returns
    /// its length, 0 if the state no longer has it.
    #[inline]
    pub fn render(&self, signal: Signal, out: &mut [u8]) -> usize {
        match signal {
            Signal::Close(bearer) => {
                let Some(entry) = self.bearers.get(bearer.index()) else { return 0 };
                let State::Closing { ident, sent: _ } = entry.state else { return 0 };
                render_command(out, DISCONNECTION_REQUEST, ident, &[
                    &entry.peer_cid.to_le_bytes(),
                    &bearer.cid().to_le_bytes(),
                ])
            },
            Signal::Credits { bearer, credits } => {
                let Some(entry) = self.bearers.get(bearer.index()).filter(|entry| entry.owed != 0) else {
                    return 0;
                };
                render_command(out, FLOW_CONTROL_CREDIT_IND, entry.owed, &[
                    &bearer.cid().to_le_bytes(),
                    &credits.to_le_bytes(),
                ])
            },
            Signal::Released(bearer) => {
                let Some(entry) = self.bearers.get(bearer.index()) else { return 0 };
                let State::Released { ident } = entry.state else { return 0 };
                render_command(out, DISCONNECTION_RESPONSE, ident, &[
                    &bearer.cid().to_le_bytes(),
                    &entry.peer_cid.to_le_bytes(),
                ])
            },
            Signal::Response(index) => {
                let Some(entry) = self.pending.get(usize::from(index.0)).filter(|entry| entry.ident != 0) else {
                    return 0;
                };
                let mut dcids: [u8; SCIDS_MAX.strict_mul(2)] = [0; SCIDS_MAX.strict_mul(2)];
                for (pos, dcid) in (0_u8..).zip(dcids.as_chunks_mut::<2>().0.iter_mut()) {
                    let answered = BearerId::all()
                        .zip(self.bearers.iter())
                        .find(|&(_, bearer)| bearer.state == State::Answer { ident: entry.ident, pos });
                    if let Some((bearer, _)) = answered {
                        *dcid = bearer.cid().to_le_bytes();
                    }
                }
                render_command(out, CREDIT_BASED_CONNECTION_RESPONSE, entry.ident, &[
                    &MTU.to_le_bytes(),
                    &MPS.to_le_bytes(),
                    &RX_CREDITS.to_le_bytes(),
                    &u16::from(entry.code).to_le_bytes(),
                    dcids.get(..usize::from(entry.count).saturating_mul(2)).unwrap_or_default(),
                ])
            },
        }
    }

    /// Answers the held requests as they were decided at their arrival: the
    /// link is encrypted.
    #[inline]
    pub fn resolve_holds(&mut self) {
        self.hold_until = None;
        for entry in &mut self.pending {
            entry.held = false;
        }
        for entry in &mut self.bearers {
            if let State::Held { ident, pos } = entry.state {
                entry.state = State::Answer { ident, pos };
            }
        }
    }

    /// Notes that the command `signal` was queued, at `now`.
    #[inline]
    pub fn signal_sent(&mut self, signal: Signal, now: Instant) {
        match signal {
            Signal::Close(bearer) => {
                if let Some(entry) = self.bearers.get_mut(bearer.index())
                    && let State::Closing { ident, sent: false } = entry.state
                {
                    entry.state = State::Closing { ident, sent: true };
                    self.close_until = Some(now.checked_add(CLOSE_TIMEOUT).unwrap_or(Instant::MAX));
                }
            },
            Signal::Credits { bearer, credits } => {
                if let Some(entry) = self.bearers.get_mut(bearer.index()) {
                    entry.rx_credits = entry.rx_credits.saturating_add(credits);
                    entry.owed = 0;
                }
            },
            Signal::Released(bearer) => {
                if let Some(entry) = self.bearers.get_mut(bearer.index())
                    && matches!(entry.state, State::Released { ident: _ })
                {
                    *entry = Bearer::IDLE;
                }
            },
            Signal::Response(index) => {
                let Some(entry) = self.pending.get_mut(usize::from(index.0)) else { return };
                for bearer in &mut self.bearers {
                    if matches!(bearer.state, State::Answer { ident, pos: _ } if ident == entry.ident) {
                        bearer.state = State::Open;
                    }
                }
                *entry = Pending::FREE;
            },
        }
    }
}

impl Default for Ecfc {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// Renders the command with `code`, `identifier` and the data `parts` in
/// order into `out`, and returns its length.
fn render_command(out: &mut [u8], code: u8, identifier: u8, parts: &[&[u8]]) -> usize {
    let len = parts.iter().map(|part| part.len()).fold(0_usize, usize::saturating_add);
    let [len0, len1] = len.saturating_cast::<u16>().to_le_bytes();
    let Some((header, data)) = out.split_first_chunk_mut::<HEADER_LEN>() else { return 0 };
    *header = [code, identifier, len0, len1];
    HEADER_LEN.saturating_add(concat_into(data, parts))
}

#[cfg(test)] mod tests;
