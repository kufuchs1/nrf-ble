//! A simulated central for the enhanced bearers: `BlueZ` 5.88's ATT client
//! over Linux 7.3's L2CAP, as `scratchpad/eatt/design-v2.md` 1.1 reads them,
//! driving the engine through its fragments.
//!
//! The kernel part models what decides how the bearers open:
//!
//! - `BlueZ` opens `Channels` − 1 sockets in one loop, each but the last with
//!   `DEFER_SETUP`; each takes the lowest free dynamic CID and goes to the tail
//!   of `chan_l` (`l2cap_alloc_cid`, `__l2cap_chan_add`).
//! - The last socket's `l2cap_ecred_connect` sends one request, its own CID
//!   first and then the deferred channels in `chan_l` order
//!   (`l2cap_ecred_defer_connect`).
//! - The response walk (`l2cap_ecred_conn_rsp`) goes through `chan_l` from the
//!   head and gives each channel with the request's identifier the next
//!   destination CID: the cross-wiring. Every binding is checked against the
//!   source CID the response gave that destination CID to, and the test fails
//!   on a crossed one, as on a destination CID already in use.
//! - A refusal for security (0x0005, 0x0008) escalates the security; on the
//!   encryption (`l2cap_security_cfm`) every channel sends a request of its
//!   own, all before our first answer. It fails the test if it arrives on an
//!   encrypted link: Linux would ask for a pairing with protection against a
//!   man in the middle, which Just Works cannot give.
//! - Credits: 3 for each channel (its MTU 517 over its MPS 247, plus 1),
//!   returned when used up; K-frames to us are cut by our MPS.
//!
//! The `BlueZ` part sends the queued ATT requests on whichever bearer is free,
//! the enhanced ones first, the newest first (`bt_att_attach_fd` puts each at
//! the head of its list), the fixed channel last, and fails the test on a
//! response that arrives on a bearer without a request waiting, which
//! `BlueZ` answers by shutting the bearer down.
//!
//! A `spec` central instead names its source CIDs in ascending order and binds
//! each destination CID to the source CID in the same position, as Zephyr and
//! Android do.

extern crate alloc;

use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};

/// The MTU of Linux's channels: `BlueZ`'s `[GATT] MTU`, 517 by default.
pub(super) const KERNEL_MTU: u16 = 517;
/// The MPS of Linux's channels on a link of the default data length.
pub(super) const KERNEL_MPS: u16 = 247;
/// The credits Linux grants a channel at a time: its MTU over its MPS, plus 1.
pub(super) const KERNEL_CREDITS: u16 = KERNEL_MTU.strict_div(KERNEL_MPS) + 1;
/// The time each step of the simulation takes, in ms.
const STEP: u64 = 10;

/// A bearer of the central.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum On {
    /// The credit based channel with this CID of the kernel.
    Chan(u16),
    /// The fixed channel, CID 4.
    Fixed,
}

/// The state of a kernel channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChanState {
    /// `BT_CONNECT`: its request is to be sent, or waits for the answer.
    Connect,
    /// `BT_CONNECTED`.
    Connected,
    /// `BT_DISCONN`: its Disconnection Request waits for the answer.
    Disconn,
}

/// One channel of `chan_l`.
#[derive(Clone, Debug)]
pub(super) struct Chan {
    /// Our CID, once bound.
    pub dcid:       u16,
    /// `FLAG_DEFER_SETUP`.
    pub defer:      bool,
    /// The identifier of its request, 0 for none.
    pub ident:      u8,
    /// The ATT request of `BlueZ` that waits for its response.
    pub pending:    Option<Vec<u8>>,
    /// Our MPS.
    pub remote_mps: u16,
    /// The credits it granted us, left.
    pub rx_credits: u16,
    /// The kernel's CID.
    pub scid:       u16,
    /// The SDU of ours being received, and its length.
    pub sdu:        Option<(usize, Vec<u8>)>,
    /// `FLAG_ECRED_CONN_REQ_SENT`.
    pub sent:       bool,
    /// Its state.
    pub state:      ChanState,
    /// The credits we granted it, left.
    pub tx_credits: u16,
}

/// How a [`Kernel`] differs from Linux with free socket buffers.
#[derive(Debug, Default)]
pub(super) struct Behaviour {
    /// Whether the kernel keeps the credits we used, as one whose socket
    /// buffer is full.
    pub hold_credits: bool,
    /// Whether the kernel leaves our Disconnection Requests unanswered.
    pub ignore_close: bool,
    /// Whether it is a spec-correct central rather than Linux.
    pub spec:         bool,
}

/// The central: Linux's L2CAP and `BlueZ`'s ATT client.
#[derive(Debug, Default)]
pub(super) struct Kernel {
    /// The bearers `BlueZ` attached, in the order they opened.
    pub attached:      Vec<u16>,
    /// How it differs from Linux with free socket buffers.
    pub behaviour:     Behaviour,
    /// `chan_l`.
    pub chans:         Vec<Chan>,
    /// The credits each new channel grants us.
    pub credits:       u16,
    /// The channels deleted.
    pub deleted:       usize,
    /// The PDUs of ours dropped for a channel being closed.
    pub dropped:       usize,
    /// Whether the link is encrypted: `MEDIUM`, else `LOW`.
    pub encrypted:     bool,
    /// Whether a refusal for security asked for the encryption.
    pub escalated:     bool,
    /// The last identifier given.
    pub ident:         u8,
    /// The kernel's MPS for its next channels.
    pub mps:           u16,
    /// The notifications received, with their bearer.
    pub notifications: Vec<(On, Vec<u8>)>,
    /// The PDUs for us: CID and payload.
    pub out:           VecDeque<(u16, Vec<u8>)>,
    /// The ATT request of `BlueZ` on the fixed channel that waits.
    pub pending:       Option<Vec<u8>>,
    /// `BlueZ`'s queue of ATT requests.
    pub queue:         VecDeque<Vec<u8>>,
    /// The source CIDs of each request sent, by identifier.
    pub requests:      Vec<(u8, Vec<u16>)>,
    /// The ATT responses received: bearer, request and response.
    pub responses:     Vec<(On, Vec<u8>, Vec<u8>)>,
    /// Our L2CAP PDU being received.
    pub rx:            Vec<u8>,
    /// Our signalling commands received.
    pub signals:       Vec<Vec<u8>>,
}

impl Kernel {
    /// Takes the ATT PDU `pdu` of ours on bearer `on`.
    fn att_in(&mut self, on: On, pdu: Vec<u8>) {
        match *assert_some!(pdu.first()) {
            0x1B | 0x1D | 0x23 => self.notifications.push((on, pdu)),
            _ => {
                let pending = match on {
                    On::Fixed => self.pending.take(),
                    On::Chan(scid) => self.chan_mut(scid).and_then(|chan| chan.pending.take()),
                };
                let Some(request) = ({
                    let value = pending;
                    assert!(
                        value.is_some(),
                        "BlueZ: an ATT response {pdu:02X?} on {on:?}, where no request waits: the bearer is shut down"
                    );
                    value
                }) else {
                    return;
                };
                self.responses.push((on, request, pdu));
            },
        }
    }

    /// The bearers open, newest first: `BlueZ`'s order of choice.
    pub(super) fn bearers(&self) -> Vec<u16> { self.attached.iter().rev().copied().collect() }

    /// The channel with the kernel's CID `scid`.
    fn chan_mut(&mut self, scid: u16) -> Option<&mut Chan> { self.chans.iter_mut().find(|chan| chan.scid == scid) }

    /// Closes the channel `scid` with a Disconnection Request; returns its
    /// identifier.
    pub(super) fn close(&mut self, scid: u16) -> u8 {
        let open = self.chan_mut(scid);
        assert!(open.is_some(), "the channel {scid:#06X}");
        let Some(chan) = open else { return 0 };
        chan.state = ChanState::Disconn;
        let data = [chan.dcid.to_le_bytes(), scid.to_le_bytes()].concat();
        self.attached.retain(|&attached| attached != scid);
        self.send_signal(0x06, &data)
    }

    /// `BlueZ` connects with `Channels` = `channels`: one socket for each
    /// channel beyond the fixed one, each but the last deferred.
    pub(super) fn connect_eatt(&mut self, channels: usize) {
        let count = channels.saturating_sub(1);
        let first = self.chans.len();
        for index in 0..count {
            let scid = assert_some!((0x0040..=u16::MAX).find(|cid| !self.chans.iter().any(|chan| chan.scid == *cid)));
            self.chans.push(Chan {
                dcid: 0,
                defer: index.strict_add(1) < count,
                ident: 0,
                pending: None,
                remote_mps: 0,
                rx_credits: 0,
                scid,
                sdu: None,
                sent: false,
                state: ChanState::Connect,
                tx_credits: 0,
            });
        }
        if count > 0 {
            if self.behaviour.spec {
                self.spec_connect(first);
            } else {
                self.ecred_connect(first.strict_add(count).strict_sub(1));
            }
        }
    }

    /// Takes our Credit Based Connection Response with `ident` and `data`,
    /// as `l2cap_ecred_conn_rsp` does, and checks each binding.
    fn connection_response(&mut self, ident: u8, data: &[u8]) {
        let field = |at: usize| {
            data.get(at..at.strict_add(2)).and_then(|octets| octets.try_into().ok()).map(u16::from_le_bytes)
        };
        let fields = (field(0), field(2), field(4), field(6));
        let (Some(mtu), Some(mps), Some(credits), Some(result)) = ({
            let value = fields;
            assert!(matches!(value, (Some(_), Some(_), Some(_), Some(_))), "a response of 8 octets or more");
            value
        }) else {
            return;
        };
        assert!(mtu >= 64 && mps >= 64, "a response with MTU {mtu} and MPS {mps}");
        let (pairs, odd) = data.get(8..).unwrap_or_default().as_chunks::<2>();
        assert!(odd.is_empty(), "destination CIDs of two octets");
        let dcids: Vec<u16> = pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect();
        let found = self.requests.iter().position(|request| request.0 == ident);
        let Some(position) = ({
            let value = found;
            assert!(value.is_some(), "a response with identifier {ident} to no request");
            value
        }) else {
            return;
        };
        let (_, scids) = self.requests.remove(position);
        assert_eq!(dcids.len(), scids.len(), "one destination CID for each source CID");
        let encrypted = self.encrypted;
        let mut next = 0;
        let mut index = 0;
        while index < self.chans.len() {
            let chan = assert_some!(self.chans.get(index));
            let in_request = if self.behaviour.spec { scids.contains(&chan.scid) } else { chan.ident == ident };
            if !in_request || chan.state == ChanState::Connected {
                index = index.strict_add(1);
                continue;
            }
            // The position the walk takes, or the spec's: the source CID's.
            let at =
                if self.behaviour.spec { assert_some!(scids.iter().position(|&scid| scid == chan.scid)) } else { next };
            next = next.strict_add(1);
            let Some(&dcid) = dcids.get(at) else {
                self.delete(index);
                continue;
            };
            assert!(
                dcid == 0 || !self.chans.iter().any(|other| other.dcid == dcid),
                "destination CID {dcid:#06x} already in use: Linux discards both channels"
            );
            match result {
                0x0005 | 0x0008 => {
                    assert!(
                        !encrypted,
                        "a refusal for security on an encrypted link: Linux escalates to a MITM pairing"
                    );
                    self.escalated = true;
                    assert_some!(self.chans.get_mut(index)).sent = false;
                    index = index.strict_add(1);
                },
                0x0002 => self.delete(index),
                _ if dcid == 0 => self.delete(index),
                _ => {
                    let named = *assert_some!(scids.get(at));
                    assert_eq!(
                        chan.scid, named,
                        "Linux binds destination CID {dcid:#06x} to the channel of source CID {:#06x}, the response gave \
                         it to source CID {named:#06x}: crossed",
                        chan.scid
                    );
                    let bound = assert_some!(self.chans.get_mut(index));
                    bound.ident = 0;
                    bound.dcid = dcid;
                    bound.remote_mps = mps;
                    bound.tx_credits = credits;
                    bound.state = ChanState::Connected;
                    let scid = bound.scid;
                    self.attached.push(scid);
                    index = index.strict_add(1);
                },
            }
        }
    }

    /// Deletes the channel at `index` (`l2cap_chan_del`).
    fn delete(&mut self, index: usize) {
        let chan = self.chans.remove(index);
        self.attached.retain(|&scid| scid != chan.scid);
        self.deleted = self.deleted.strict_add(1);
    }

    /// `l2cap_ecred_connect` for the channel at `index`.
    fn ecred_connect(&mut self, index: usize) {
        let credits = self.credits;
        let chosen = assert_some!(self.chans.get_mut(index));
        if chosen.defer || chosen.sent {
            return;
        }
        let ident = self.ident.checked_add(1).unwrap_or(1);
        chosen.sent = true;
        chosen.ident = ident;
        chosen.rx_credits = credits;
        let mut scids = vec![chosen.scid];
        self.ident = ident;
        // `l2cap_ecred_defer_connect`, in `chan_l` order.
        for (other, chan) in self.chans.iter_mut().enumerate() {
            if other == index || !chan.defer || chan.ident != 0 || chan.state != ChanState::Connect {
                continue;
            }
            chan.defer = false;
            if chan.sent {
                continue;
            }
            chan.sent = true;
            chan.ident = ident;
            chan.rx_credits = self.credits;
            scids.push(chan.scid);
        }
        self.send_request(ident, &scids);
    }

    /// The link is encrypted: `l2cap_security_cfm`, which lets every channel
    /// still to connect send its own request.
    pub(super) fn encrypted(&mut self) {
        self.encrypted = true;
        self.escalated = false;
        let mut index = 0;
        while let Some((state, sent)) = self.chans.get(index).map(|chan| (chan.state, chan.sent)) {
            if state == ChanState::Connect {
                if self.behaviour.spec {
                    if !sent {
                        self.spec_connect(index);
                    }
                } else {
                    self.ecred_connect(index);
                }
            }
            index = index.strict_add(1);
        }
    }

    /// Grants us `credits` more on the channel `scid`.
    pub(super) fn give_credits(&mut self, scid: u16, credits: u16) {
        let chan = assert_some!(self.chan_mut(scid));
        chan.rx_credits = chan.rx_credits.strict_add(credits);
        self.send_signal(0x16, &[scid.to_le_bytes(), credits.to_le_bytes()].concat());
    }

    /// Linux.
    pub(super) fn linux() -> Self { Self { credits: KERNEL_CREDITS, mps: KERNEL_MPS, ..Self::default() } }

    /// Takes our L2CAP PDU on `cid`.
    fn pdu_in(&mut self, cid: u16, payload: Vec<u8>) {
        match cid {
            4 => self.att_in(On::Fixed, payload),
            5 => self.signal_in(&payload),
            6 => {},
            _ => {
                if self.chan_mut(cid).is_some_and(|chan| chan.state == ChanState::Disconn) {
                    self.dropped = self.dropped.strict_add(1);
                    return;
                }
                let (hold_credits, credits) = (self.behaviour.hold_credits, self.credits);
                let Some(chan) = ({
                    let value = self.chan_mut(cid).filter(|chan| chan.state == ChanState::Connected);
                    assert!(value.is_some(), "a PDU to CID {cid:#06x}, which the kernel has no channel for");
                    value
                }) else {
                    return;
                };
                assert!(chan.rx_credits > 0, "a K-frame without a credit");
                assert!(payload.len() <= usize::from(KERNEL_MPS), "a K-frame longer than the kernel's MPS");
                chan.rx_credits = chan.rx_credits.strict_sub(1);
                let (len, data) = match chan.sdu.take() {
                    None => {
                        let (&len_octets, data) = assert_some!(payload.split_first_chunk::<2>(), "an SDU length");
                        (usize::from(u16::from_le_bytes(len_octets)), data.to_vec())
                    },
                    Some((len, mut data)) => {
                        data.extend_from_slice(&payload);
                        (len, data)
                    },
                };
                assert!(
                    len <= usize::from(KERNEL_MTU) && data.len() <= len,
                    "an SDU of {len} octets, {} so far",
                    data.len()
                );
                let complete = if data.len() == len {
                    Some(data)
                } else {
                    chan.sdu = Some((len, data));
                    None
                };
                if chan.rx_credits == 0 && !hold_credits {
                    // `l2cap_chan_le_send_credits`.
                    chan.rx_credits = credits;
                    let scid = chan.scid;
                    self.send_signal(0x16, &[&scid.to_le_bytes()[..], &credits.to_le_bytes()].concat());
                }
                if let Some(sdu) = complete {
                    self.att_in(On::Chan(cid), sdu);
                }
            },
        }
    }

    /// Takes one of our fragments.
    pub(super) fn receive(&mut self, fragment: &Fragment) {
        if fragment.start() {
            assert!(self.rx.is_empty(), "a start fragment while a PDU is incomplete: {:02X?}", self.rx);
        } else {
            assert!(!self.rx.is_empty(), "a continuation fragment without a start");
        }
        self.rx.extend_from_slice(fragment.bytes());
        let (&header, rest) = assert_some!(self.rx.split_first_chunk::<4>(), "a basic L2CAP header");
        let [len0, len1, cid0, cid1] = header;
        let len = usize::from(u16::from_le_bytes([len0, len1]));
        assert!(rest.len() <= len);
        if rest.len() == len {
            let cid = u16::from_le_bytes([cid0, cid1]);
            let payload = rest.to_vec();
            self.rx.clear();
            self.pdu_in(cid, payload);
        }
    }

    /// Queues the ATT request `pdu` for the next free bearer.
    pub(super) fn request(&mut self, pdu: &[u8]) { self.queue.push_back(pdu.to_vec()); }

    /// Sends the ATT request `pdu` on `on`, which is free.
    pub(super) fn request_on(&mut self, on: On, pdu: &[u8]) {
        match on {
            On::Fixed => {
                assert!(self.pending.replace(pdu.to_vec()).is_none());
                self.out.push_back((4, pdu.to_vec()));
            },
            On::Chan(scid) => {
                let chan = assert_some!(self.chan_mut(scid));
                assert!(chan.pending.replace(pdu.to_vec()).is_none());
                self.send_sdu(scid, pdu);
            },
        }
    }

    /// Sends the queued requests on the free bearers, `BlueZ`'s way.
    fn send_queued(&mut self) {
        while let Some(pdu) = self.queue.front().cloned() {
            let free = self
                .bearers()
                .into_iter()
                .find(|&scid| self.chans.iter().any(|chan| chan.scid == scid && chan.pending.is_none()))
                .map(On::Chan)
                .or_else(|| self.pending.is_none().then_some(On::Fixed));
            let Some(on) = free else { return };
            self.queue.pop_front();
            self.request_on(on, &pdu);
        }
    }

    /// Sends a request with `ident` for `scids`.
    pub(super) fn send_request(&mut self, ident: u8, scids: &[u16]) {
        let mut data = vec![0x27, 0x00];
        data.extend_from_slice(&KERNEL_MTU.to_le_bytes());
        data.extend_from_slice(&self.mps.to_le_bytes());
        data.extend_from_slice(&self.credits.to_le_bytes());
        for scid in scids {
            data.extend_from_slice(&scid.to_le_bytes());
        }
        self.requests.push((ident, scids.to_vec()));
        self.out.push_back((5, [&[0x17, ident, data.len().truncate::<u8>(), 0][..], &data].concat()));
    }

    /// Sends the SDU `sdu` on the channel `scid`, in K-frames of our MPS.
    pub(super) fn send_sdu(&mut self, scid: u16, sdu: &[u8]) {
        let chan = assert_some!(self.chan_mut(scid));
        let (dcid, mps) = (chan.dcid, usize::from(chan.remote_mps));
        let mut kframes = Vec::new();
        let mut rest = sdu;
        let mut first = true;
        while first || !rest.is_empty() {
            let room = if first { mps.strict_sub(2) } else { mps };
            let (part, after) = rest.split_at(rest.len().min(room));
            let mut kframe = Vec::new();
            if first {
                kframe.extend_from_slice(&sdu.len().truncate::<u16>().to_le_bytes());
            }
            kframe.extend_from_slice(part);
            kframes.push(kframe);
            rest = after;
            first = false;
        }
        let sender = assert_some!(self.chan_mut(scid));
        assert!(usize::from(sender.tx_credits) >= kframes.len(), "Linux waits for credits on {scid:#06x}");
        sender.tx_credits = sender.tx_credits.strict_sub(kframes.len().truncate::<u16>());
        for kframe in kframes {
            self.out.push_back((dcid, kframe));
        }
    }

    /// Sends the signalling command `code` with `data`, with a new
    /// identifier.
    pub(super) fn send_signal(&mut self, code: u8, data: &[u8]) -> u8 {
        self.ident = self.ident.checked_add(1).unwrap_or(1);
        let ident = self.ident;
        self.out.push_back((5, [&[code, ident, data.len().truncate::<u8>(), 0][..], data].concat()));
        ident
    }

    /// Whether no channel waits for an answer, which Linux would wait 40 s
    /// for.
    pub(super) fn settled(&self) -> bool { self.chans.iter().all(|chan| chan.state == ChanState::Connected) }

    /// Takes our signalling command `pdu`.
    fn signal_in(&mut self, pdu: &[u8]) {
        self.signals.push(pdu.to_vec());
        let (&[code, ident, _, _], data) = assert_some!(pdu.split_first_chunk::<4>(), "a signalling header");
        let field = |at: usize| {
            let octets = data.get(at..at.strict_add(2)).and_then(|pair| <[u8; 2]>::try_from(pair).ok());
            assert!(octets.is_some(), "a field at {at} of {data:02X?}");
            octets.map_or(0, u16::from_le_bytes)
        };
        match code {
            0x18 => self.connection_response(ident, data),
            0x16 => {
                let (cid, credits) = (field(0), field(2));
                let chan = assert_some!(
                    self.chans.iter_mut().find(|chan| chan.dcid == cid && chan.state == ChanState::Connected),
                    "credits for CID {cid:#06x}, which no channel has"
                );
                chan.tx_credits = assert_some!(chan.tx_credits.checked_add(credits), "credits above 65535");
            },
            0x06 => {
                // Our Disconnection Request: its DCID is the kernel's CID.
                let (dcid, scid) = (field(0), field(2));
                if let Some(index) = self.chans.iter().position(|chan| chan.scid == dcid && chan.dcid == scid) {
                    self.delete(index);
                    // A kernel that lost the channel does not answer.
                    if !self.behaviour.ignore_close {
                        self.out.push_back((
                            5,
                            [&[0x07, ident, 4, 0][..], &dcid.to_le_bytes(), &scid.to_le_bytes()].concat(),
                        ));
                    }
                }
            },
            0x07 => {
                let (dcid, scid) = (field(0), field(2));
                let index = assert_some!(
                    self.chans
                        .iter()
                        .position(|chan| chan.dcid == dcid && chan.scid == scid && chan.state == ChanState::Disconn),
                    "a Disconnection Response for {dcid:#06x}, {scid:#06x}"
                );
                self.delete(index);
            },
            0x12 => self.out.push_back((5, vec![0x13, ident, 2, 0, 0, 0])),
            _ => {},
        }
    }

    /// A spec-correct central.
    pub(super) fn spec() -> Self {
        Self { behaviour: Behaviour { spec: true, ..Behaviour::default() }, ..Self::linux() }
    }

    /// The spec's connection request for the channel at `index` and every
    /// other one still to connect, in ascending order.
    fn spec_connect(&mut self, index: usize) {
        self.ident = self.ident.checked_add(1).unwrap_or(1);
        let ident = self.ident;
        let mut scids = Vec::new();
        for (other, chan) in self.chans.iter_mut().enumerate() {
            if chan.state == ChanState::Connect && !chan.sent && (other == index || chan.defer || other > index) {
                chan.sent = true;
                chan.defer = false;
                chan.ident = ident;
                chan.rx_credits = self.credits;
                scids.push(chan.scid);
            }
        }
        scids.sort_unstable();
        self.send_request(ident, &scids);
    }
}

/// The engine and the central on one link, at a time of their own.
pub(super) struct Sim {
    /// The crypto of the engine.
    pub device: Device,
    /// The engine.
    pub engine: Engine,
    /// The link's epoch.
    pub epoch:  Epoch,
    /// The central.
    pub kernel: Kernel,
    /// The time, in ms.
    pub now:    u64,
}

impl Sim {
    /// Lets `millis` ms pass, step by step, with the engine's deadlines.
    pub(super) fn advance(&mut self, millis: u64) {
        let end = self.now.strict_add(millis);
        while self.now < end {
            self.now = self.now.strict_add(STEP).min(end);
            self.pump();
        }
    }

    /// The time now.
    pub(super) fn at(&self) -> Instant { at(self.now) }

    /// The bearers the central has open, with our CID of each.
    pub(super) fn bound(&self) -> Vec<(u16, u16)> {
        self.kernel
            .chans
            .iter()
            .filter(|chan| chan.state == ChanState::Connected)
            .map(|chan| (chan.scid, chan.dcid))
            .collect()
    }

    /// Delivers the central's PDUs to the engine.
    pub(super) fn deliver(&mut self) {
        let now = self.at();
        while let Some((cid, payload)) = self.kernel.out.pop_front() {
            receive_as(&mut self.engine, &mut self.device, cid, &payload, self.kernel.encrypted, now);
        }
    }

    /// The link layer's encryption with the bond's key, which the central
    /// starts: its key request, our reply, and the encryption.
    pub(super) fn encrypt(&mut self) {
        let now = self.at();
        self.engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, now);
        assert!(matches!(
            self.engine.take_command(0, now),
            Some(Command::LtkReply { epoch: _, key: Some([0x77, ..]) })
        ));
        self.engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, now);
        self.kernel.encrypted();
        self.pump();
    }

    /// A first connection of `kernel`, paired with Just Works and encrypted,
    /// our identity keys sent.
    pub(super) fn paired(kernel: Kernel) -> Self {
        let mut engine = Engine::new(&example::DB, example::CONFIG);
        let mut device = Device(9);
        let (epoch, _) = pair(&mut engine, &mut device, &identity(), Peer::new(CENTRAL_ADDRESS, false), false);
        let mut sim = Self { device, engine, epoch, kernel, now: 0 };
        sim.kernel.encrypted = true;
        sim.pump();
        sim
    }

    /// Delivers the central's PDUs and the engine's fragments both ways,
    /// with the engine's deadlines, until neither has more.
    pub(super) fn pump(&mut self) {
        let now = self.at();
        let mut settled = false;
        for _ in 0_i32..10_000_i32 {
            if self.engine.next_deadline().is_some_and(|deadline| deadline <= now) {
                self.engine.on_time(now);
            }
            self.kernel.send_queued();
            let delivered = !self.kernel.out.is_empty();
            self.deliver();
            let fragments = drain(&mut self.engine, 4, now);
            // The central acknowledges every fragment.
            while self.engine.take_command(0, now).is_some() {}
            for fragment in &fragments {
                self.kernel.receive(fragment);
            }
            if !delivered && fragments.is_empty() && self.kernel.out.is_empty() {
                settled = true;
                break;
            }
        }
        assert!(settled, "the link never settles");
    }

    /// A reconnection of the central of `bond` to `engine`, not yet
    /// encrypted, with `kernel`.
    pub(super) fn reconnect(mut engine: Engine, bond: Bond, kernel: Kernel) -> Self {
        engine.advertise(false, &identity(), Some(bond), Duration::from_secs(20));
        engine.connected(&info(Peer::new([3; 6], true), Some(Peer::new(CENTRAL_IDENTITY, false))), at(0));
        let connected = engine.epoch();
        assert!(connected.is_some(), "connected");
        assert_eq!(engine.take_command(0, at(0)), Some(Command::HoldLatency(true)));
        Self { device: Device(9), engine, epoch: connected.unwrap_or(Epoch::for_test(0)), kernel, now: 0 }
    }

    /// A reconnection of the central of `bond`, not yet encrypted, with
    /// `kernel`.
    pub(super) fn reconnection(bond: Bond, kernel: Kernel) -> Self {
        Self::reconnect(Engine::new(&example::DB, example::CONFIG), bond, kernel)
    }

    /// Our Credit Based Connection Responses so far: identifier, result and
    /// destination CIDs.
    pub(super) fn responses(&self) -> Vec<(u8, u16, Vec<u16>)> {
        self.kernel
            .signals
            .iter()
            .filter(|signal| signal.first() == Some(&0x18))
            .map(|signal| {
                let header = signal.get(..12).and_then(|octets| <[u8; 12]>::try_from(octets).ok());
                assert!(header.is_some(), "a response of 12 octets or more: {signal:02X?}");
                let [_, ident, _, _, _, _, _, _, _, _, result0, result1] = header.unwrap_or_default();
                let (pairs, odd) = signal.get(12..).unwrap_or_default().as_chunks::<2>();
                assert!(odd.is_empty(), "destination CIDs of two octets: {signal:02X?}");
                (
                    ident,
                    u16::from_le_bytes([result0, result1]),
                    pairs.iter().map(|&pair| u16::from_le_bytes(pair)).collect(),
                )
            })
            .collect()
    }
}
