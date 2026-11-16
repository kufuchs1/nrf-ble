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

extern crate std;

use super::*;
use std::{collections::VecDeque, vec, vec::Vec};

/// The MTU of Linux's channels: `BlueZ`'s `[GATT] MTU`, 517 by default.
pub(super) const KERNEL_MTU: u16 = 517;
/// The MPS of Linux's channels on a link of the default data length.
pub(super) const KERNEL_MPS: u16 = 247;
/// The credits Linux grants a channel at a time: its MTU over its MPS, plus 1.
pub(super) const KERNEL_CREDITS: u16 = KERNEL_MTU / KERNEL_MPS + 1;
/// The time each step of the simulation takes, in ms.
const STEP: u64 = 10;

/// A bearer of the central.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum On {
    /// The fixed channel, CID 4.
    Fixed,
    /// The credit based channel with this CID of the kernel.
    Chan(u16),
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
    pub(super) dcid:       u16,
    /// `FLAG_DEFER_SETUP`.
    defer:                 bool,
    /// The identifier of its request, 0 for none.
    ident:                 u8,
    /// The ATT request of `BlueZ` that waits for its response.
    pending:               Option<Vec<u8>>,
    /// Our MPS.
    remote_mps:            u16,
    /// The credits it granted us, left.
    pub(super) rx_credits: u16,
    /// The kernel's CID.
    pub(super) scid:       u16,
    /// The SDU of ours being received, and its length.
    sdu:                   Option<(usize, Vec<u8>)>,
    /// `FLAG_ECRED_CONN_REQ_SENT`.
    sent:                  bool,
    /// Its state.
    pub(super) state:      ChanState,
    /// The credits we granted it, left.
    pub(super) tx_credits: u16,
}

/// The central: Linux's L2CAP and `BlueZ`'s ATT client.
#[derive(Debug, Default)]
pub(super) struct Kernel {
    /// The bearers `BlueZ` attached, in the order they opened.
    attached: Vec<u16>,
    /// `chan_l`.
    pub(super) chans: Vec<Chan>,
    /// The channels deleted.
    pub(super) deleted: usize,
    /// The PDUs of ours dropped for a channel being closed.
    pub(super) dropped: usize,
    /// Whether the link is encrypted: `MEDIUM`, else `LOW`.
    pub(super) encrypted: bool,
    /// Whether a refusal for security asked for the encryption.
    pub(super) escalated: bool,
    /// The credits each new channel grants us.
    pub(super) credits: u16,
    /// Whether the kernel keeps the credits we used, as one whose socket
    /// buffer is full.
    pub(super) hold_credits: bool,
    /// The last identifier given.
    ident: u8,
    /// Whether the kernel leaves our Disconnection Requests unanswered.
    pub(super) ignore_close: bool,
    /// The kernel's MPS for its next channels.
    pub(super) mps: u16,
    /// The notifications received, with their bearer.
    pub(super) notifications: Vec<(On, Vec<u8>)>,
    /// The PDUs for us: CID and payload.
    pub(super) out: VecDeque<(u16, Vec<u8>)>,
    /// The ATT request of `BlueZ` on the fixed channel that waits.
    pending: Option<Vec<u8>>,
    /// `BlueZ`'s queue of ATT requests.
    queue: VecDeque<Vec<u8>>,
    /// The source CIDs of each request sent, by identifier.
    requests: Vec<(u8, Vec<u16>)>,
    /// The ATT responses received: bearer, request and response.
    pub(super) responses: Vec<(On, Vec<u8>, Vec<u8>)>,
    /// Our L2CAP PDU being received.
    rx: Vec<u8>,
    /// Our signalling commands received.
    pub(super) signals: Vec<Vec<u8>>,
    /// Whether it is a spec-correct central rather than Linux.
    spec: bool,
}

impl Kernel {
    /// Linux.
    pub(super) fn linux() -> Self { Self { credits: KERNEL_CREDITS, mps: KERNEL_MPS, ..Self::default() } }

    /// A spec-correct central.
    pub(super) fn spec() -> Self { Self { spec: true, ..Self::linux() } }

    /// The bearers open, newest first: `BlueZ`'s order of choice.
    pub(super) fn bearers(&self) -> Vec<u16> { self.attached.iter().rev().copied().collect() }

    /// `BlueZ` connects with `Channels` = `channels`: one socket for each
    /// channel beyond the fixed one, each but the last deferred.
    pub(super) fn connect_eatt(&mut self, channels: usize) {
        let count = channels.saturating_sub(1);
        let first = self.chans.len();
        for index in 0..count {
            let scid = (0x0040..).find(|cid| !self.chans.iter().any(|chan| chan.scid == *cid)).unwrap();
            self.chans.push(Chan {
                dcid: 0,
                defer: index + 1 < count,
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
            if self.spec {
                self.spec_connect(first);
            } else {
                self.ecred_connect(first + count - 1);
            }
        }
    }

    /// Deletes the channel at `index` (`l2cap_chan_del`).
    fn delete(&mut self, index: usize) {
        let chan = self.chans.remove(index);
        self.attached.retain(|&scid| scid != chan.scid);
        self.deleted += 1;
    }

    /// `l2cap_ecred_connect` for the channel at `index`.
    fn ecred_connect(&mut self, index: usize) {
        if self.chans[index].defer || self.chans[index].sent {
            return;
        }
        self.ident = self.ident.checked_add(1).unwrap_or(1);
        let ident = self.ident;
        self.chans[index].sent = true;
        self.chans[index].ident = ident;
        self.chans[index].rx_credits = self.credits;
        let mut scids = vec![self.chans[index].scid];
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
        while index < self.chans.len() {
            if self.chans[index].state == ChanState::Connect {
                if self.spec {
                    if !self.chans[index].sent {
                        self.spec_connect(index);
                    }
                } else {
                    self.ecred_connect(index);
                }
            }
            index += 1;
        }
    }

    /// Closes the channel `scid` with a Disconnection Request; returns its
    /// identifier.
    pub(super) fn close(&mut self, scid: u16) -> u8 {
        let chan = self.chan_mut(scid).unwrap();
        chan.state = ChanState::Disconn;
        let data = [chan.dcid.to_le_bytes(), scid.to_le_bytes()].concat();
        self.attached.retain(|&attached| attached != scid);
        self.send_signal(0x06, &data)
    }

    /// Grants us `credits` more on the channel `scid`.
    pub(super) fn give_credits(&mut self, scid: u16, credits: u16) {
        let chan = self.chan_mut(scid).unwrap();
        chan.rx_credits += credits;
        self.send_signal(0x16, &[scid.to_le_bytes(), credits.to_le_bytes()].concat());
    }

    /// Whether no channel waits for an answer, which Linux would wait 40 s
    /// for.
    pub(super) fn settled(&self) -> bool { self.chans.iter().all(|chan| chan.state == ChanState::Connected) }

    /// Takes the ATT PDU `pdu` of ours on bearer `on`.
    fn att_in(&mut self, on: On, pdu: Vec<u8>) {
        match pdu[0] {
            0x1B | 0x1D | 0x23 => self.notifications.push((on, pdu)),
            _ => {
                let pending = match on {
                    On::Fixed => self.pending.take(),
                    On::Chan(scid) => self.chan_mut(scid).and_then(|chan| chan.pending.take()),
                };
                let Some(request) = pending else {
                    panic!(
                        "BlueZ: an ATT response {pdu:02X?} on {on:?}, where no request waits: the bearer is shut down"
                    );
                };
                self.responses.push((on, request, pdu));
            },
        }
    }

    /// The channel with the kernel's CID `scid`.
    fn chan_mut(&mut self, scid: u16) -> Option<&mut Chan> { self.chans.iter_mut().find(|chan| chan.scid == scid) }

    /// Takes our Credit Based Connection Response with `ident` and `data`,
    /// as `l2cap_ecred_conn_rsp` does, and checks each binding.
    fn connection_response(&mut self, ident: u8, data: &[u8]) {
        let field = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]);
        let (mtu, mps, credits, result) = (field(0), field(2), field(4), field(6));
        assert!(mtu >= 64 && mps >= 64, "a response with MTU {mtu} and MPS {mps}");
        let dcids: Vec<u16> = data[8..].chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        let position = self.requests.iter().position(|(sent, _)| *sent == ident);
        let Some(position) = position else { panic!("a response with identifier {ident} to no request") };
        let (_, scids) = self.requests.remove(position);
        assert_eq!(dcids.len(), scids.len(), "one destination CID for each source CID");
        let encrypted = self.encrypted;
        let mut next = 0;
        let mut index = 0;
        while index < self.chans.len() {
            let chan = &self.chans[index];
            let in_request = if self.spec { scids.contains(&chan.scid) } else { chan.ident == ident };
            if !in_request || chan.state == ChanState::Connected {
                index += 1;
                continue;
            }
            // The position the walk takes, or the spec's: the source CID's.
            let at = if self.spec { scids.iter().position(|&scid| scid == chan.scid).unwrap() } else { next };
            next += 1;
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
                    let chan = &mut self.chans[index];
                    chan.sent = false;
                    index += 1;
                },
                0x0002 => self.delete(index),
                _ if dcid == 0 => self.delete(index),
                _ => {
                    assert_eq!(
                        chan.scid, scids[at],
                        "Linux binds destination CID {dcid:#06x} to the channel of source CID {:#06x}, the response gave \
                         it to source CID {:#06x}: crossed",
                        chan.scid, scids[at]
                    );
                    let chan = &mut self.chans[index];
                    chan.ident = 0;
                    chan.dcid = dcid;
                    chan.remote_mps = mps;
                    chan.tx_credits = credits;
                    chan.state = ChanState::Connected;
                    let scid = chan.scid;
                    self.attached.push(scid);
                    index += 1;
                },
            }
        }
    }

    /// Takes our L2CAP PDU on `cid`.
    fn pdu_in(&mut self, cid: u16, payload: Vec<u8>) {
        match cid {
            4 => self.att_in(On::Fixed, payload),
            5 => self.signal_in(&payload),
            6 => {},
            _ => {
                if self.chan_mut(cid).is_some_and(|chan| chan.state == ChanState::Disconn) {
                    self.dropped += 1;
                    return;
                }
                let (hold_credits, credits) = (self.hold_credits, self.credits);
                let Some(chan) = self.chan_mut(cid).filter(|chan| chan.state == ChanState::Connected) else {
                    panic!("a PDU to CID {cid:#06x}, which the kernel has no channel for");
                };
                assert!(chan.rx_credits > 0, "a K-frame without a credit");
                assert!(payload.len() <= usize::from(KERNEL_MPS), "a K-frame longer than the kernel's MPS");
                chan.rx_credits -= 1;
                let (len, data) = match chan.sdu.take() {
                    None => (usize::from(u16::from_le_bytes([payload[0], payload[1]])), payload[2..].to_vec()),
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
        let len = usize::from(u16::from_le_bytes([self.rx[0], self.rx[1]]));
        assert!(self.rx.len() <= 4 + len);
        if self.rx.len() == 4 + len {
            let cid = u16::from_le_bytes([self.rx[2], self.rx[3]]);
            let payload = self.rx[4..].to_vec();
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
                let chan = self.chan_mut(scid).unwrap();
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
                .or(self.pending.is_none().then_some(On::Fixed));
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
        self.out.push_back((5, [&[0x17, ident, data.len() as u8, 0][..], &data].concat()));
    }

    /// Sends the SDU `sdu` on the channel `scid`, in K-frames of our MPS.
    pub(super) fn send_sdu(&mut self, scid: u16, sdu: &[u8]) {
        let chan = self.chan_mut(scid).unwrap();
        let (dcid, mps) = (chan.dcid, usize::from(chan.remote_mps));
        let mut kframes = Vec::new();
        let mut rest = sdu;
        let mut first = true;
        while first || !rest.is_empty() {
            let room = if first { mps - 2 } else { mps };
            let (part, after) = rest.split_at(rest.len().min(room));
            let mut kframe = Vec::new();
            if first {
                kframe.extend_from_slice(&(sdu.len() as u16).to_le_bytes());
            }
            kframe.extend_from_slice(part);
            kframes.push(kframe);
            rest = after;
            first = false;
        }
        let chan = self.chan_mut(scid).unwrap();
        assert!(usize::from(chan.tx_credits) >= kframes.len(), "Linux waits for credits on {scid:#06x}");
        chan.tx_credits -= kframes.len() as u16;
        for kframe in kframes {
            self.out.push_back((dcid, kframe));
        }
    }

    /// Sends the signalling command `code` with `data`, with a new
    /// identifier.
    pub(super) fn send_signal(&mut self, code: u8, data: &[u8]) -> u8 {
        self.ident = self.ident.checked_add(1).unwrap_or(1);
        let ident = self.ident;
        self.out.push_back((5, [&[code, ident, data.len() as u8, 0][..], data].concat()));
        ident
    }

    /// Takes our signalling command `pdu`.
    fn signal_in(&mut self, pdu: &[u8]) {
        self.signals.push(pdu.to_vec());
        let (code, ident, data) = (pdu[0], pdu[1], &pdu[4..]);
        let field = |at: usize| u16::from_le_bytes([data[at], data[at + 1]]);
        match code {
            0x18 => self.connection_response(ident, data),
            0x16 => {
                let (cid, credits) = (field(0), field(2));
                let chan = self.chans.iter_mut().find(|chan| chan.dcid == cid && chan.state == ChanState::Connected);
                let chan = chan.unwrap_or_else(|| panic!("credits for CID {cid:#06x}, which no channel has"));
                chan.tx_credits = chan.tx_credits.checked_add(credits).expect("credits above 65535");
            },
            0x06 => {
                // Our Disconnection Request: its DCID is the kernel's CID.
                let (dcid, scid) = (field(0), field(2));
                if let Some(index) = self.chans.iter().position(|chan| chan.scid == dcid && chan.dcid == scid) {
                    self.delete(index);
                    // A kernel that lost the channel does not answer.
                    if !self.ignore_close {
                        self.out.push_back((
                            5,
                            [&[0x07, ident, 4, 0][..], &dcid.to_le_bytes(), &scid.to_le_bytes()].concat(),
                        ));
                    }
                }
            },
            0x07 => {
                let (dcid, scid) = (field(0), field(2));
                let index = self.chans.iter().position(|chan| chan.dcid == dcid && chan.scid == scid);
                let index = index.filter(|&index| self.chans[index].state == ChanState::Disconn);
                self.delete(index.unwrap_or_else(|| panic!("a Disconnection Response for {dcid:#06x}, {scid:#06x}")));
            },
            0x12 => self.out.push_back((5, vec![0x13, ident, 2, 0, 0, 0])),
            _ => {},
        }
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
    pub(super) device: Device,
    /// The engine.
    pub(super) engine: Engine,
    /// The link's epoch.
    pub(super) epoch:  Epoch,
    /// The central.
    pub(super) kernel: Kernel,
    /// The time, in ms.
    pub(super) now:    u64,
}

impl Sim {
    /// A reconnection of the central of `bond`, not yet encrypted, with
    /// `kernel`.
    pub(super) fn reconnection(bond: Bond, kernel: Kernel) -> Self {
        Self::reconnect(Engine::new(&example::DB, example::CONFIG), bond, kernel)
    }

    /// A reconnection of the central of `bond` to `engine`, not yet
    /// encrypted, with `kernel`.
    pub(super) fn reconnect(mut engine: Engine, bond: Bond, kernel: Kernel) -> Self {
        engine.advertise(false, &identity(), Some(bond), Duration::from_secs(20));
        engine.connected(&info(Peer::new([3; 6], true), Some(Peer::new(CENTRAL_IDENTITY, false))), at(0));
        let epoch = engine.epoch().unwrap();
        assert_eq!(engine.take_command(0, at(0)), Some(Command::HoldLatency(true)));
        Self { device: Device(9), engine, epoch, kernel, now: 0 }
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

    /// The time now.
    pub(super) fn at(&self) -> Instant { at(self.now) }

    /// Lets `millis` ms pass, step by step, with the engine's deadlines.
    pub(super) fn advance(&mut self, millis: u64) {
        let end = self.now + millis;
        while self.now < end {
            self.now = (self.now + STEP).min(end);
            self.pump();
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

    /// Delivers the central's PDUs to the engine.
    pub(super) fn deliver(&mut self) {
        let now = self.at();
        while let Some((cid, payload)) = self.kernel.out.pop_front() {
            receive_as(&mut self.engine, &mut self.device, cid, &payload, self.kernel.encrypted, now);
        }
    }

    /// Delivers the central's PDUs and the engine's fragments both ways,
    /// with the engine's deadlines, until neither has more.
    pub(super) fn pump(&mut self) {
        let now = self.at();
        for _ in 0..10_000 {
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
                return;
            }
        }
        panic!("the link never settles");
    }

    /// The bearers the central has open, with our CID of each.
    pub(super) fn bound(&self) -> Vec<(u16, u16)> {
        self.kernel
            .chans
            .iter()
            .filter(|chan| chan.state == ChanState::Connected)
            .map(|chan| (chan.scid, chan.dcid))
            .collect()
    }

    /// Our Credit Based Connection Responses so far: identifier, result and
    /// destination CIDs.
    pub(super) fn responses(&self) -> Vec<(u8, u16, Vec<u16>)> {
        self.kernel
            .signals
            .iter()
            .filter(|signal| signal[0] == 0x18)
            .map(|signal| {
                let dcids = signal[12..].chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
                (signal[1], u16::from_le_bytes([signal[10], signal[11]]), dcids)
            })
            .collect()
    }
}
