//! Tests of the host's async glue and its engine over a stand-in link layer
//! ([`MockLink`]): a first connection with BlueZ's pairing and discovery, a
//! reconnection with the bond's key, the pacing of notifications, the
//! deadlines, the wake-up on room, an advertising call dropped while a
//! central connects, and the order of the events.

extern crate std;

use super::{
    AdvertiseError,
    Aes as _,
    ConnEvent,
    Host,
    NotifyError,
    Port,
    adv::{Call, Control, Mode},
    bond::Bond,
    engine::{Config, Unclaimed},
    example,
    gatt::{AttError, Handler, ValueId},
    identity::{DeviceSecret, LocalIdentity, Variant},
    l2cap::{CID_ATT, CID_SECURITY_MANAGER, CID_SIGNALLING, Channel, Reassembly},
    smp::tests::{CENTRAL_ADDRESS, CENTRAL_IDENTITY, CENTRAL_IRK, Central, Device, linux_request, local_rpa, pdu},
    test_aes::Software,
};
use crate::{
    link::{self, AclIn, ConnectionParams, Epoch, Event, Info, Rx},
    pdu::Peer,
};
use core::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use embassy_time::Instant;
use std::{collections::VecDeque, vec, vec::Vec};

/// A call of the link layer as the stand-in records it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Seen {
    /// [`link::Link::accept_list_add`].
    AcceptListAdd(Peer),
    /// [`link::Link::advertise`]: its interval and filter policy.
    Advertise(u16, u8),
    /// [`link::Link::disconnect`]: the reason.
    Disconnect(u8),
    /// [`link::Link::hold_latency`].
    Hold(bool),
    /// [`link::Link::ltk_reply`].
    Ltk(Option<[u8; 16]>),
    /// Another setup call of advertising.
    Setup,
    /// [`link::Link::stop_advertising`].
    StopAdvertising,
}

impl core::fmt::Debug for Peer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:02X?}/{}", self.address, self.random)
    }
}

/// The link layer and the time, as the host's tasks see them: what the
/// central sends waits in `rx`, what the host queues in `queue` until the
/// test takes it for the air.
struct MockLink {
    /// The calls of the link layer so far.
    calls:     RefCell<Vec<Seen>>,
    /// Places in the link layer's queue.
    capacity:  Cell<usize>,
    /// Whether a link exists.
    connected: Cell<bool>,
    /// The current link.
    epoch:     Cell<u32>,
    /// The link's information.
    info:      Cell<Option<Info>>,
    /// The time in milliseconds.
    now:       Cell<u64>,
    /// The fragments queued and not yet taken for the air.
    queue:     RefCell<VecDeque<(bool, Vec<u8>)>>,
    /// Room returned since [`Port::tx_room_changed`] last returned.
    room:      Cell<bool>,
    /// The events and fragments for the host.
    rx:        RefCell<VecDeque<Rx>>,
    /// The fragments taken for the air and not yet acknowledged.
    unacked:   Cell<usize>,
}

impl MockLink {
    /// Acknowledges every fragment on the air.
    fn ack(&self) {
        self.unacked.set(0);
        self.room.set(true);
    }

    /// The calls so far, forgotten.
    fn calls(&self) -> Vec<Seen> { core::mem::take(&mut *self.calls.borrow_mut()) }

    /// A central connects from `peer`, resolved to `identity`, to our
    /// address `local`.
    fn connect(&self, peer: Peer, identity: Option<Peer>, local: Peer) -> Epoch {
        let epoch = Epoch::for_test(self.epoch.get() + 1);
        self.epoch.set(self.epoch.get() + 1);
        self.connected.set(true);
        self.info.set(Some(Info {
            central_accuracy: 0,
            epoch,
            identity,
            local,
            params: ConnectionParams::new(24, 0, 72),
            peer,
        }));
        self.event(Event::Connected(epoch));
        epoch
    }

    /// The central receives what was queued, acknowledges it and returns
    /// the PDUs it makes.
    fn deliver(&self) -> Vec<(Channel, Vec<u8>)> {
        let mut reassembly = Reassembly::new();
        let mut pdus = Vec::new();
        for (start, fragment) in self.transmit() {
            if let Some(pdu) = reassembly.push(start, false, &fragment) {
                pdus.push((pdu.channel, pdu.payload.to_vec()));
            }
        }
        self.ack();
        pdus
    }

    /// The link ends for `reason`.
    fn disconnect_link(&self, reason: u8) {
        self.connected.set(false);
        self.info.set(None);
        self.queue.borrow_mut().clear();
        self.unacked.set(0);
        self.room.set(true);
        self.event(Event::Disconnected(reason));
    }

    /// The link layer reports `event`.
    fn event(&self, event: Event) { self.rx.borrow_mut().push_back(Rx::Event(event)); }

    /// The time passes by `millis`.
    fn advance(&self, millis: u64) { self.now.set(self.now.get() + millis); }

    /// A link layer with four places and no link.
    fn new() -> Self {
        Self {
            calls:     RefCell::new(Vec::new()),
            capacity:  Cell::new(4),
            connected: Cell::new(false),
            epoch:     Cell::new(0),
            info:      Cell::new(None),
            now:       Cell::new(1_000),
            queue:     RefCell::new(VecDeque::new()),
            room:      Cell::new(false),
            rx:        RefCell::new(VecDeque::new()),
            unacked:   Cell::new(0),
        }
    }

    /// The central sends `payload` on the channel `cid`, in fragments of 27
    /// octets, `encrypted` or not.
    fn send(&self, cid: u16, payload: &[u8], encrypted: bool) {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_le_bytes());
        pdu.extend_from_slice(&cid.to_le_bytes());
        pdu.extend_from_slice(payload);
        for (index, chunk) in pdu.chunks(27).enumerate() {
            self.rx.borrow_mut().push_back(Rx::Acl(AclIn::for_test(index == 0, encrypted, chunk)));
        }
    }

    /// The central sends `payload` on the security manager channel and
    /// receives what the host answers.
    #[cfg(feature = "passkey")]
    fn send_and_deliver<R: Future, K: Future>(
        &self,
        payload: &[u8],
        tasks: &mut Tasks<'_, R, K>,
    ) -> Vec<(Channel, Vec<u8>)> {
        self.send(CID_SECURITY_MANAGER, payload, false);
        tasks.step();
        self.deliver()
    }

    /// The link layer takes every queued fragment for the air.
    fn transmit(&self) -> Vec<(bool, Vec<u8>)> {
        let taken: Vec<_> = self.queue.borrow_mut().drain(..).collect();
        self.unacked.set(self.unacked.get() + taken.len());
        if !taken.is_empty() {
            self.room.set(true);
        }
        taken
    }
}

impl Control for MockLink {
    fn call(&self, call: Call<'_>) -> Result<(), link::Error> {
        let seen = match call {
            Call::AcceptListAdd(peer) => Seen::AcceptListAdd(peer),
            Call::Advertise { params, .. } => {
                if self.connected.get() {
                    return Err(link::Error::Disallowed);
                }
                Seen::Advertise(params.interval, params.filter_policy)
            },
            Call::StopAdvertising => Seen::StopAdvertising,
            _ => Seen::Setup,
        };
        self.calls.borrow_mut().push(seen);
        Ok(())
    }
}

impl Port for MockLink {
    fn disconnect(&self, epoch: Epoch, reason: u8) -> Result<(), link::Error> {
        if !self.connected.get() || self.info.get().unwrap().epoch != epoch {
            return Err(link::Error::Gone);
        }
        self.calls.borrow_mut().push(Seen::Disconnect(reason));
        Ok(())
    }

    fn hold_latency(&self, hold: bool) { self.calls.borrow_mut().push(Seen::Hold(hold)); }

    fn in_flight(&self, _epoch: Epoch) -> usize { self.queue.borrow().len() + self.unacked.get() }

    fn info(&self) -> Option<Info> { self.info.get() }

    fn ltk_reply(&self, _epoch: Epoch, key: Option<[u8; 16]>) -> Result<(), link::Error> {
        self.calls.borrow_mut().push(Seen::Ltk(key));
        Ok(())
    }

    fn next(&self) -> impl Future<Output = Rx> {
        poll_fn(|_| self.rx.borrow_mut().pop_front().map_or(Poll::Pending, Poll::Ready))
    }

    fn now(&self) -> Instant { Instant::from_millis(self.now.get()) }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        poll_fn(move |_| if self.now() >= deadline { Poll::Ready(()) } else { Poll::Pending })
    }

    fn try_send(&self, epoch: Epoch, start: bool, fragment: &[u8]) -> Result<(), link::Error> {
        if !self.connected.get() || self.info.get().unwrap().epoch != epoch {
            return Err(link::Error::Gone);
        }
        let mut queue = self.queue.borrow_mut();
        if queue.len() >= self.capacity.get() {
            return Err(link::Error::Full);
        }
        queue.push_back((start, fragment.to_vec()));
        Ok(())
    }

    fn tx_room(&self) -> usize { self.capacity.get() - self.queue.borrow().len() }

    fn tx_room_changed(&self) -> impl Future<Output = ()> {
        poll_fn(|_| if self.room.replace(false) { Poll::Ready(()) } else { Poll::Pending })
    }
}

/// The application's side of the table: a battery level of 90 %.
struct App;

impl Handler for App {
    fn read(&self, id: ValueId, out: &mut [u8]) -> Result<usize, AttError> {
        assert_eq!(id, example::BATTERY_LEVEL_VALUE);
        out[0] = 90;
        Ok(1)
    }

    fn write(&self, _id: ValueId, _data: &[u8], _with_response: bool) -> Result<(), AttError> {
        Err(AttError::WRITE_NOT_PERMITTED)
    }
}

/// The host's two tasks, polled by hand.
struct Tasks<'f, R, K> {
    /// [`Host::crypto`].
    crypto: Pin<&'f mut K>,
    /// [`Host::run`].
    run:    Pin<&'f mut R>,
}

impl<R: Future, K: Future> Tasks<'_, R, K> {
    /// Runs both tasks until neither has anything left to do.
    fn step(&mut self) {
        for _ in 0..4 {
            assert!(poll(self.run.as_mut()).is_pending());
            assert!(poll(self.crypto.as_mut()).is_pending());
        }
    }
}

/// Polls `future` once.
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> { future.poll(&mut Context::from_waker(Waker::noop())) }

/// Polls `future` once and returns its output, which must be ready.
fn ready<F: Future>(future: Pin<&mut F>) -> F::Output {
    match poll(future) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the future is not ready"),
    }
}

/// The host over a stand-in link layer, with the example table.
fn host(unclaimed: Unclaimed) -> Host<MockLink> {
    Host::new(MockLink::new(), &example::DB, Config::new(Some(example::PARAMS), unclaimed))
}

/// Our identity in generation `generation`.
fn identity(generation: u8) -> LocalIdentity {
    LocalIdentity::derive(&Software, &DeviceSecret::new([0x11; 16], [0x22; 16]), Variant::new(0, generation))
}

/// A bond with the central of the SMP tests, made under `identity`, with
/// the battery's and the keyboard's notifications on.
fn bond(identity: &LocalIdentity) -> Bond {
    let mut bond =
        Bond::new(Peer::new(CENTRAL_IDENTITY, false), Some(CENTRAL_IRK), [0x5C; 16], identity.variant(), &example::DB);
    bond.cccd = 0b0101;
    bond
}

/// Sets up the host's tasks as `$tasks`, with a watchdog hook counting its
/// calls in `$count`.
macro_rules! tasks {
    ($host:expr, $tasks:ident, $count:ident) => {
        let $count = Cell::new(0_u32);
        let mut run_device = Device(0x0123_4567_89AB_CDEF);
        let mut crypto_device = Device(0x0F1E_2D3C_4B5A_6978);
        let run = pin!($host.run(&App, &mut run_device));
        let crypto = pin!($host.crypto(&mut crypto_device, || $count.set($count.get() + 1)));
        let mut $tasks = Tasks { crypto, run };
    };
}

/// One ATT request, encrypted, and its response.
fn request<R: Future, K: Future>(link: &MockLink, tasks: &mut Tasks<'_, R, K>, pdu: &[u8]) -> Vec<u8> {
    link.send(CID_ATT, pdu, true);
    tasks.step();
    let mut pdus = link.deliver();
    assert_eq!(pdus.len(), 1, "one response");
    let (channel, response) = pdus.remove(0);
    assert_eq!(channel, Channel::Att);
    response
}

/// One PDU of the security manager from the central, and ours in answer.
fn smp<R: Future, K: Future>(
    link: &MockLink,
    tasks: &mut Tasks<'_, R, K>,
    pdu: &[u8],
    encrypted: bool,
) -> Vec<Vec<u8>> {
    link.send(CID_SECURITY_MANAGER, pdu, encrypted);
    tasks.step();
    link.deliver()
        .into_iter()
        .map(|(channel, payload)| {
            assert_eq!(channel, Channel::SecurityManager);
            payload
        })
        .collect()
}

/// The event that waits for `conn`'s application.
macro_rules! next {
    ($conn:expr) => {
        ready(pin!($conn.next()))
    };
}

#[test]
fn a_first_connection_pairs_discovers_and_asks_for_the_parameters() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));

    // Pairable advertising waits for the key pair, made at once.
    assert!(poll(advertise.as_mut()).is_pending());
    assert!(link.calls().is_empty());
    tasks.step();
    assert_eq!(multiplications.get(), 1);
    assert!(poll(advertise.as_mut()).is_pending());
    let calls = link.calls();
    assert_eq!(calls.first(), Some(&Seen::StopAdvertising));
    assert_eq!(calls.last(), Some(&Seen::Advertise(32, 0)));

    // A Linux central connects from its public address to our private one.
    let local = local_rpa();
    let central_address = Peer::new(CENTRAL_ADDRESS, false);
    let epoch = link.connect(central_address, None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    assert_eq!(conn.epoch(), epoch);
    assert_eq!(link.calls(), [Seen::Hold(true)]);
    assert_eq!(conn.security(), Some(super::gatt::Sec::Open));

    // The pairing, against the reference central, octet for octet.
    let mut central = Central::new(linux_request(true, true), local);
    let response = smp(link, &mut tasks, &central.request, false);
    assert_eq!(response, [vec![0x02, 0x03, 0x00, 0x09, 0x10, 0x02, 0x02]]);
    let answer = smp(link, &mut tasks, &central.public_key(), false);
    assert_eq!(answer.len(), 2);
    central.take_public_key(&answer[0]);
    central.take_confirm(&answer[1]);
    // The Diffie-Hellman job ran once both went out.
    assert_eq!(multiplications.get(), 2);
    let random = smp(link, &mut tasks, &central.random(), false);
    central.take_random(&random[0]);
    let check = central.check();
    assert_eq!(smp(link, &mut tasks, &check, false), [central.expected_check().to_vec()]);

    // The link layer asks for the key: the pairing's, least significant
    // octet first.
    let mut ltk = central.ltk;
    ltk.reverse();
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(Some(ltk))]);

    // Encrypted: our identity keys go out, then the central's arrive.
    link.event(Event::Encryption { on: true, refresh: false, status: 0 });
    tasks.step();
    let keys = link.deliver();
    let mut info = vec![0x08];
    info.extend_from_slice(&identity.irk());
    let mut address = vec![0x09, 0x01];
    address.extend_from_slice(&identity.address());
    assert_eq!(keys, [(Channel::SecurityManager, info), (Channel::SecurityManager, address)]);
    assert!(smp(link, &mut tasks, &pdu::<17>(0x08, &CENTRAL_IRK), true).is_empty());
    let mut central_identity = [0x09, 0x00, 0, 0, 0, 0, 0, 0];
    central_identity[2..].copy_from_slice(&CENTRAL_IDENTITY);
    assert!(smp(link, &mut tasks, &central_identity, true).is_empty());

    assert_eq!(next!(conn), ConnEvent::Encrypted { bonded: false });
    let ConnEvent::Bonded(bond) = next!(conn) else { panic!("no bond") };
    assert!(bond.peer == Peer::new(CENTRAL_IDENTITY, false));
    assert_eq!(bond.peer_irk, Some(CENTRAL_IRK));
    assert_eq!(bond.ltk, ltk);
    assert_eq!(bond.local, identity.variant());
    assert_eq!(bond.cccd, 0);
    // The stored form gives the same bond back.
    assert!(Bond::from_bytes(&bond.to_bytes()) == Some(bond.clone()));
    assert!(poll(pin!(conn.next())).is_pending());

    // Discovery as BlueZ runs it, encrypted.
    assert_eq!(request(link, &mut tasks, &[0x02, 0x05, 0x02]), [0x03, 0x17, 0x00]);
    assert_eq!(request(link, &mut tasks, &[0x08, 0x01, 0x00, 0xFF, 0xFF, 0x3A, 0x2B]), [0x01, 0x08, 0x01, 0x00, 0x0A]);
    assert_eq!(request(link, &mut tasks, &[0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28]), [
        0x11, 0x06, 0x01, 0x00, 0x07, 0x00, 0x00, 0x18, 0x08, 0x00, 0x0A, 0x00, 0x01, 0x18, 0x0B, 0x00, 0x0E, 0x00,
        0x0F, 0x18
    ]);
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x0D, 0x00]), [0x0B, 90]);
    let report_map = request(link, &mut tasks, &[0x0A, 0x16, 0x00]);
    assert_eq!(&report_map[1..], &example::REPORT_MAP[..22]);
    // The input reports need the encryption, which the request had.
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x1A, 0x00]), [0x0B, 0, 0, 0, 0, 0, 0, 0, 0]);
    // The configuration of the battery and of the three reports: the bond
    // takes it.
    for cccd in [0x0E_u8, 0x1B, 0x1F] {
        assert_eq!(request(link, &mut tasks, &[0x12, cccd, 0x00, 0x01, 0x00]), [0x13]);
    }
    // The last input report's: its Write Response goes on the air, and
    // the central does not acknowledge it yet.
    link.send(CID_ATT, &[0x12, 0x23, 0x00, 0x01, 0x00], true);
    tasks.step();
    assert_eq!(link.transmit().len(), 1);
    let ConnEvent::BondUpdated(updated) = next!(conn) else { panic!("no update") };
    assert_eq!(updated.cccd, 0b0101_0101);
    assert!(poll(pin!(conn.next())).is_pending());

    // The latency is held until the central has that response and ATT has
    // been idle for 100 ms since it was queued.
    link.advance(200);
    tasks.step();
    assert!(link.calls().is_empty());
    link.ack();
    tasks.step();
    assert_eq!(link.calls(), [Seen::Hold(false)]);
    assert_eq!(next!(conn), ConnEvent::Ready);

    // The parameters are asked for once ATT has been idle for 1.5 s: the
    // same as the table's preferred ones.
    link.advance(1299);
    tasks.step();
    assert!(link.deliver().is_empty());
    link.advance(1);
    tasks.step();
    let request = link.deliver();
    assert_eq!(request, [(Channel::Signalling, vec![0x12, 0x01, 0x08, 0x00, 12, 0, 12, 0, 30, 0, 0x58, 0x02])]);
    link.send(CID_SIGNALLING, &[0x13, 0x01, 0x02, 0x00, 0x00, 0x00], false);
    link.event(Event::ParamsUpdated { params: ConnectionParams::new(12, 30, 600), status: 0 });
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::ParamsUpdated(ConnectionParams::new(12, 30, 600)));
    link.advance(60_000);
    tasks.step();
    assert!(link.deliver().is_empty(), "asked once per link");

    // A report goes out as one fragment.
    let report = [0, 0, 0x4B, 0, 0, 0, 0, 0];
    assert_eq!(ready(pin!(conn.notify(example::KEYBOARD, &report))), Ok(()));
    let mut notification = vec![0x1B, 0x1A, 0x00];
    notification.extend_from_slice(&report);
    assert_eq!(link.deliver(), [(Channel::Att, notification)]);

    // The end of the link.
    link.disconnect_link(0x13);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x13));
    assert_eq!(link.calls(), [Seen::Hold(false)]);
    assert_eq!(ready(pin!(conn.notify(example::KEYBOARD, &report))), Err(NotifyError::Disconnected));
    assert_eq!(multiplications.get(), 2);
}

/// Sets up a reconnection of the bonded central, encrypted with the bond's
/// key, and returns the link.
macro_rules! reconnected {
    ($host:expr, $link:expr, $tasks:ident, $conn:ident) => {
        let identity = identity(1);
        let bond = bond(&identity);
        let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
        let mut advertise = pin!($host.advertise(&advertising, &identity));
        // No key pair for a reconnection.
        assert!(poll(advertise.as_mut()).is_pending());
        $tasks.step();
        assert!(poll(advertise.as_mut()).is_pending());
        let calls = $link.calls();
        assert!(calls.contains(&Seen::AcceptListAdd(bond.peer)));
        assert_eq!(calls.last(), Some(&Seen::Advertise(32, 3)));
        // The central connects from a private address the link layer
        // resolved.
        $link.connect(Peer::new([1, 2, 3, 4, 5, 0x45], true), Some(bond.peer), local_rpa());
        $tasks.step();
        let $conn = ready(advertise.as_mut()).unwrap();
        assert_eq!($link.calls(), [Seen::Hold(true)]);
        $link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
        $tasks.step();
        assert_eq!($link.calls(), [Seen::Ltk(Some(bond.ltk))]);
        $link.event(Event::Encryption { on: true, refresh: false, status: 0 });
        $tasks.step();
        assert_eq!(next!($conn), ConnEvent::Encrypted { bonded: true });
    };
}

#[test]
fn a_reconnection_encrypts_with_the_bond_and_restores_its_subscriptions() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let bond = bond(&identity);
    let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    assert_eq!(multiplications.get(), 0, "a reconnection never makes a key pair");
    let calls = link.calls();
    assert!(calls.contains(&Seen::AcceptListAdd(bond.peer)));
    assert_eq!(calls.last(), Some(&Seen::Advertise(32, 3)));
    link.connect(Peer::new([1, 2, 3, 4, 5, 0x45], true), Some(bond.peer), local_rpa());
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    assert_eq!(link.calls(), [Seen::Hold(true)]);

    // Before the encryption the bond's subscriptions are not the link's:
    // nothing is notified.
    assert!(!conn.is_subscribed(example::BATTERY_LEVEL));
    assert!(!conn.is_subscribed(example::KEYBOARD));
    assert_eq!(conn.try_notify(example::BATTERY_LEVEL, &[50]), Err(NotifyError::NotSubscribed));
    assert!(conn.try_notify(example::KEYBOARD, &[0; 8]).is_err());
    assert!(link.deliver().is_empty());

    // Only EDIV 0 and Rand 0 get the bond's key.
    link.event(Event::LtkRequest { ediv: 0x1234, rand: [0; 8] });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(None)]);
    link.event(Event::LtkRequest { ediv: 0, rand: [0, 0, 0, 0, 0, 0, 0, 1] });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(None)]);
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(Some(bond.ltk))]);

    // An encrypted request that overtakes the encryption event is served
    // as encrypted, with the bond's subscriptions restored.
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x1B, 0x00]), [0x0B, 0x01, 0x00]);
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x0E, 0x00]), [0x0B, 0x01, 0x00]);
    assert!(conn.is_subscribed(example::KEYBOARD));
    assert!(!conn.is_subscribed(example::MOUSE));
    link.event(Event::Encryption { on: true, refresh: false, status: 0 });
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Encrypted { bonded: true });

    // BlueZ writes the same configuration again: the bond keeps it, and the
    // application has nothing to store.
    for cccd in [0x0E_u8, 0x1B] {
        assert_eq!(request(link, &mut tasks, &[0x12, cccd, 0x00, 0x01, 0x00]), [0x13]);
    }
    assert!(poll(pin!(conn.next())).is_pending());
    // A report on the restored subscription.
    assert_eq!(conn.try_notify(example::KEYBOARD, &[0; 8]), Ok(()));
    assert_eq!(conn.try_notify(example::MOUSE, &[0; 5]), Err(NotifyError::NotSubscribed));
    assert_eq!(link.deliver().len(), 1);
}

#[test]
fn only_the_bonded_central_gets_the_bond_s_key() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let bond = bond(&identity);
    let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    link.calls();
    // Another central, which the link layer did not resolve.
    link.connect(Peer::new([9, 9, 9, 9, 9, 0xC9], true), None, local_rpa());
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Hold(true), Seen::Ltk(None)]);
    // Its encrypted requests are not served as encrypted, as no key of
    // ours made them.
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x1A, 0x00]), [0x01, 0x0A, 0x1A, 0x00, 0x0F]);
    // The bonded central, connected from its identity address in device
    // privacy, does get it.
    link.disconnect_link(0x13);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x13));
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(bond.peer, None, local_rpa());
    tasks.step();
    let _conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(Some(bond.ltk))]);
    assert_eq!(multiplications.get(), 0);
}

#[test]
fn notifications_keep_two_in_flight_and_one_place_free() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);

    // Two may be in flight, no third.
    assert_eq!(conn.try_notify(example::KEYBOARD, &[1; 8]), Ok(()));
    assert_eq!(conn.try_notify(example::KEYBOARD, &[2; 8]), Ok(()));
    assert_eq!(conn.try_notify(example::KEYBOARD, &[3; 8]), Err(NotifyError::Busy));
    // On the air, still unacknowledged: still two in flight.
    assert_eq!(link.transmit().len(), 2);
    assert_eq!(conn.try_notify(example::KEYBOARD, &[3; 8]), Err(NotifyError::Busy));

    // A waiting notification goes out when the acknowledgement returns
    // room, which wakes the run task.
    let mut notify = pin!(conn.notify(example::KEYBOARD, &[3; 8]));
    assert!(poll(notify.as_mut()).is_pending());
    tasks.step();
    assert!(poll(notify.as_mut()).is_pending());
    link.ack();
    tasks.step();
    assert_eq!(ready(notify.as_mut()), Ok(()));
    assert_eq!(link.deliver().len(), 1);

    // One place of the link layer's queue stays for the responses: with
    // one free, a notification waits even with nothing in flight.
    link.capacity.set(2);
    link.queue.borrow_mut().push_back((true, vec![0; 4]));
    link.unacked.set(0);
    assert_eq!(link.in_flight(conn.epoch()), 1);
    assert_eq!(conn.try_notify(example::KEYBOARD, &[4; 8]), Err(NotifyError::Busy));
    // An ATT response still takes that place.
    assert_eq!(request_queued(link, &mut tasks, &[0x0A, 0x0D, 0x00]), 2);
    link.deliver();
    assert_eq!(conn.try_notify(example::KEYBOARD, &[4; 8]), Ok(()));
    assert_eq!(multiplications.get(), 0);
}

/// Sends an ATT request and returns how many fragments the link layer's
/// queue then holds.
fn request_queued<R: Future, K: Future>(link: &MockLink, tasks: &mut Tasks<'_, R, K>, pdu: &[u8]) -> usize {
    link.send(CID_ATT, pdu, true);
    tasks.step();
    link.queue.borrow().len()
}

#[test]
fn output_waiting_for_room_goes_out_when_the_link_layer_takes_a_fragment() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    let local = local_rpa();
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let _conn = ready(advertise.as_mut()).unwrap();
    let mut central = Central::new(linux_request(true, true), local);
    smp(link, &mut tasks, &central.request, false);

    // Our public key and confirm value take four fragments; two fit.
    link.capacity.set(2);
    link.send(CID_SECURITY_MANAGER, &central.public_key(), false);
    tasks.step();
    assert_eq!(link.queue.borrow().len(), 2);
    // Nothing arrives from the central: only the room the link layer
    // returns wakes the run task, which queues the rest.
    let first = link.transmit();
    tasks.step();
    let second = link.transmit();
    assert_eq!((first.len(), second.len()), (2, 2));
    link.ack();
    let mut reassembly = Reassembly::new();
    let pdus: Vec<Vec<u8>> = first
        .iter()
        .chain(&second)
        .filter_map(|(start, fragment)| reassembly.push(*start, false, fragment).map(|pdu| pdu.payload.to_vec()))
        .collect();
    assert_eq!(pdus.len(), 2);
    central.take_public_key(&pdus[0]);
    central.take_confirm(&pdus[1]);
    assert_eq!(multiplications.get(), 2);
}

#[test]
fn a_link_not_encrypted_in_time_ends_with_an_authentication_failure() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let bond = bond(&identity);
    let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new([1, 2, 3, 4, 5, 0x45], true), Some(bond.peer), local_rpa());
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    // The reconnection schedule gives the central 20 s.
    link.advance(19_999);
    tasks.step();
    assert!(link.calls().is_empty());
    link.advance(1);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Disconnect(0x05)]);
    // The latency is never released by discovery: the end of the link does.
    link.disconnect_link(0x16);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Hold(false)]);
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x16));
    assert_eq!(multiplications.get(), 0);
}

#[test]
fn a_pairing_that_stalls_times_out_and_a_failed_one_ends_once_flushed() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let local = local_rpa();

    // A central that stops after the Pairing Request: 30 s later the
    // pairing times out and the link ends.
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    let central = Central::new(linux_request(true, true), local);
    assert_eq!(smp(link, &mut tasks, &central.request, false).len(), 1);
    link.advance(29_999);
    tasks.step();
    assert!(link.calls().is_empty());
    link.advance(1);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Disconnect(0x13)]);
    link.disconnect_link(0x16);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x16));

    // A central whose request lacks Secure Connections: our Pairing Failed
    // goes out, and the link ends once it was acknowledged.
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    link.send(CID_SECURITY_MANAGER, &[0x01, 0x04, 0x00, 0x05, 0x10, 0x07, 0x07], false);
    tasks.step();
    assert!(link.calls().is_empty(), "not before the Pairing Failed was acknowledged");
    let failed = link.deliver();
    assert_eq!(failed, [(Channel::SecurityManager, vec![0x05, 0x03])]);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Disconnect(0x05)]);
    assert_eq!(next!(conn), ConnEvent::PairingFailed(super::smp::Reason::AUTHENTICATION_REQUIREMENTS));
    // One key pair served both links: the first pairing never used it.
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn a_pairing_failed_that_is_never_acknowledged_ends_the_link_after_a_second() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    // A request without Secure Connections; our Pairing Failed goes on the
    // air and the central never acknowledges it.
    link.send(CID_SECURITY_MANAGER, &[0x01, 0x04, 0x00, 0x05, 0x10, 0x07, 0x07], false);
    tasks.step();
    assert_eq!(link.transmit(), [(true, vec![2, 0, 6, 0, 0x05, 0x03])]);
    link.advance(999);
    tasks.step();
    assert!(link.calls().is_empty());
    link.advance(1);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Disconnect(0x05)]);
    assert_eq!(next!(conn), ConnEvent::PairingFailed(super::smp::Reason::AUTHENTICATION_REQUIREMENTS));
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn a_pairing_failed_from_the_central_ends_the_link_at_once() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    let local = local_rpa();
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    let central = Central::new(linux_request(true, true), local);
    assert_eq!(smp(link, &mut tasks, &central.request, false).len(), 1);
    // The central gives up: never answered, and the link ends.
    assert!(smp(link, &mut tasks, &[0x05, 0x08], false).is_empty());
    assert_eq!(link.calls(), [Seen::Disconnect(0x05)]);
    assert_eq!(next!(conn), ConnEvent::PairingFailed(super::smp::Reason::UNSPECIFIED));
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn a_pairing_request_while_reconnecting_is_refused_and_ends_the_link() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let bond = bond(&identity);
    let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new([1, 2, 3, 4, 5, 0x45], true), Some(bond.peer), local_rpa());
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    // The bonded central lost its keys and pairs again: the slot is taken.
    let central = Central::new(linux_request(true, true), local_rpa());
    assert_eq!(smp(link, &mut tasks, &central.request, false), [vec![0x05, 0x05]]);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Disconnect(0x05)]);
    assert_eq!(next!(conn), ConnEvent::PairingFailed(super::smp::Reason::PAIRING_NOT_SUPPORTED));
    link.disconnect_link(0x16);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x16));
    assert_eq!(multiplications.get(), 0);
}

#[test]
fn a_rejected_parameter_request_is_not_repeated() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);
    // Without input report writes, discovery is over after a second of
    // idle ATT, and the request follows half a second later.
    link.advance(1000);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Hold(false)]);
    assert_eq!(next!(conn), ConnEvent::Ready);
    link.advance(500);
    tasks.step();
    let request = link.deliver();
    assert_eq!(request, [(Channel::Signalling, vec![0x12, 0x01, 0x08, 0x00, 12, 0, 12, 0, 30, 0, 0x58, 0x02])]);
    // The central refuses: the link keeps its parameters and goes on.
    link.send(CID_SIGNALLING, &[0x13, 0x01, 0x02, 0x00, 0x01, 0x00], false);
    tasks.step();
    link.advance(60_000);
    tasks.step();
    assert!(link.deliver().is_empty());
    assert!(link.calls().is_empty());
    #[cfg(feature = "param-requests")]
    assert_eq!(next!(conn), ConnEvent::ParamsRejected);
    assert!(poll(pin!(conn.next())).is_pending());
    assert_eq!(conn.try_notify(example::KEYBOARD, &[0; 8]), Ok(()));
    assert_eq!(multiplications.get(), 0);
}

#[test]
fn a_bond_is_reported_only_once_the_central_has_our_identity() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let local = local_rpa();
    for acknowledged in [false, true] {
        let mut advertise = pin!(host.advertise(&advertising, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        tasks.step();
        assert!(poll(advertise.as_mut()).is_pending());
        link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
        tasks.step();
        let conn = ready(advertise.as_mut()).unwrap();
        // BlueZ's default: the central distributes no identity of its own.
        let mut central = Central::new(linux_request(false, true), local);
        smp(link, &mut tasks, &central.request, false);
        let answer = smp(link, &mut tasks, &central.public_key(), false);
        central.take_public_key(&answer[0]);
        central.take_confirm(&answer[1]);
        let random = smp(link, &mut tasks, &central.random(), false);
        central.take_random(&random[0]);
        smp(link, &mut tasks, &central.check(), false);
        link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
        link.event(Event::Encryption { on: true, refresh: false, status: 0 });
        tasks.step();
        // Our identity keys are on the air, not yet acknowledged.
        assert_eq!(link.transmit().len(), 2);
        assert_eq!(next!(conn), ConnEvent::Encrypted { bonded: false });
        assert!(poll(pin!(conn.next())).is_pending());
        if acknowledged {
            link.ack();
            tasks.step();
            let ConnEvent::Bonded(bond) = next!(conn) else { panic!("no bond") };
            assert!(bond.peer == Peer::new(CENTRAL_ADDRESS, false));
        } else {
            // The link ends first: the central may never have learned our
            // identity, and nothing is to be stored.
            link.disconnect_link(0x08);
            tasks.step();
            assert_eq!(next!(conn), ConnEvent::Disconnected(0x08));
        }
        link.disconnect_link(0x13);
        tasks.step();
        link.calls();
    }
    assert_eq!(multiplications.get(), 4);
}

#[test]
fn a_call_waits_for_a_link_the_run_task_has_not_taken_yet() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let pairing = example::advertising(Mode::Pairing, None).unwrap();
    {
        let mut advertise = pin!(host.advertise(&pairing, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        tasks.step();
        assert!(poll(advertise.as_mut()).is_pending());
    }
    link.calls();
    // A central connected to the dropped call; the run task has not read
    // the event when the application asks for reconnection.
    let epoch = link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
    let bond = bond(&identity);
    let reconnect = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&reconnect, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    // The link from the pairing call comes back, and nothing was set up
    // for the new call under it.
    let conn = ready(advertise.as_mut()).unwrap();
    assert_eq!(conn.epoch(), epoch);
    assert_eq!(link.calls(), [Seen::Hold(true)]);
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn advertising_starts_again_when_a_link_ends_before_the_host_took_it() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    assert_eq!(link.calls().last(), Some(&Seen::Advertise(32, 0)));
    // The link layer stopped advertising for a connection that failed to
    // be established before the run task read it.
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
    link.disconnect_link(0x3E);
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    assert_eq!(link.calls(), [Seen::Advertise(32, 0)]);
    // The next central is served.
    let epoch = link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
    tasks.step();
    assert_eq!(ready(advertise.as_mut()).unwrap().epoch(), epoch);
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn a_central_that_connects_after_the_advertising_call_was_dropped_is_kept() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    {
        let mut advertise = pin!(host.advertise(&advertising, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        tasks.step();
        assert!(poll(advertise.as_mut()).is_pending());
        assert!(link.calls().contains(&Seen::Advertise(32, 0)));
    }
    // The dropped call stopped advertising, but a central had connected.
    assert_eq!(link.calls(), [Seen::StopAdvertising]);
    let epoch = link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
    tasks.step();
    assert_eq!(link.calls(), [Seen::Hold(true)]);
    // The next call returns it without advertising.
    let conn = ready(pin!(host.advertise(&advertising, &identity))).unwrap();
    assert_eq!(conn.epoch(), epoch);
    assert_eq!(link.calls(), []);
    // A second call while it exists is refused.
    assert!(matches!(ready(pin!(host.advertise(&advertising, &identity))), Err(AdvertiseError::Connected)));

    // A link that arrived for a call that was dropped before it took it is
    // kept too.
    link.disconnect_link(0x13);
    tasks.step();
    {
        let mut advertise = pin!(host.advertise(&advertising, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
        tasks.step();
    }
    let calls = link.calls();
    assert!(!calls.iter().any(|call| matches!(call, Seen::Disconnect(_))));
    assert!(ready(pin!(host.advertise(&advertising, &identity))).is_ok());
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn a_central_that_connects_after_the_advertising_call_was_dropped_can_be_ended() {
    let host = host(Unclaimed::Disconnect);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    {
        let mut advertise = pin!(host.advertise(&advertising, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        tasks.step();
        assert!(poll(advertise.as_mut()).is_pending());
    }
    link.calls();
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
    tasks.step();
    assert_eq!(link.calls(), [Seen::Hold(true), Seen::Disconnect(0x13)]);
    // The link is nobody's: the next call waits for its end, then
    // advertises.
    {
        let mut advertise = pin!(host.advertise(&advertising, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        assert!(link.calls().is_empty());
        link.disconnect_link(0x16);
        tasks.step();
        assert!(poll(advertise.as_mut()).is_pending());
        assert_eq!(link.calls().last(), Some(&Seen::Advertise(32, 0)));
    }
    link.calls();

    // The same when the link arrived before the call's future was dropped.
    {
        let mut advertise = pin!(host.advertise(&advertising, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
        tasks.step();
    }
    tasks.step();
    let calls = link.calls();
    assert!(calls.contains(&Seen::Disconnect(0x13)), "{calls:?}");
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn advertising_runs_its_phases_and_then_times_out() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    assert_eq!(link.calls().last(), Some(&Seen::Advertise(32, 0)));
    link.advance(3_000);
    assert!(poll(advertise.as_mut()).is_pending());
    assert_eq!(link.calls(), [Seen::Advertise(80, 0)]);
    link.advance(12_000);
    assert!(poll(advertise.as_mut()).is_pending());
    assert_eq!(link.calls(), [Seen::Advertise(640, 0)]);
    link.advance(45_000);
    assert!(matches!(ready(advertise.as_mut()), Err(AdvertiseError::Timeout)));
    assert_eq!(link.calls(), [Seen::StopAdvertising]);
    assert_eq!(multiplications.get(), 1);
}

#[test]
fn disconnected_comes_after_every_other_event_of_its_link() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);
    // Events pile up while the application does not read them, and the
    // link ends meanwhile.
    link.event(Event::ParamsUpdated { params: ConnectionParams::new(6, 0, 100), status: 0 });
    link.event(Event::ParamsUpdated { params: ConnectionParams::new(12, 30, 600), status: 0 });
    link.advance(1000);
    tasks.step();
    link.disconnect_link(0x08);
    tasks.step();
    // They coalesce and come in order, the end last, and again after that.
    assert_eq!(next!(conn), ConnEvent::ParamsUpdated(ConnectionParams::new(12, 30, 600)));
    assert_eq!(next!(conn), ConnEvent::Ready);
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x08));
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x08));
    // A link that ended before the next one still tells its reason.
    let identity = identity(1);
    let bond = bond(&identity);
    let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(bond.peer, None, local_rpa());
    tasks.step();
    let next = ready(advertise.as_mut()).unwrap();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x08));
    assert!(poll(pin!(next.next())).is_pending());
    assert_eq!(conn.try_notify(example::KEYBOARD, &[0; 8]), Err(NotifyError::Disconnected));
    link.disconnect_link(0x13);
    tasks.step();
    assert_eq!(next!(next), ConnEvent::Disconnected(0x13));
    // One the host no longer knows ended for a reason it forgot.
    assert_eq!(next!(conn), ConnEvent::Disconnected(0));
    assert_eq!(multiplications.get(), 0);
}

#[test]
fn the_battery_level_is_notified_when_it_changes() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);
    let battery = super::Battery::new(example::BATTERY_LEVEL, 90);
    let mut out = [0; 2];
    assert_eq!(battery.read(&mut out), Ok(1));
    assert_eq!(out[0], 90);
    assert_eq!(ready(pin!(battery.update(&conn, 90))), Ok(()));
    assert!(link.deliver().is_empty());
    assert_eq!(ready(pin!(battery.update(&conn, 89))), Ok(()));
    assert_eq!(link.deliver(), [(Channel::Att, vec![0x1B, 0x0D, 0x00, 89])]);
    assert_eq!(battery.level(), 89);
    assert_eq!(multiplications.get(), 0);
}

#[test]
fn signalling_requests_get_a_command_reject() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);
    link.send(CID_SIGNALLING, &[0x0A, 0x07, 0x02, 0x00, 0x01, 0x00], false);
    tasks.step();
    assert_eq!(link.deliver(), [(Channel::Signalling, vec![0x01, 0x07, 0x02, 0x00, 0x00, 0x00])]);
    assert_eq!(conn.security(), Some(super::gatt::Sec::Encrypted));
    assert_eq!(multiplications.get(), 0);
}

/// The software stand-in gives the AES-128 example of FIPS-197 appendix
/// C.1.
#[test]
fn software_aes_matches_fips_197() {
    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let plain = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let cipher = [0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A];
    assert_eq!(Software.encrypt(key, plain), cipher);
}

/// The fallback range of the parameter request tests: 11.25 to 15 ms, a
/// latency of 30 events, 6 s.
#[cfg(feature = "param-requests")]
const FALLBACK: link::ParamRange = link::ParamRange::new(9, 12, 30, 600);

#[cfg(feature = "param-requests")]
#[test]
fn the_application_asks_for_parameters_and_learns_of_a_rejection() {
    use super::RequestError;
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);
    // A request goes out at once as a signalling PDU, with the first
    // identifier of the link.
    assert_eq!(conn.request_params(FALLBACK), Ok(()));
    tasks.step();
    assert_eq!(link.deliver(), [(Channel::Signalling, vec![0x12, 0x01, 0x08, 0x00, 9, 0, 12, 0, 30, 0, 0x58, 0x02])]);
    // One at a time: a second waits for the response to the first.
    assert_eq!(conn.request_params(example::PARAMS), Err(RequestError::Busy));
    // The central refuses it: the application learns it.
    link.send(CID_SIGNALLING, &[0x13, 0x01, 0x02, 0x00, 0x01, 0x00], false);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::ParamsRejected);
    assert!(poll(pin!(conn.next())).is_pending());
    // The next request has a fresh identifier; a Command Reject of it
    // rejects it too.
    assert_eq!(conn.request_params(FALLBACK), Ok(()));
    tasks.step();
    assert_eq!(link.deliver(), [(Channel::Signalling, vec![0x12, 0x02, 0x08, 0x00, 9, 0, 12, 0, 30, 0, 0x58, 0x02])]);
    link.send(CID_SIGNALLING, &[0x01, 0x02, 0x02, 0x00, 0x00, 0x00], false);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::ParamsRejected);
    // An accepted request has no event of its own: the update follows.
    assert_eq!(conn.request_params(FALLBACK), Ok(()));
    tasks.step();
    assert_eq!(link.deliver().len(), 1);
    link.send(CID_SIGNALLING, &[0x13, 0x03, 0x02, 0x00, 0x00, 0x00], false);
    tasks.step();
    assert!(poll(pin!(conn.next())).is_pending());
    link.event(Event::ParamsUpdated { params: ConnectionParams::new(12, 30, 600), status: 0 });
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::ParamsUpdated(ConnectionParams::new(12, 30, 600)));
    // The engine's own request is not made after the application's.
    link.advance(1000);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Ready);
    link.advance(60_000);
    tasks.step();
    assert!(link.deliver().is_empty(), "no automatic request after a manual one");
    // A range out of the specification's is refused.
    assert_eq!(conn.request_params(link::ParamRange::new(12, 9, 30, 600)), Err(RequestError::Invalid));
    assert_eq!(conn.request_params(link::ParamRange::new(5, 12, 30, 600)), Err(RequestError::Invalid));
    assert_eq!(conn.request_params(link::ParamRange::new(12, 12, 30, 10)), Err(RequestError::Invalid));
    assert!(link.deliver().is_empty());
    assert_eq!(multiplications.get(), 0);
}

#[cfg(feature = "param-requests")]
#[test]
fn the_end_of_the_link_clears_a_pending_parameter_request() {
    use super::RequestError;
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);
    assert_eq!(conn.request_params(FALLBACK), Ok(()));
    tasks.step();
    assert_eq!(link.deliver().len(), 1);
    link.disconnect_link(0x13);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x13));
    assert_eq!(conn.request_params(FALLBACK), Err(RequestError::Gone));
    // The next link asks again from the first identifier; a late response
    // of the old link's request would be dropped.
    let identity = identity(1);
    let bond = bond(&identity);
    let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(bond.peer, None, local_rpa());
    tasks.step();
    let next = ready(advertise.as_mut()).unwrap();
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    link.event(Event::Encryption { on: true, refresh: false, status: 0 });
    tasks.step();
    assert_eq!(next!(next), ConnEvent::Encrypted { bonded: true });
    assert_eq!(next.request_params(FALLBACK), Ok(()));
    tasks.step();
    assert_eq!(link.deliver(), [(Channel::Signalling, vec![0x12, 0x01, 0x08, 0x00, 9, 0, 12, 0, 30, 0, 0x58, 0x02])]);
    // A request the central never answers lets the next go out after the
    // signalling timeout, without an event.
    link.advance(29_999);
    tasks.step();
    assert_eq!(next.request_params(FALLBACK), Err(RequestError::Busy));
    link.advance(1);
    tasks.step();
    assert_eq!(next!(next), ConnEvent::Ready);
    assert!(poll(pin!(next.next())).is_pending());
    assert_eq!(next.request_params(FALLBACK), Ok(()));
    assert_eq!(multiplications.get(), 0);
}

#[cfg(feature = "param-requests")]
#[test]
fn the_engine_s_own_rejected_request_is_reported_too() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    reconnected!(host, link, tasks, conn);
    link.advance(1000);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Ready);
    link.advance(500);
    tasks.step();
    assert_eq!(link.deliver().len(), 1);
    link.send(CID_SIGNALLING, &[0x13, 0x01, 0x02, 0x00, 0x01, 0x00], false);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::ParamsRejected);
    // The application's fallback goes out as the second request.
    assert_eq!(conn.request_params(FALLBACK), Ok(()));
    tasks.step();
    assert_eq!(link.deliver(), [(Channel::Signalling, vec![0x12, 0x02, 0x08, 0x00, 9, 0, 12, 0, 30, 0, 0x58, 0x02])]);
    assert_eq!(multiplications.get(), 0);
}

#[cfg(feature = "key-missing")]
#[test]
fn a_reconnection_without_the_bond_s_key_ends_at_once() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let bond = bond(&identity);
    let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new([1, 2, 3, 4, 5, 0x45], true), Some(bond.peer), local_rpa());
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    // The central asks for a key of another pairing: the negative reply,
    // which the link layer reports as a failed encryption, and the link
    // ends at once instead of 20 s later.
    link.event(Event::LtkRequest { ediv: 0x1234, rand: [7; 8] });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(None)]);
    link.event(Event::Encryption { on: false, refresh: false, status: 0x06 });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Disconnect(0x05)]);
    assert_eq!(next!(conn), ConnEvent::KeyMissing);
    assert!(poll(pin!(conn.next())).is_pending());
    // Once only, and the end of the link follows.
    link.advance(20_000);
    tasks.step();
    assert!(link.calls().is_empty());
    link.disconnect_link(0x16);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x16));
    assert_eq!(multiplications.get(), 0);
}

#[cfg(feature = "key-missing")]
#[test]
fn a_pairable_link_without_a_key_waits_for_a_pairing() {
    let host = host(Unclaimed::Keep);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local_rpa());
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    // A central with a stale key of ours: in pairing mode it may still pair,
    // so the link goes on.
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    link.event(Event::Encryption { on: false, refresh: false, status: 0x06 });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(None)]);
    assert!(poll(pin!(conn.next())).is_pending());
    let central = Central::new(linux_request(true, true), local_rpa());
    assert_eq!(smp(link, &mut tasks, &central.request, false).len(), 1);
    assert_eq!(multiplications.get(), 1);
}

/// A keyboard's table for the Passkey Entry tests: an input report that
/// needs an authenticated link.
#[cfg(feature = "passkey")]
mod keyboard {
    use crate::host::gatt::Value;

    crate::gatt! {
        /// The table.
        pub const DB;
        service 0x1812 {
            /// The keyboard input report.
            char KEYS: 0x2A4D [read, notify; authenticated] = Value::Zeros(8);
            ccc;
        }
    }
}

/// A keyboard's host: Passkey Entry only.
#[cfg(feature = "passkey")]
fn keyboard_host() -> Host<MockLink> {
    let config = Config::new(Some(example::PARAMS), Unclaimed::Keep).with_security(super::smp::tests::KEYBOARD);
    Host::new(MockLink::new(), &keyboard::DB, config)
}

#[cfg(feature = "passkey")]
#[test]
fn a_keyboard_pairs_with_the_passkey_the_user_types_and_its_link_is_authenticated() {
    use super::{PasskeyError, gatt::Sec, smp::tests::request_with_io};
    let host = keyboard_host();
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    let local = local_rpa();
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    // Nothing to enter before the pairing asks for it.
    assert_eq!(conn.enter_passkey(Some(1)), Err(PasskeyError::NotWaiting));

    let passkey = 314_159;
    let mut central = Central::new(request_with_io(0x04), local).with_passkey(passkey);
    assert_eq!(smp(link, &mut tasks, &central.request, false), [vec![0x02, 0x02, 0x00, 0x0D, 0x10, 0x02, 0x02]]);
    let answer = smp(link, &mut tasks, &central.public_key(), false);
    assert_eq!(answer.len(), 1, "our public key alone");
    central.take_public_key(&answer[0]);
    assert_eq!(next!(conn), ConnEvent::PasskeyRequested);
    // The Diffie-Hellman key is computed while the user types.
    assert_eq!(multiplications.get(), 2);
    // The central's first confirm value comes first; then the passkey.
    assert!(smp(link, &mut tasks, &central.round_confirm(0, passkey), false).is_empty());
    assert_eq!(conn.enter_passkey(Some(1_000_000)), Err(PasskeyError::Invalid));
    assert_eq!(conn.enter_passkey(Some(passkey)), Ok(()));
    assert_eq!(conn.enter_passkey(Some(passkey)), Err(PasskeyError::NotWaiting));
    tasks.step();
    let mut confirm = link.deliver();
    for round in 0..20 {
        assert_eq!(confirm.len(), 1, "round {round}");
        central.take_confirm(&confirm.remove(0).1);
        let random = smp(link, &mut tasks, &central.random(), false);
        central.take_round_random(&random[0], round, passkey);
        if round < 19 {
            confirm = link.send_and_deliver(&central.round_confirm(round + 1, passkey), &mut tasks);
        }
    }
    let check = central.check();
    assert_eq!(smp(link, &mut tasks, &check, false), [central.expected_check().to_vec()]);
    let mut ltk = central.ltk;
    ltk.reverse();
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    link.event(Event::Encryption { on: true, refresh: false, status: 0 });
    tasks.step();
    assert_eq!(link.calls(), [Seen::Ltk(Some(ltk))]);
    assert_eq!(conn.security(), Some(Sec::Authenticated));
    // Our identity keys.
    assert_eq!(link.deliver().len(), 2);
    // The report that needs authentication is served on this link.
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x03, 0x00]), [0x0B, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(smp(link, &mut tasks, &pdu::<17>(0x08, &CENTRAL_IRK), true).is_empty());
    let mut central_identity = [0x09, 0x00, 0, 0, 0, 0, 0, 0];
    central_identity[2..].copy_from_slice(&CENTRAL_IDENTITY);
    assert!(smp(link, &mut tasks, &central_identity, true).is_empty());
    assert_eq!(next!(conn), ConnEvent::Encrypted { bonded: false });
    let ConnEvent::Bonded(bond) = next!(conn) else { panic!("no bond") };
    assert!(bond.authenticated);
    assert!(Bond::from_bytes(&bond.to_bytes()).is_some_and(|stored| stored.authenticated));
    assert_eq!(conn.security(), Some(Sec::Authenticated));
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x03, 0x00]), [0x0B, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(multiplications.get(), 2);
}

#[cfg(feature = "passkey")]
#[test]
fn a_passkey_refused_by_the_user_fails_the_pairing_and_ends_the_link() {
    use super::{PasskeyError, smp::tests::request_with_io};
    let host = keyboard_host();
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    let local = local_rpa();
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    let central = Central::new(request_with_io(0x04), local);
    smp(link, &mut tasks, &central.request, false);
    smp(link, &mut tasks, &central.public_key(), false);
    assert_eq!(next!(conn), ConnEvent::PasskeyRequested);
    assert_eq!(conn.enter_passkey(None), Ok(()));
    tasks.step();
    assert_eq!(link.deliver(), [(Channel::SecurityManager, vec![0x05, 0x01])]);
    tasks.step();
    assert_eq!(link.calls(), [Seen::Disconnect(0x05)]);
    assert_eq!(next!(conn), ConnEvent::PairingFailed(super::smp::Reason::PASSKEY_ENTRY_FAILED));
    link.disconnect_link(0x16);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::Disconnected(0x16));
    assert_eq!(conn.enter_passkey(Some(1)), Err(PasskeyError::Gone));

    // A central without input or output is refused at its request.
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    let central = Central::new(request_with_io(0x03), local);
    assert_eq!(smp(link, &mut tasks, &central.request, false), [vec![0x05, 0x03]]);
    tasks.step();
    assert_eq!(next!(conn), ConnEvent::PairingFailed(super::smp::Reason::AUTHENTICATION_REQUIREMENTS));
    assert!(multiplications.get() >= 1);
}

#[cfg(feature = "passkey")]
#[test]
fn a_reconnection_is_authenticated_only_with_an_authenticated_bond() {
    use super::gatt::Sec;
    for authenticated in [false, true] {
        let host = keyboard_host();
        let link = host.port();
        tasks!(host, tasks, multiplications);
        let identity = identity(1);
        let mut bond = Bond::new(
            Peer::new(CENTRAL_IDENTITY, false),
            Some(CENTRAL_IRK),
            [0x5C; 16],
            identity.variant(),
            &keyboard::DB,
        );
        bond.authenticated = authenticated;
        bond.cccd = 0b01;
        let advertising = example::advertising(Mode::Reconnect(&bond), None).unwrap();
        let mut advertise = pin!(host.advertise(&advertising, &identity));
        assert!(poll(advertise.as_mut()).is_pending());
        link.connect(Peer::new([1, 2, 3, 4, 5, 0x45], true), Some(bond.peer), local_rpa());
        tasks.step();
        let conn = ready(advertise.as_mut()).unwrap();
        link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
        link.event(Event::Encryption { on: true, refresh: false, status: 0 });
        tasks.step();
        assert_eq!(next!(conn), ConnEvent::Encrypted { bonded: true });
        let read = request(link, &mut tasks, &[0x0A, 0x03, 0x00]);
        if authenticated {
            assert_eq!(conn.security(), Some(Sec::Authenticated));
            assert_eq!(read, [0x0B, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(conn.try_notify(keyboard::KEYS, &[0; 8]), Ok(()));
        } else {
            // Insufficient Authentication, and no report.
            assert_eq!(conn.security(), Some(Sec::Encrypted));
            assert_eq!(read, [0x01, 0x0A, 0x03, 0x00, 0x05]);
            assert_eq!(conn.try_notify(keyboard::KEYS, &[0; 8]), Err(NotifyError::Insecure));
        }
        assert_eq!(multiplications.get(), 0);
    }
}

#[cfg(feature = "passkey")]
#[test]
fn a_just_works_key_stays_unauthenticated_when_a_passkey_pairing_starts_on_its_link() {
    use super::{
        gatt::Sec,
        smp::{IoCapability, Security, tests::request_with_io},
    };
    // Passkey Entry where the central can take part, Just Works otherwise.
    let config = Config::new(Some(example::PARAMS), Unclaimed::Keep)
        .with_security(Security::new(IoCapability::KeyboardOnly, false));
    let host = Host::new(MockLink::new(), &keyboard::DB, config);
    let link = host.port();
    tasks!(host, tasks, multiplications);
    let identity = identity(1);
    let advertising = example::advertising(Mode::Pairing, None).unwrap();
    let mut advertise = pin!(host.advertise(&advertising, &identity));
    assert!(poll(advertise.as_mut()).is_pending());
    tasks.step();
    assert!(poll(advertise.as_mut()).is_pending());
    let local = local_rpa();
    link.connect(Peer::new(CENTRAL_ADDRESS, false), None, local);
    tasks.step();
    let conn = ready(advertise.as_mut()).unwrap();
    link.calls();
    // A central without input or output: Just Works.
    let mut central = Central::new(request_with_io(0x03), local);
    central.io_cap_b = [0x0D, 0x00, 0x02];
    assert_eq!(smp(link, &mut tasks, &central.request, false), [vec![0x02, 0x02, 0x00, 0x0D, 0x10, 0x02, 0x02]]);
    let answer = smp(link, &mut tasks, &central.public_key(), false);
    assert_eq!(answer.len(), 2);
    central.take_public_key(&answer[0]);
    central.take_confirm(&answer[1]);
    let random = smp(link, &mut tasks, &central.random(), false);
    central.take_random(&random[0]);
    let check = central.check();
    assert_eq!(smp(link, &mut tasks, &check, false), [central.expected_check().to_vec()]);
    link.event(Event::LtkRequest { ediv: 0, rand: [0; 8] });
    link.event(Event::Encryption { on: true, refresh: false, status: 0 });
    tasks.step();
    link.calls();
    assert_eq!(link.deliver().len(), 2);
    assert_eq!(conn.security(), Some(Sec::Encrypted));
    // In place of its identity keys, a Pairing Request, which fails the
    // pairing under way; then one claiming a display, which starts Passkey
    // Entry on the link still encrypted with the Just Works key.
    let display = Central::new(request_with_io(0x04), local);
    assert_eq!(smp(link, &mut tasks, &display.request, true), [vec![0x05, 0x08]]);
    assert_eq!(smp(link, &mut tasks, &display.request, true), [vec![0x02, 0x02, 0x00, 0x0D, 0x10, 0x02, 0x02]]);
    // The key of the link is still that of Just Works.
    assert_eq!(conn.security(), Some(Sec::Encrypted));
    assert_eq!(request(link, &mut tasks, &[0x0A, 0x03, 0x00]), [0x01, 0x0A, 0x03, 0x00, 0x05]);
    // The failed pairing ends the link; no report goes out meanwhile.
    assert!(conn.try_notify(keyboard::KEYS, &[0; 8]).is_err());
    assert!(multiplications.get() >= 1);
}

#[cfg(feature = "passkey")]
#[test]
#[should_panic(expected = "authenticated attributes")]
fn a_table_with_authenticated_attributes_needs_passkey_entry() {
    let _host = Host::new(MockLink::new(), &keyboard::DB, Config::new(None, Unclaimed::Keep));
}
