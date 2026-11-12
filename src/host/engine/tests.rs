//! Tests of the engine without the async glue: the room its output leaves,
//! the order of its calls of the link layer, and notifications against a
//! PDU of several fragments.

use super::*;
use crate::{
    host::{
        bond::Bond,
        example,
        gatt::{AttError, ValueId},
        identity::DeviceSecret,
        smp::{
            IDENTITY_ADDRESS_INFORMATION,
            IDENTITY_INFORMATION,
            tests::{CENTRAL_ADDRESS, CENTRAL_IDENTITY, Central, Device, linux_request, local_rpa, pdu},
        },
        test_aes::Software,
    },
    pdu::Peer,
};

/// The application's side of the table: a battery level of 90 %.
struct App;

impl Handler for App {
    fn read(&self, _id: ValueId, out: &mut [u8]) -> Result<usize, AttError> {
        out[0] = 90;
        Ok(1)
    }

    fn write(&self, _id: ValueId, _data: &[u8], _with_response: bool) -> Result<(), AttError> {
        Err(AttError::WRITE_NOT_PERMITTED)
    }
}

/// The time `millis` milliseconds into the test.
fn at(millis: u64) -> Instant { Instant::from_millis(millis) }

/// Our identity.
fn identity() -> identity::Local {
    identity::Local::derive(&Software, &DeviceSecret::new([0x11; 16], [0x22; 16]), Variant::new(0, 1))
}

/// The information of a link from `peer`, resolved to `identity`.
fn info(peer: Peer, identity: Option<Peer>) -> Info {
    Info {
        central_accuracy: 0,
        epoch: Epoch::for_test(1),
        identity,
        local: local_rpa(),
        params: ConnectionParams::new(24, 0, 72),
        peer,
    }
}

/// `payload` on `cid` as the fragments of a received PDU, unencrypted.
fn receive(engine: &mut Engine, device: &mut Device, cid: u16, payload: &[u8], now: Instant) {
    receive_as(engine, device, cid, payload, false, now);
}

/// `payload` on `cid` as the fragments of a received PDU, `encrypted` or
/// not.
fn receive_as(engine: &mut Engine, device: &mut Device, cid: u16, payload: &[u8], encrypted: bool, now: Instant) {
    let mut pdu = std::vec::Vec::new();
    pdu.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_le_bytes());
    pdu.extend_from_slice(&cid.to_le_bytes());
    pdu.extend_from_slice(payload);
    for (index, chunk) in pdu.chunks(27).enumerate() {
        engine.on_acl(device, &App, &AclIn::for_test(index == 0, encrypted, chunk), now);
    }
}

extern crate std;

/// Queues every fragment the engine has, with room for `room`, and
/// returns them.
fn drain(engine: &mut Engine, room: usize, now: Instant) -> std::vec::Vec<Fragment> {
    let mut fragments = std::vec::Vec::new();
    while let Some(fragment) = engine.next_fragment(room) {
        fragments.push(fragment);
        engine.fragment_sent(now);
    }
    fragments
}

#[test]
fn a_notification_never_interleaves_with_the_fragments_of_a_public_key() {
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(5);
    engine.advertise(true, &identity(), None, Duration::from_secs(60));
    let job = engine.take_job().unwrap();
    let result = job.run(&mut device.clone(), || ());
    engine.job_done(&mut device, result, at(0));
    engine.connected(&info(Peer::new(CENTRAL_ADDRESS, false), None), at(0));
    // The battery's notifications are open: enabled before any pairing.
    receive(&mut engine, &mut device, 4, &[0x12, 0x0E, 0x00, 0x01, 0x00], at(0));
    assert_eq!(drain(&mut engine, 4, at(0)).len(), 1);
    let epoch = engine.epoch().unwrap();
    assert!(engine.notification(epoch, example::BATTERY_LEVEL, &[50]).is_ok());

    let central = Central::new(linux_request(true, true), local_rpa());
    receive(&mut engine, &mut device, 6, &central.request, at(1));
    assert_eq!(drain(&mut engine, 4, at(1)).len(), 1);
    receive(&mut engine, &mut device, 6, &central.public_key(), at(2));
    // The first fragment of our public key is queued: the rest must follow
    // before anything else starts.
    let first = engine.next_fragment(4).unwrap();
    assert!(first.start());
    engine.fragment_sent(at(2));
    assert_eq!(engine.notification(epoch, example::BATTERY_LEVEL, &[50]), Err(NotifyError::Busy));
    let rest = drain(&mut engine, 4, at(2));
    assert_eq!(rest.iter().map(|fragment| (fragment.start(), fragment.bytes().len())).collect::<std::vec::Vec<_>>(), [
        (false, 27),
        (false, 15),
        (true, 21)
    ]);
    let fragment = engine.notification(epoch, example::BATTERY_LEVEL, &[50]).unwrap();
    assert_eq!(fragment.bytes(), [4, 0, 4, 0, 0x1B, 0x0D, 0x00, 50]);
    // The input reports need the encryption the link lacks.
    assert_eq!(engine.notification(epoch, example::KEYBOARD, &[0; 8]), Err(NotifyError::NotSubscribed));
}

#[test]
fn the_parameter_request_leaves_the_last_place_to_responses() {
    let identity = identity();
    let bond = Bond::new(Peer::new(CENTRAL_IDENTITY, false), None, [0x77; 16], identity.variant(), &example::DB);
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    engine.advertise(false, &identity, Some(bond), Duration::from_secs(20));
    assert!(!engine.has_job(), "no key pair for a reconnection");
    engine.connected(&info(Peer::new([3; 6], true), Some(Peer::new(CENTRAL_IDENTITY, false))), at(0));
    let epoch = engine.epoch().unwrap();
    engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, at(0));
    // The latency hold, then the key.
    assert_eq!(engine.take_command(0, at(0)), Some(Command::HoldLatency(true)));
    assert_eq!(engine.take_command(0, at(0)), Some(Command::LtkReply { epoch, key: Some([0x77; 16]) }));
    assert_eq!(engine.take_command(0, at(0)), None);
    engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, at(10));
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: true }));
    // No input report configuration was written: the fallback.
    assert_eq!(engine.next_deadline(), Some(at(1010)));
    engine.on_time(at(1010));
    assert_eq!(engine.take_command(0, at(1010)), Some(Command::HoldLatency(false)));
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Ready));
    assert_eq!(engine.next_deadline(), Some(at(1510)));
    engine.on_time(at(1510));
    assert!(engine.has_output());
    assert_eq!(engine.next_fragment(1), None);
    let request = engine.next_fragment(2).unwrap();
    assert_eq!(request.bytes()[..6], [12, 0, 5, 0, 0x12, 0x01]);
    engine.fragment_sent(at(1510));
    // The response has 30 s.
    assert_eq!(engine.next_deadline(), Some(at(31_510)));
    engine.on_time(at(31_510));
    assert_eq!(engine.next_deadline(), None);
    // The engine never asks twice on a link, and the link layer's end
    // releases nothing more.
    engine.on_event(&Event::Disconnected(0x13), at(40_000));
    assert_eq!(engine.take_command(0, at(40_000)), Some(Command::HoldLatency(false)));
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Disconnected(0x13)));
    assert!(!engine.has_output());
}

/// Pairs `engine` with a Linux central at `peer` that is to send its
/// identity keys if `central_id`, up to the encryption; returns the link's
/// epoch and the key.
fn pair(
    engine: &mut Engine,
    device: &mut Device,
    identity: &identity::Local,
    peer: Peer,
    central_id: bool,
) -> (Epoch, [u8; 16]) {
    engine.advertise(true, identity, None, Duration::from_secs(60));
    let job = engine.take_job().unwrap();
    let result = job.run(&mut device.clone(), || ());
    engine.job_done(device, result, at(0));
    engine.connected(&info(peer, None), at(0));
    let epoch = engine.epoch().unwrap();
    let mut central = Central::new(linux_request(central_id, true), local_rpa());
    receive(engine, device, 6, &central.request, at(0));
    drain(engine, 4, at(0));
    receive(engine, device, 6, &central.public_key(), at(0));
    let fragments = drain(engine, 4, at(0));
    let mut reassembly = Reassembly::new();
    let pdus: std::vec::Vec<std::vec::Vec<u8>> = fragments
        .iter()
        .filter_map(|fragment| {
            reassembly.push(fragment.start(), false, fragment.bytes()).map(|pdu| pdu.payload.to_vec())
        })
        .collect();
    central.take_public_key(&pdus[0]);
    central.take_confirm(&pdus[1]);
    let job = engine.take_job().unwrap();
    let result = job.run(&mut device.clone(), || ());
    engine.job_done(device, result, at(0));
    receive(engine, device, 6, &central.random(), at(0));
    let random = drain(engine, 4, at(0));
    central.take_random(&random[0].bytes()[4..]);
    receive(engine, device, 6, &central.check(), at(0));
    drain(engine, 4, at(0));
    engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, at(0));
    let mut ltk = central.ltk;
    ltk.reverse();
    assert_eq!(engine.take_command(0, at(0)), Some(Command::HoldLatency(true)));
    assert_eq!(engine.take_command(0, at(0)), Some(Command::LtkReply { epoch, key: Some(ltk) }));
    engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, at(0));
    (epoch, ltk)
}

#[test]
fn the_bond_is_built_from_the_address_on_the_air_without_the_central_s_identity() {
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(9);
    let identity = identity();
    let peer = Peer::new(CENTRAL_ADDRESS, false);
    let (epoch, ltk) = pair(&mut engine, &mut device, &identity, peer, false);
    // Our identity keys go out, and the bond is made: the central sends
    // none of its own. It is reported only once the central acknowledged
    // them, as the kernel stores its bond only when they arrive.
    assert_eq!(drain(&mut engine, 4, at(0)).len(), 2);
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: false }));
    assert_eq!(engine.take_event(epoch), None);
    assert!(engine.has_output(), "the glue waits for the acknowledgement");
    assert_eq!(engine.take_command(2, at(0)), None);
    assert_eq!(engine.take_event(epoch), None);
    assert_eq!(engine.take_command(0, at(0)), None);
    assert!(!engine.has_output());
    let Some(ConnEvent::Bonded(bond)) = engine.take_event(epoch) else { panic!("no bond") };
    assert!(bond.peer == peer);
    assert_eq!(bond.peer_irk, None);
    assert_eq!(bond.ltk, ltk);
    assert_eq!(bond.local, identity.variant());
}

#[test]
fn an_all_zero_key_from_the_central_is_no_key() {
    // A central without an identity resolving key may send its identity
    // address with an all-zero key: it scans from its identity address.
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(9);
    let identity = identity();
    let (epoch, ltk) = pair(&mut engine, &mut device, &identity, Peer::new(CENTRAL_ADDRESS, false), true);
    // Our identity keys, then the central's.
    assert_eq!(drain(&mut engine, 4, at(0)).len(), 2);
    receive_as(&mut engine, &mut device, 6, &pdu::<17>(IDENTITY_INFORMATION, &[0; 16]), true, at(0));
    let mut address = [IDENTITY_ADDRESS_INFORMATION, 0x00, 0, 0, 0, 0, 0, 0];
    address[2..].copy_from_slice(&CENTRAL_IDENTITY);
    receive_as(&mut engine, &mut device, 6, &address, true, at(0));
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: false }));
    assert_eq!(engine.take_command(0, at(0)), None);
    let Some(ConnEvent::Bonded(bond)) = engine.take_event(epoch) else { panic!("no bond") };
    assert!(bond.peer == Peer::new(CENTRAL_IDENTITY, false));
    assert_eq!(bond.peer_irk, None);
    assert_eq!(bond.ltk, ltk);
    // It is stored and read back, where a key flagged but all zero is
    // refused.
    assert!(Bond::from_bytes(&bond.to_bytes()) == Some(bond.clone()));
    // A reconnection is directed to its identity.
    #[cfg(feature = "directed-advertising")]
    assert!(
        crate::host::adv::Mode::Reconnect(&bond)
            .directs(&crate::host::adv::Phase::directed(crate::host::adv::DIRECTED_MAX))
    );
}

#[test]
fn the_input_reports_are_the_notifying_hid_reports() {
    // The keyboard's, the consumer control's and the mouse's
    // configuration, not the battery's.
    assert_eq!(example::DB.input_reports(), 0b1110);
}
