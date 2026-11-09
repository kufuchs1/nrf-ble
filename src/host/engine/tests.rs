//! Tests of the engine without the async glue: the room its output leaves,
//! the order of its calls of the link layer, and notifications against a
//! PDU of several fragments.

use super::*;
use crate::{
    host::{
        bond::Bond,
        gatt::{AttError, ValueId},
        identity::DeviceSecret,
        smp::tests::{CENTRAL_ADDRESS, CENTRAL_IDENTITY, Central, Device, linux_request, local_rpa},
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
fn identity() -> LocalIdentity {
    LocalIdentity::derive(&Software, &DeviceSecret::new([0x11; 16], [0x22; 16]), Variant::new(0, 1))
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
    let mut pdu = std::vec::Vec::new();
    pdu.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_le_bytes());
    pdu.extend_from_slice(&cid.to_le_bytes());
    pdu.extend_from_slice(payload);
    for (index, chunk) in pdu.chunks(27).enumerate() {
        engine.on_acl(device, &App, &AclIn::for_test(index == 0, false, chunk), now);
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
    let mut engine = Engine::new(&spotlight::DB, Config::SPOTLIGHT);
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
    assert!(engine.notification(epoch, spotlight::BATTERY_LEVEL, &[50]).is_ok());

    let central = Central::new(linux_request(true, true), local_rpa());
    receive(&mut engine, &mut device, 6, &central.request, at(1));
    assert_eq!(drain(&mut engine, 4, at(1)).len(), 1);
    receive(&mut engine, &mut device, 6, &central.public_key(), at(2));
    // The first fragment of our public key is queued: the rest must follow
    // before anything else starts.
    let first = engine.next_fragment(4).unwrap();
    assert!(first.start());
    engine.fragment_sent(at(2));
    assert_eq!(engine.notification(epoch, spotlight::BATTERY_LEVEL, &[50]), Err(NotifyError::Busy));
    let rest = drain(&mut engine, 4, at(2));
    assert_eq!(rest.iter().map(|fragment| (fragment.start(), fragment.bytes().len())).collect::<std::vec::Vec<_>>(), [
        (false, 27),
        (false, 15),
        (true, 21)
    ]);
    let fragment = engine.notification(epoch, spotlight::BATTERY_LEVEL, &[50]).unwrap();
    assert_eq!(fragment.bytes(), [4, 0, 4, 0, 0x1B, 0x0D, 0x00, 50]);
    // The input reports need the encryption the link lacks.
    assert_eq!(engine.notification(epoch, spotlight::KEYBOARD, &[0; 8]), Err(NotifyError::NotSubscribed));
}

#[test]
fn the_parameter_request_leaves_the_last_place_to_responses() {
    let identity = identity();
    let bond = Bond::new(Peer::new(CENTRAL_IDENTITY, false), None, [0x77; 16], identity.variant(), &spotlight::DB);
    let mut engine = Engine::new(&spotlight::DB, Config::SPOTLIGHT);
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
    assert_eq!(engine.next_deadline(), Some(at(510)));
    engine.on_time(at(510));
    assert_eq!(engine.take_command(0, at(510)), Some(Command::HoldLatency(false)));
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

#[test]
fn the_bond_is_built_from_the_address_on_the_air_without_the_central_s_identity() {
    let mut engine = Engine::new(&spotlight::DB, Config::SPOTLIGHT);
    let mut device = Device(9);
    let identity = identity();
    engine.advertise(true, &identity, None, Duration::from_secs(60));
    let job = engine.take_job().unwrap();
    let result = job.run(&mut device.clone(), || ());
    engine.job_done(&mut device, result, at(0));
    let peer = Peer::new(CENTRAL_ADDRESS, false);
    engine.connected(&info(peer, None), at(0));
    let epoch = engine.epoch().unwrap();
    let mut central = Central::new(linux_request(false, true), local_rpa());
    receive(&mut engine, &mut device, 6, &central.request, at(0));
    drain(&mut engine, 4, at(0));
    receive(&mut engine, &mut device, 6, &central.public_key(), at(0));
    let fragments = drain(&mut engine, 4, at(0));
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
    engine.job_done(&mut device, result, at(0));
    receive(&mut engine, &mut device, 6, &central.random(), at(0));
    let random = drain(&mut engine, 4, at(0));
    central.take_random(&random[0].bytes()[4..]);
    receive(&mut engine, &mut device, 6, &central.check(), at(0));
    drain(&mut engine, 4, at(0));
    engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, at(0));
    let mut ltk = central.ltk;
    ltk.reverse();
    assert_eq!(engine.take_command(0, at(0)), Some(Command::HoldLatency(true)));
    assert_eq!(engine.take_command(0, at(0)), Some(Command::LtkReply { epoch, key: Some(ltk) }));
    engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, at(0));
    // Our identity keys go out, and the bond is made: the central sends
    // none of its own.
    assert_eq!(drain(&mut engine, 4, at(0)).len(), 2);
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: false }));
    let Some(ConnEvent::Bonded(bond)) = engine.take_event(epoch) else { panic!("no bond") };
    assert!(bond.peer == peer);
    assert_eq!(bond.peer_irk, None);
    assert_eq!(bond.ltk, ltk);
    assert_eq!(bond.local, identity.variant());
}
