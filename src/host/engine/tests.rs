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
        directed: false,
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

/// The Write Request that enables the battery level's notifications.
fn enable_battery() -> [u8; 5] {
    let [handle0, handle1] = (example::BATTERY_LEVEL.handle() + 1).to_le_bytes();
    [0x12, handle0, handle1, 0x01, 0x00]
}

/// The battery level's notification of 50 %, as its one fragment.
fn battery_50() -> [u8; 8] {
    let [handle0, handle1] = example::BATTERY_LEVEL.handle().to_le_bytes();
    [4, 0, 4, 0, 0x1B, handle0, handle1, 50]
}

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
    receive(&mut engine, &mut device, 4, &enable_battery(), at(0));
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
    assert_eq!(fragment.bytes(), battery_50());
    // The input reports need the encryption the link lacks.
    assert_eq!(engine.notification(epoch, example::KEYBOARD, &[0; 8]), Err(NotifyError::NotSubscribed));
}

/// With `att-mtu` an ATT response of more than 23 octets takes several
/// fragments, and a notification waits for the last of them as it does for
/// a public key.
#[cfg(feature = "att-mtu")]
#[test]
fn a_notification_never_interleaves_with_the_fragments_of_a_long_response() {
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(5);
    engine.connected(&info(Peer::new(CENTRAL_ADDRESS, false), None), at(0));
    receive(&mut engine, &mut device, 4, &enable_battery(), at(0));
    assert_eq!(drain(&mut engine, 4, at(0)).len(), 1);
    let epoch = engine.epoch().unwrap();
    receive(&mut engine, &mut device, 4, &[0x02, 0x05, 0x02], at(1));
    let answer = drain(&mut engine, 4, at(1));
    assert_eq!(answer.iter().map(Fragment::bytes).collect::<std::vec::Vec<_>>(), [[3, 0, 4, 0, 0x03, 0x41, 0x00]]);
    // Find Information over the whole table: 15 entries, 62 octets, in
    // three fragments.
    receive(&mut engine, &mut device, 4, &[0x04, 0x01, 0x00, 0xFF, 0xFF], at(2));
    let first = engine.next_fragment(4).unwrap();
    assert!(first.start());
    assert_eq!(first.bytes()[..6], [62, 0, 4, 0, 0x05, 0x01]);
    engine.fragment_sent(at(2));
    assert_eq!(engine.notification(epoch, example::BATTERY_LEVEL, &[50]), Err(NotifyError::Busy));
    let second = engine.next_fragment(4).unwrap();
    engine.fragment_sent(at(2));
    assert_eq!(engine.notification(epoch, example::BATTERY_LEVEL, &[50]), Err(NotifyError::Busy));
    let rest = drain(&mut engine, 4, at(2));
    assert_eq!(
        [&first, &second]
            .into_iter()
            .chain(&rest)
            .map(|fragment| (fragment.start(), fragment.bytes().len()))
            .collect::<std::vec::Vec<_>>(),
        [(true, 27), (false, 27), (false, 12)]
    );
    let fragment = engine.notification(epoch, example::BATTERY_LEVEL, &[50]).unwrap();
    assert_eq!(fragment.bytes(), battery_50());
}

#[test]
fn a_received_pdu_leaves_no_copy_in_the_reassembly_buffer() {
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(9);
    let identity = identity();
    engine.advertise(true, &identity, None, Duration::from_secs(60));
    engine.connected(&info(Peer::new(CENTRAL_ADDRESS, false), None), at(0));
    let central = Central::new(linux_request(true, true), local_rpa());
    receive(&mut engine, &mut device, 6, &central.request, at(0));
    assert_eq!(engine.rx.buffer(), &[0; RX_MAX]);
    // The central's public key, in three fragments.
    receive(&mut engine, &mut device, 6, &central.public_key(), at(0));
    assert_eq!(engine.rx.buffer(), &[0; RX_MAX]);
}

#[test]
fn the_parameter_request_leaves_the_last_place_to_responses() {
    let identity = identity();
    let bond = Bond::new(
        IdentityAddress::valid(Peer::new(CENTRAL_IDENTITY, false)),
        None,
        [0x77; 16],
        identity.variant(),
        &example::DB,
    );
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
    assert_eq!(engine.take_command(0, at(0)), Some(Command::HoldLatency(true)));
    (epoch, pair_link(engine, device, central_id, at(0)))
}

/// Pairs the link of `engine` with a Linux central at the link's address on
/// the air that is to send its identity keys if `central_id`, at `now`, up to
/// the encryption; returns the key.
fn pair_link(engine: &mut Engine, device: &mut Device, central_id: bool, now: Instant) -> [u8; 16] {
    let epoch = engine.epoch().unwrap();
    let mut central = Central::new(linux_request(central_id, true), local_rpa());
    if let Some(link) = engine.link.as_ref() {
        central.address = link.info.peer;
    }
    receive(engine, device, 6, &central.request, now);
    drain(engine, 4, now);
    receive(engine, device, 6, &central.public_key(), now);
    let fragments = drain(engine, 4, now);
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
    engine.job_done(device, result, now);
    receive(engine, device, 6, &central.random(), now);
    let random = drain(engine, 4, now);
    central.take_random(&random[0].bytes()[4..]);
    receive(engine, device, 6, &central.check(), now);
    drain(engine, 4, now);
    engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, now);
    let mut ltk = central.ltk;
    ltk.reverse();
    assert_eq!(engine.take_command(0, now), Some(Command::LtkReply { epoch, key: Some(ltk) }));
    engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, now);
    ltk
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
    assert!(bond.peer.peer() == peer);
    assert_eq!(bond.peer_irk, None);
    assert_eq!(bond.ltk, ltk);
    assert_eq!(bond.local, identity.variant());
}

#[test]
fn a_central_on_a_private_address_without_an_identity_gets_no_bond() {
    // A resolvable private address changes, so a bond with it would never
    // find the central again; one stored would not be read back.
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(9);
    let identity = identity();
    let rpa = Peer::new([1, 2, 3, 4, 5, 0x45], true);
    let (epoch, _ltk) = pair(&mut engine, &mut device, &identity, rpa, false);
    // Our identity keys go out, the central sends none.
    assert_eq!(drain(&mut engine, 4, at(0)).len(), 2);
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: false }));
    assert_eq!(engine.take_command(0, at(0)), None);
    assert_eq!(engine.take_event(epoch), None, "no bond is reported");
    assert!(engine.bond().is_none());
    // The link stays, encrypted with the pairing's key.
    assert_eq!(engine.epoch(), Some(epoch));
    assert_eq!(engine.security(epoch), Some(Sec::Encrypted));
}

#[test]
fn an_all_zero_identity_address_is_no_identity_address() {
    // The central's identity address is dropped with its key: from a private
    // address on the air, the pairing makes no bond.
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(9);
    let identity = identity();
    let (epoch, _ltk) = pair(&mut engine, &mut device, &identity, Peer::new([1, 2, 3, 4, 5, 0x45], true), true);
    assert_eq!(drain(&mut engine, 4, at(0)).len(), 2);
    receive_as(&mut engine, &mut device, 6, &pdu::<17>(IDENTITY_INFORMATION, &[0x5A; 16]), true, at(0));
    receive_as(&mut engine, &mut device, 6, &[IDENTITY_ADDRESS_INFORMATION, 0x00, 0, 0, 0, 0, 0, 0], true, at(0));
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: false }));
    assert_eq!(engine.take_command(0, at(0)), None);
    assert_eq!(engine.take_event(epoch), None, "no bond is reported");
    assert!(engine.bond().is_none());
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
    assert!(bond.peer.peer() == Peer::new(CENTRAL_IDENTITY, false));
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

/// A Write Request of `features` to the Client Supported Features.
#[cfg(feature = "eatt")]
fn write_features(features: &[u8]) -> std::vec::Vec<u8> {
    let [handle0, handle1] = example::CLIENT_FEATURES.to_le_bytes();
    [&[0x12, handle0, handle1][..], features].concat()
}

/// The ATT PDUs among `fragments`, each a fragment of its own.
#[cfg(feature = "eatt")]
fn att_pdus(fragments: &[Fragment]) -> std::vec::Vec<std::vec::Vec<u8>> {
    fragments
        .iter()
        .filter(|fragment| fragment.bytes()[2..4] == [4, 0])
        .map(|fragment| fragment.bytes()[4..].to_vec())
        .collect()
}

/// A reconnection of the bonded central of `bond`, up to the long term key
/// request answered with its key; returns the engine and the link's epoch.
#[cfg(feature = "eatt")]
fn reconnect(bond: Bond) -> (Engine, Epoch) {
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    engine.advertise(false, &identity(), Some(bond), Duration::from_secs(20));
    engine.connected(&info(Peer::new([3; 6], true), Some(Peer::new(CENTRAL_IDENTITY, false))), at(0));
    let epoch = engine.epoch().unwrap();
    engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, at(0));
    assert_eq!(engine.take_command(0, at(0)), Some(Command::HoldLatency(true)));
    assert_eq!(engine.take_command(0, at(0)), Some(Command::LtkReply { epoch, key: Some([0x77; 16]) }));
    (engine, epoch)
}

/// The bond of [`reconnect`], with the Client Supported Features
/// `features`.
#[cfg(feature = "eatt")]
fn bond_with_features(features: u8) -> Bond {
    let mut bond = Bond::new(
        IdentityAddress::valid(Peer::new(CENTRAL_IDENTITY, false)),
        None,
        [0x77; 16],
        identity().variant(),
        &example::DB,
    );
    bond.client_features = features;
    bond
}

/// The Client Supported Features a client writes during pairing go into
/// the bond, before or after it is made.
#[cfg(feature = "eatt")]
#[test]
fn the_bond_takes_the_client_features_written_while_pairing() {
    for before in [true, false] {
        let mut engine = Engine::new(&example::DB, example::CONFIG);
        let mut device = Device(9);
        let identity = identity();
        let (epoch, _) = pair(&mut engine, &mut device, &identity, Peer::new(CENTRAL_ADDRESS, false), false);
        if before {
            // Before encryption, as BlueZ writes them once the MTU is
            // agreed: open, so taken.
            receive(&mut engine, &mut device, 4, &write_features(&[0x05]), at(0));
        }
        let fragments = drain(&mut engine, 4, at(0));
        if !before {
            receive_as(&mut engine, &mut device, 4, &write_features(&[0x07]), true, at(0));
        }
        let fragments = [fragments, drain(&mut engine, 4, at(0))].concat();
        assert_eq!(att_pdus(&fragments), [[0x13]]);
        assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: false }));
        assert_eq!(engine.take_command(0, at(0)), None);
        let Some(ConnEvent::Bonded(bond)) = engine.take_event(epoch) else { panic!("no bond") };
        assert_eq!(bond.client_features, if before { 0x05 } else { 0x07 });
        assert_eq!(engine.take_event(epoch), None, "no update besides the bond");
        assert!(Bond::from_bytes(&bond.to_bytes()) == Some(bond.clone()));
    }
}

/// On a reconnection the bond's features join those written before the
/// encryption, and only a change updates the bond.
#[cfg(feature = "eatt")]
#[test]
fn a_reconnection_adds_the_bond_s_client_features_and_stores_only_changes() {
    let mut device = Device(9);
    // The bond has Robust Caching; before the encryption the client writes
    // Multiple Handle Value Notifications, which is taken.
    let (mut engine, epoch) = reconnect(bond_with_features(0x01));
    receive(&mut engine, &mut device, 4, &write_features(&[0x04]), at(5));
    assert_eq!(att_pdus(&drain(&mut engine, 4, at(5))), [[0x13]]);
    assert_eq!(engine.take_event(epoch), None, "nothing stored before the encryption");
    engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, at(10));
    assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: true }));
    let Some(ConnEvent::BondUpdated(bond)) = engine.take_event(epoch) else { panic!("no update") };
    assert_eq!(bond.client_features, 0x05);
    assert_eq!(engine.take_event(epoch), None);
    let [handle0, handle1] = example::CLIENT_FEATURES.to_le_bytes();
    receive_as(&mut engine, &mut device, 4, &[0x0A, handle0, handle1], true, at(20));
    assert_eq!(att_pdus(&drain(&mut engine, 4, at(20))), [[0x0B, 0x05]]);
    // The same value again changes nothing to store.
    receive_as(&mut engine, &mut device, 4, &write_features(&[0x05]), true, at(30));
    assert_eq!(att_pdus(&drain(&mut engine, 4, at(30))), [[0x13]]);
    assert_eq!(engine.take_event(epoch), None);
    // Clearing a bit is refused, and stores nothing either.
    receive_as(&mut engine, &mut device, 4, &write_features(&[0x04]), true, at(40));
    assert_eq!(att_pdus(&drain(&mut engine, 4, at(40))), [[0x01, 0x12, handle0, handle1, 0x13]]);
    assert_eq!(engine.take_event(epoch), None);
    // A new bit is stored.
    receive_as(&mut engine, &mut device, 4, &write_features(&[0x07]), true, at(50));
    assert_eq!(att_pdus(&drain(&mut engine, 4, at(50))), [[0x13]]);
    let Some(ConnEvent::BondUpdated(bond)) = engine.take_event(epoch) else { panic!("no update") };
    assert_eq!(bond.client_features, 0x07);
    assert_eq!(engine.bond().map(|bond| bond.client_features), Some(0x07));
}

/// BlueZ writes its features on every connection, after the encryption on
/// a bonded reconnection: the bond's value again stores nothing, and a
/// value with fewer bits, after BlueZ went back to one channel, is refused.
#[cfg(feature = "eatt")]
#[test]
fn bluez_writing_the_bond_s_client_features_again_stores_nothing() {
    for (bond_features, written, answer) in [(0x05, 0x05, &[0x13][..]), (0x07, 0x05, &[0x01, 0x12, 0, 0, 0x13][..])] {
        let mut device = Device(9);
        let (mut engine, epoch) = reconnect(bond_with_features(bond_features));
        engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, at(10));
        assert_eq!(engine.take_event(epoch), Some(ConnEvent::Encrypted { bonded: true }));
        assert_eq!(engine.take_event(epoch), None, "the restored features are the bond's");
        receive_as(&mut engine, &mut device, 4, &write_features(&[written]), true, at(20));
        let mut expected = answer.to_vec();
        if expected.len() > 1 {
            expected[2..4].copy_from_slice(&example::CLIENT_FEATURES.to_le_bytes());
        }
        assert_eq!(att_pdus(&drain(&mut engine, 4, at(20))), [expected]);
        assert_eq!(engine.take_event(epoch), None);
        assert_eq!(engine.bond().map(|bond| bond.client_features), Some(bond_features));
    }
}

#[cfg(feature = "eatt")] mod bearers;
#[cfg(feature = "eatt")] mod sim;
