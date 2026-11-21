//! The enhanced bearers wired into the engine, against the simulated `BlueZ`
//! 5.88 and Linux 7.3 central of [`super::sim`]: every `[GATT] Channels`
//! value, the hold until the encryption, the refusal for security and
//! Linux's single requests after it, concurrent requests, K-frames and
//! credits, the closes, and the link's end. Each runs with the bearers the
//! build has ([`BEARERS`]).

extern crate std;

use super::{
    sim::{ChanState, Kernel, On, Sim},
    *,
};
use crate::host::ecfc::{CLOSE_TIMEOUT, HOLD_MAX, RX_CREDITS, TOP_UP};
use std::{vec, vec::Vec};

/// A Read Request of the Client Supported Features, whose response is
/// `[0x0B, features]`.
fn read_features() -> Vec<u8> {
    let [handle0, handle1] = example::CLIENT_FEATURES.to_le_bytes();
    vec![0x0A, handle0, handle1]
}

/// A Read Request of the Report Map, whose response fills an ATT MTU of 65.
fn read_report_map() -> Vec<u8> {
    let [handle0, handle1] = (example::KEYBOARD.handle() - 4).to_le_bytes();
    vec![0x0A, handle0, handle1]
}

/// The Write Request that enables the notifications of `characteristic`.
fn enable(characteristic: Char) -> Vec<u8> {
    let [handle0, handle1] = (characteristic.handle() + 1).to_le_bytes();
    vec![0x12, handle0, handle1, 0x01, 0x00]
}

/// The number of bearers a request for `count` gets.
fn granted(count: usize) -> usize { count.min(BEARERS) }

/// The destination CIDs of `count` single or ascending requests: ours in
/// order, then 0.
fn dcids(count: usize) -> Vec<u16> {
    (0..count).map(|bearer| if bearer < BEARERS { 0x0040 + bearer as u16 } else { 0 }).collect()
}

/// The results and destination CIDs of our responses.
fn answers(sim: &Sim) -> Vec<(u16, Vec<u16>)> {
    sim.responses().into_iter().map(|(_, result, dcids)| (result, dcids)).collect()
}

/// Every bearer of the central, and the fixed channel, serves a request at
/// once, each answered on its own bearer.
fn serve_on_every_bearer(sim: &mut Sim) {
    let bearers = sim.kernel.bearers();
    let before = sim.kernel.responses.len();
    for &scid in &bearers {
        sim.kernel.request_on(On::Chan(scid), &read_features());
    }
    sim.kernel.request_on(On::Fixed, &read_report_map());
    sim.pump();
    let responses = &sim.kernel.responses[before..];
    assert_eq!(responses.len(), bearers.len() + 1);
    for &scid in &bearers {
        let mine: Vec<_> = responses.iter().filter(|(on, ..)| *on == On::Chan(scid)).collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].2, [0x0B, sim.engine.att.client_features()]);
    }
    let fixed: Vec<_> = responses.iter().filter(|(on, ..)| *on == On::Fixed).collect();
    let map = &fixed[0].2;
    assert_eq!(map[0], 0x0B);
    assert_eq!(map[1..], example::REPORT_MAP[..map.len() - 1]);
}

/// The events waiting.
fn events(sim: &mut Sim) -> Vec<ConnEvent> {
    let mut events = Vec::new();
    while let Some(event) = sim.engine.take_event(sim.epoch) {
        events.push(event);
    }
    events
}

/// A paired first connection with `Channels` = 2: the bearer's request
/// comes once discovery is over, on the encrypted link, and is answered at
/// once. The input reports' configuration that completes on the bearer
/// makes the link ready, and reports go on CID 4.
#[test]
fn channels_2_after_pairing_opens_one_bearer_and_reports_go_on_cid_4() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.request(&[0x02, 0x05, 0x02]);
    sim.kernel.request(&write_features(&[0x07]));
    sim.pump();
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(answers(&sim), [(0x0000, vec![0x0040])]);
    assert_eq!(sim.bound(), [(0x0040, 0x0040)]);
    assert!(sim.kernel.settled() && !sim.kernel.escalated);
    for characteristic in [example::KEYBOARD, example::CONSUMER, example::MOUSE] {
        sim.kernel.request(&enable(characteristic));
    }
    sim.pump();
    let writes: Vec<_> = sim.kernel.responses.iter().filter(|(_, request, _)| request[0] == 0x12).skip(1).collect();
    assert_eq!(writes.len(), 3);
    // The bearer first, then CID 4 while the bearer is busy; the third,
    // which completes the configuration, on the bearer again.
    assert_eq!(writes.iter().map(|(on, _, response)| (*on, response.clone())).collect::<Vec<_>>()[2..], [(
        On::Chan(0x0040),
        vec![0x13]
    )]);
    assert!(writes.iter().any(|(on, ..)| *on == On::Fixed));
    assert!(!events(&mut sim).contains(&ConnEvent::Ready));
    sim.advance(INPUTS_IDLE.as_millis() + 10);
    assert!(events(&mut sim).contains(&ConnEvent::Ready));
    let report = sim.engine.notification(sim.epoch, example::KEYBOARD, &[0; 8]).unwrap();
    assert_eq!(report.bytes()[2..5], [0x04, 0x00, 0x1B]);
}

/// A bonded reconnection with `Channels` = 2: `BlueZ` asks for the bearer
/// before the link is encrypted, the request is held, and answered with
/// success once the central encrypted; Linux never escalates.
#[test]
fn channels_2_on_a_reconnection_holds_the_request_until_the_encryption() {
    let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::linux());
    sim.kernel.connect_eatt(2);
    sim.pump();
    sim.advance(HOLD_MAX.as_millis() / 2);
    assert_eq!(answers(&sim), []);
    assert_eq!(sim.engine.next_deadline(), Some(at(HOLD_MAX.as_millis())));
    sim.encrypt();
    assert_eq!(answers(&sim), [(0x0000, vec![0x0040])]);
    assert!(sim.kernel.settled() && !sim.kernel.escalated);
    assert_eq!(sim.engine.next_deadline(), Some(at(sim.now + READY_IDLE.as_millis())));
    serve_on_every_bearer(&mut sim);
}

/// The key request answered, the hold waits past its 2 s for the
/// encryption, which then answers it.
#[test]
fn a_hold_waits_for_an_encryption_under_way() {
    let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::linux());
    sim.kernel.connect_eatt(2);
    sim.pump();
    let now = sim.at();
    sim.engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, now);
    assert!(matches!(sim.engine.take_command(0, now), Some(Command::LtkReply { epoch: _, key: Some(_) })));
    sim.advance(HOLD_MAX.as_millis() + 500);
    assert_eq!(answers(&sim), []);
    sim.engine.on_event(&Event::Encryption { on: true, refresh: false, status: 0 }, sim.at());
    assert!(sim.engine.has_output(), "the answer waits for room in the link layer's queue");
    sim.kernel.encrypted();
    sim.pump();
    assert_eq!(answers(&sim), [(0x0000, vec![0x0040])]);
    assert!(sim.kernel.settled() && !sim.kernel.escalated);
}

/// A pairing under way keeps the hold past its 2 s too: the request is not
/// refused while the central pairs.
#[test]
fn a_hold_waits_for_a_pairing_under_way() {
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(9);
    engine.advertise(true, &identity(), None, Duration::from_secs(60));
    let job = engine.take_job().unwrap();
    let result = job.run(&mut device.clone(), || ());
    engine.job_done(&mut device, result, at(0));
    engine.connected(&info(Peer::new(CENTRAL_ADDRESS, false), None), at(0));
    let epoch = engine.epoch().unwrap();
    let mut sim = Sim { device, engine, epoch, kernel: Kernel::linux(), now: 0 };
    sim.kernel.connect_eatt(2);
    sim.pump();
    let central = Central::new(linux_request(false, true), local_rpa());
    let now = sim.at();
    receive(&mut sim.engine, &mut sim.device, 6, &central.request, now);
    assert!(sim.engine.smp.is_pairing());
    sim.advance(HOLD_MAX.as_millis() + 500);
    assert_eq!(answers(&sim), []);
    assert_eq!(sim.engine.ecfc.deadline(), None);
}

/// A request that itself arrives encrypted, once the bond's key went to the
/// link layer and before the encryption event, proves the encryption and is
/// answered at once; one that arrives marked encrypted before any key went
/// is no proof and is held.
#[test]
fn an_encrypted_request_with_the_host_s_key_is_not_held() {
    for key in [true, false] {
        let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::linux());
        if key {
            let now = sim.at();
            sim.engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, now);
            assert!(matches!(sim.engine.take_command(0, now), Some(Command::LtkReply { epoch: _, key: Some(_) })));
        }
        sim.kernel.encrypted = true;
        sim.kernel.connect_eatt(2);
        sim.pump();
        if key {
            assert_eq!(answers(&sim), [(0x0000, vec![0x0040])]);
            assert_eq!(sim.bound(), [(0x0040, 0x0040)]);
            assert_eq!(sim.engine.ecfc.deadline(), None);
        } else {
            assert_eq!(answers(&sim), []);
            assert_eq!(sim.engine.ecfc.deadline(), Some(at(HOLD_MAX.as_millis())));
        }
        assert!(events(&mut sim).is_empty(), "no encryption event yet");
    }
}

/// A held request is answered by the first ATT PDU that arrives encrypted
/// with the bond's key, before the encryption event.
#[test]
fn an_encrypted_att_pdu_answers_the_held_request() {
    let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::linux());
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(answers(&sim), []);
    let now = sim.at();
    sim.engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, now);
    assert!(matches!(sim.engine.take_command(0, now), Some(Command::LtkReply { epoch: _, key: Some(_) })));
    sim.kernel.encrypted();
    sim.kernel.request_on(On::Fixed, &read_features());
    sim.pump();
    assert_eq!(answers(&sim), [(0x0000, vec![0x0040])]);
    assert!(sim.kernel.settled() && !sim.kernel.escalated);
    assert_eq!(sim.engine.ecfc.deadline(), None);
    assert!(events(&mut sim).is_empty(), "no encryption event yet");
    serve_on_every_bearer(&mut sim);
}

/// The central closes a bearer whose response waits for a credit: the
/// response is dropped, the input reports' configuration it completed
/// counts as open again, and a new channel on the same CID gets nothing of
/// it. The configuration written again on CID 4 then makes the link ready
/// after [`INPUTS_IDLE`].
#[test]
fn a_close_drops_a_response_waiting_for_credits() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.credits = 1;
    sim.kernel.hold_credits = true;
    sim.kernel.connect_eatt(2);
    sim.pump();
    sim.kernel.request_on(On::Chan(0x0040), &enable(example::KEYBOARD));
    sim.kernel.request_on(On::Fixed, &enable(example::CONSUMER));
    sim.pump();
    assert_eq!(sim.kernel.responses.len(), 2);
    // The bearer has no credit left for the response that completes the
    // configuration.
    sim.kernel.request_on(On::Chan(0x0040), &enable(example::MOUSE));
    sim.pump();
    assert!(sim.engine.eatt_responses[0].is_some());
    assert_eq!(
        sim.engine.link.as_ref().map(|link| link.inputs),
        Some(Inputs::Answering(AttSlot::Eatt(BearerId::FIRST)))
    );
    sim.kernel.close(0x0040);
    sim.pump();
    assert!(sim.engine.response.is_none() && sim.engine.eatt_responses.iter().all(Option::is_none));
    assert_eq!(sim.engine.link.as_ref().map(|link| link.inputs), Some(Inputs::Open));
    assert!(sim.kernel.chans.is_empty() && !sim.engine.has_output());
    // A new channel on the same CID, with credits: no stale response.
    sim.kernel.credits = 3;
    sim.kernel.hold_credits = false;
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(sim.bound(), [(0x0040, 0x0040)]);
    assert_eq!(sim.kernel.responses.len(), 2);
    sim.kernel.request_on(On::Fixed, &enable(example::MOUSE));
    sim.pump();
    assert_eq!(
        sim.kernel.responses.last().map(|(on, _, response)| (*on, response.clone())),
        Some((On::Fixed, vec![0x13]))
    );
    sim.advance(INPUTS_IDLE.as_millis() + 10);
    assert!(events(&mut sim).contains(&ConnEvent::Ready));
    serve_on_every_bearer(&mut sim);
}

/// `Channels` = 3 to 6 on a reconnection: Linux's request names 2 to 5
/// source CIDs, the newest first, and is held; after the encryption it is
/// refused with 0x0004 and every destination CID 0, and Linux deletes each
/// channel at once: none waits for the 40 s timeout, and CID 4 serves on.
#[test]
fn channels_3_to_6_on_a_reconnection_are_refused_after_the_encryption() {
    for channels in 3..=6 {
        let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::linux());
        sim.kernel.connect_eatt(channels);
        sim.pump();
        assert_eq!(answers(&sim), []);
        sim.encrypt();
        assert_eq!(answers(&sim), [(0x0004, vec![0; channels - 1])], "Channels = {channels}");
        assert!(sim.kernel.settled() && !sim.kernel.escalated);
        assert_eq!(sim.bound(), []);
        assert_eq!(sim.kernel.deleted, channels - 1);
        serve_on_every_bearer(&mut sim);
    }
}

/// `Channels` = 3 to 6 after pairing, on an encrypted link: the request is
/// refused at once.
#[test]
fn channels_3_to_6_after_pairing_are_refused_at_once() {
    for channels in 3..=6 {
        let mut sim = Sim::paired(Kernel::linux());
        sim.kernel.connect_eatt(channels);
        sim.pump();
        assert_eq!(answers(&sim), [(0x0004, vec![0; channels - 1])], "Channels = {channels}");
        assert!(sim.kernel.settled() && sim.kernel.deleted == channels - 1);
    }
}

/// `Channels` = 1 opens no bearer: `BlueZ` sends no request, and the
/// engine has no deadline of the bearers.
#[test]
fn channels_1_opens_nothing() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.connect_eatt(1);
    sim.pump();
    assert_eq!(answers(&sim), []);
    assert_eq!(sim.engine.ecfc.deadline(), None);
    serve_on_every_bearer(&mut sim);
}

/// A reconnection that stays unencrypted for 2 s with nothing under way:
/// Linux's request, of 1 to 5 source CIDs, is refused for security (0x0008,
/// the bonded central) while the link is still unencrypted; Linux encrypts
/// and sends one request for each channel, all before our first answer,
/// which open as many bearers as the build has, each correctly wired, and
/// the rest are refused with 0x0004. None is left waiting.
#[test]
fn a_refusal_for_security_opens_a_bearer_for_each_single_request() {
    for channels in 2..=6 {
        let count = channels - 1;
        let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::linux());
        sim.kernel.connect_eatt(channels);
        sim.pump();
        sim.advance(HOLD_MAX.as_millis() + 10);
        assert_eq!(answers(&sim), [(0x0008, vec![0; count])], "Channels = {channels}");
        assert!(sim.kernel.escalated);
        sim.encrypt();
        let answers = answers(&sim)[1..].to_vec();
        assert_eq!(answers.len(), count, "one request for each channel");
        for (index, (result, dcids)) in answers.iter().enumerate() {
            let expected = if index < BEARERS { (0x0000, vec![0x0040 + index as u16]) } else { (0x0004, vec![0]) };
            assert_eq!((*result, dcids.clone()), expected, "Channels = {channels}, request {index}");
        }
        assert!(sim.kernel.settled() && !sim.kernel.escalated);
        assert_eq!(sim.bound().len(), granted(count));
        assert_eq!(sim.kernel.deleted, count - granted(count));
        serve_on_every_bearer(&mut sim);
    }
}

/// The same on a first connection that is not paired: the refusal says
/// Insufficient Authentication (0x0005), Linux pairs with Just Works, and its
/// single requests follow.
#[test]
fn a_refusal_for_security_without_a_bond_lets_linux_pair_first() {
    let mut engine = Engine::new(&example::DB, example::CONFIG);
    let mut device = Device(9);
    engine.advertise(true, &identity(), None, Duration::from_secs(60));
    let job = engine.take_job().unwrap();
    let result = job.run(&mut device.clone(), || ());
    engine.job_done(&mut device, result, at(0));
    engine.connected(&info(Peer::new(CENTRAL_ADDRESS, false), None), at(0));
    let epoch = engine.epoch().unwrap();
    let mut sim = Sim { device, engine, epoch, kernel: Kernel::linux(), now: 0 };
    sim.kernel.connect_eatt(6);
    sim.pump();
    sim.advance(HOLD_MAX.as_millis() + 10);
    assert_eq!(answers(&sim), [(0x0005, vec![0; 5])]);
    let now = sim.at();
    pair_link(&mut sim.engine, &mut sim.device, false, now);
    sim.kernel.encrypted();
    sim.pump();
    let expected: Vec<_> =
        (0..5).map(|index| (if index < BEARERS { 0 } else { 4 }, dcids(index + 1)[index..].to_vec())).collect();
    assert_eq!(answers(&sim)[1..], expected[..]);
    assert!(sim.kernel.settled());
    assert_eq!(sim.bound().len(), granted(5));
    serve_on_every_bearer(&mut sim);
}

/// A spec-correct central asks for all of its channels in one ascending
/// request: it gets as many bearers as the build has, our CIDs in order, the
/// rest 0 with 0x0004; then the fixed channel and every bearer serve a
/// request each at the same time.
#[test]
fn an_ascending_request_gets_every_bearer_there_is() {
    for count in 1..=5 {
        let mut sim = Sim::paired(Kernel::spec());
        sim.kernel.connect_eatt(count + 1);
        sim.pump();
        let result = if count <= BEARERS { 0x0000 } else { 0x0004 };
        assert_eq!(answers(&sim), [(result, dcids(count))], "{count} source CIDs");
        assert_eq!(
            sim.bound(),
            (0..granted(count)).map(|index| (0x0040 + index as u16, 0x0040 + index as u16)).collect::<Vec<_>>()
        );
        assert!(sim.kernel.settled());
        serve_on_every_bearer(&mut sim);
    }
}

/// Requests on CID 4 and on every bearer at once, with the configuration of
/// the input reports among them: each is answered on its own bearer, and
/// the link becomes ready once the write that completed it was answered,
/// whichever bearer carried it.
#[test]
fn concurrent_requests_are_each_answered_on_their_bearer() {
    let mut sim = Sim::paired(Kernel::spec());
    sim.kernel.connect_eatt(BEARERS + 1);
    sim.pump();
    assert_eq!(sim.bound().len(), BEARERS);
    let mut bearers: Vec<On> = sim.kernel.bearers().into_iter().map(On::Chan).collect();
    bearers.push(On::Fixed);
    let writes = [enable(example::KEYBOARD), enable(example::CONSUMER), enable(example::MOUSE)];
    for (index, on) in bearers.iter().enumerate() {
        let request = writes.get(index).cloned().unwrap_or_else(read_features);
        sim.kernel.request_on(*on, &request);
    }
    for request in writes.iter().skip(bearers.len()) {
        sim.kernel.request(request);
    }
    sim.pump();
    for on in &bearers {
        assert!(sim.kernel.responses.iter().any(|(answered, ..)| answered == on), "{on:?}");
    }
    assert_eq!(sim.kernel.responses.iter().filter(|(_, request, _)| request[0] == 0x12).count(), 3);
    sim.advance(INPUTS_IDLE.as_millis() + 10);
    assert!(events(&mut sim).contains(&ConnEvent::Ready));
}

/// The responses of several bearers take turns: one K-frame each, from the
/// bearer after the one served last.
#[test]
fn the_bearers_take_turns() {
    if BEARERS < 2 {
        return;
    }
    let mut sim = Sim::paired(Kernel::spec());
    sim.kernel.mps = 64;
    sim.kernel.connect_eatt(BEARERS + 1);
    sim.pump();
    for scid in sim.kernel.bearers() {
        sim.kernel.request_on(On::Chan(scid), &read_report_map());
    }
    sim.deliver();
    let now = sim.at();
    let fragments = drain(&mut sim.engine, 4, now);
    // Each response is two K-frames to the bearer's CID: 64 octets in three
    // fragments, then 3 in one.
    let starts: Vec<(u16, usize)> = fragments
        .iter()
        .filter(|fragment| fragment.start())
        .map(|fragment| {
            (u16::from_le_bytes([fragment.bytes()[2], fragment.bytes()[3]]), usize::from(fragment.bytes()[0]))
        })
        .collect();
    // From the bearer after bearer 0, which counts as served last.
    let order = (1..=BEARERS).map(|step| 0x0040 + (step % BEARERS) as u16);
    let first: Vec<_> = order.clone().map(|cid| (cid, 64)).collect();
    let second: Vec<_> = order.map(|cid| (cid, 3)).collect();
    assert_eq!(starts, [first, second].concat());
    for fragment in &fragments {
        sim.kernel.receive(fragment);
    }
    assert_eq!(sim.kernel.responses.len(), BEARERS);
}

/// With the peer's MPS of 64 a response of 65 octets goes in two K-frames,
/// 2 + 62 and 3 octets, each taking a credit; a notification may go between
/// them, but not inside the first, which takes three fragments.
#[test]
fn an_mps_of_64_splits_a_response_with_a_notification_between() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.mps = 64;
    sim.kernel.request(&enable(example::BATTERY_LEVEL));
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(sim.kernel.chans[0].rx_credits, 3);
    sim.kernel.request_on(On::Chan(0x0040), &read_report_map());
    sim.deliver();
    let now = sim.at();
    let mut first = Vec::new();
    for _ in 0..3 {
        first.push(sim.engine.next_fragment(4).unwrap());
        sim.engine.fragment_sent(now);
        if first.len() < 3 {
            assert_eq!(sim.engine.notification(sim.epoch, example::BATTERY_LEVEL, &[50]), Err(NotifyError::Busy));
        }
    }
    assert_eq!(first.iter().map(|fragment| fragment.bytes().len()).collect::<Vec<_>>(), [27, 27, 14]);
    assert_eq!(first[0].bytes()[..6], [64, 0, 0x40, 0x00, 65, 0]);
    let notification = sim.engine.notification(sim.epoch, example::BATTERY_LEVEL, &[50]).unwrap();
    assert_eq!(notification.bytes()[2..4], [4, 0]);
    let second = drain(&mut sim.engine, 4, now);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].bytes()[..4], [3, 0, 0x40, 0x00]);
    for fragment in first.iter().chain([&notification]).chain(&second) {
        sim.kernel.receive(fragment);
    }
    let (on, _, response) = sim.kernel.responses.last().unwrap();
    assert_eq!(*on, On::Chan(0x0040));
    assert_eq!(response[..], [&[0x0B][..], &example::REPORT_MAP[..64]].concat()[..]);
    assert_eq!(sim.kernel.chans[0].rx_credits, 1, "a credit for each K-frame");
    assert_eq!(sim.kernel.notifications.len(), 1);
}

/// Without credits a bearer's response waits, and the fixed channel goes on;
/// the central's credits send it.
#[test]
fn without_credits_a_response_waits_and_cid_4_goes_on() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.credits = 1;
    sim.kernel.hold_credits = true;
    sim.kernel.connect_eatt(2);
    sim.pump();
    sim.kernel.request_on(On::Chan(0x0040), &read_features());
    sim.pump();
    assert_eq!(sim.kernel.responses.len(), 1);
    sim.kernel.request_on(On::Chan(0x0040), &read_features());
    sim.kernel.request_on(On::Fixed, &read_features());
    sim.pump();
    assert_eq!(sim.kernel.responses.iter().map(|(on, ..)| *on).collect::<Vec<_>>(), [On::Chan(0x0040), On::Fixed]);
    assert!(!sim.engine.has_output(), "nothing the link layer's room would let go");
    assert!(sim.engine.eatt_responses[0].is_some());
    sim.kernel.give_credits(0x0040, 1);
    sim.pump();
    assert_eq!(sim.kernel.responses.len(), 3);
    assert_eq!(sim.kernel.responses[2].0, On::Chan(0x0040));
}

/// The central closes a bearer while the first K-frame of its response is
/// part sent: the K-frame ends, the rest of the response is dropped, and the
/// Disconnection Response follows.
#[test]
fn a_close_in_the_middle_of_a_kframe_finishes_it() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.mps = 64;
    sim.kernel.connect_eatt(2);
    sim.pump();
    sim.kernel.request_on(On::Chan(0x0040), &read_report_map());
    sim.deliver();
    let now = sim.at();
    let start = sim.engine.next_fragment(4).unwrap();
    sim.engine.fragment_sent(now);
    let ident = sim.kernel.close(0x0040);
    sim.deliver();
    let rest = drain(&mut sim.engine, 4, now);
    assert_eq!(rest.iter().map(|fragment| (fragment.start(), fragment.bytes().len())).collect::<Vec<_>>(), [
        (false, 27),
        (false, 14),
        (true, 12)
    ]);
    assert_eq!(rest[2].bytes(), [8, 0, 5, 0, 0x07, ident, 4, 0, 0x40, 0, 0x40, 0]);
    for fragment in [&start].into_iter().chain(&rest) {
        sim.kernel.receive(fragment);
    }
    assert_eq!(sim.kernel.dropped, 1);
    assert!(sim.engine.response.is_none() && sim.engine.eatt_responses.iter().all(Option::is_none));
    assert!(!sim.engine.has_output());
    assert_eq!(sim.kernel.chans.len(), 0);
    // The bearer is free again.
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(sim.bound(), [(0x0040, 0x0040)]);
    serve_on_every_bearer(&mut sim);
}

/// A K-frame too long for the reassembly closes its bearer with our
/// Disconnection Request, and the bearer is free once Linux answers.
#[test]
fn a_kframe_too_long_closes_the_bearer() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.connect_eatt(2);
    sim.pump();
    sim.kernel.out.push_back((0x0040, vec![0; 80]));
    sim.pump();
    let close = sim.kernel.signals.last().unwrap();
    assert_eq!(close[0], 0x06);
    assert_eq!(close[4..], [0x40, 0, 0x40, 0]);
    assert_eq!(sim.kernel.chans.len(), 0);
    assert!(!sim.engine.ecfc.is_open(BearerId::FIRST));
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(sim.bound(), [(0x0040, 0x0040)]);
}

/// Our Disconnection Request that is never answered keeps its bearer, and
/// the central's CID, until 30 s after it went.
#[test]
fn an_unanswered_close_frees_the_bearer_after_30_s() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.ignore_close = true;
    sim.kernel.connect_eatt(2);
    sim.pump();
    sim.kernel.out.push_back((0x0040, vec![0; 80]));
    sim.pump();
    assert_eq!(sim.kernel.signals.last().unwrap()[0], 0x06);
    let closed = sim.now;
    assert_eq!(sim.engine.ecfc.deadline(), Some(at(closed + CLOSE_TIMEOUT.as_millis())));
    // The kernel's next channel has the same CID, which the closing bearer
    // still has.
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(answers(&sim)[1..], [(0x000A, vec![0])]);
    sim.advance(CLOSE_TIMEOUT.as_millis());
    assert_eq!(sim.engine.ecfc.deadline(), None);
    sim.kernel.connect_eatt(2);
    sim.pump();
    assert_eq!(answers(&sim)[2..], [(0x0000, vec![0x0040])]);
}

/// The link's end forgets the bearers, the held requests and the
/// responses: the next link starts with every bearer free.
#[test]
fn the_link_s_end_resets_the_bearers() {
    let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::spec());
    sim.kernel.connect_eatt(BEARERS + 1);
    sim.pump();
    sim.encrypt();
    assert_eq!(sim.bound().len(), BEARERS);
    sim.kernel.hold_credits = true;
    for scid in sim.kernel.bearers() {
        sim.kernel.request_on(On::Chan(scid), &read_features());
    }
    sim.deliver();
    // A request still to be answered.
    sim.kernel.send_request(0x80, &[0x0050]);
    sim.deliver();
    assert!(sim.engine.eatt_responses.iter().all(Option::is_some));
    sim.engine.on_event(&Event::Disconnected(0x13), sim.at());
    assert!(sim.engine.response.is_none() && sim.engine.eatt_responses.iter().all(Option::is_none));
    assert_eq!(sim.engine.ecfc.deadline(), None);
    assert!(BearerId::all().all(|bearer| !sim.engine.ecfc.is_open(bearer)));
    assert_eq!((sim.engine.served, sim.engine.sending), (BearerId::FIRST, None));
    let mut sim = Sim::reconnect(sim.engine, bond_with_features(0x07), Kernel::spec());
    sim.kernel.connect_eatt(BEARERS + 1);
    sim.pump();
    assert_eq!(answers(&sim), []);
    sim.encrypt();
    assert_eq!(answers(&sim), [(0x0000, dcids(BEARERS))]);
    serve_on_every_bearer(&mut sim);
}

/// A thousand requests on a bearer: the credits balance, with exactly seven
/// Flow Control Credit Indications of 128 from us.
#[test]
fn a_thousand_requests_balance_the_credits() {
    let mut sim = Sim::paired(Kernel::linux());
    sim.kernel.connect_eatt(2);
    sim.pump();
    for _ in 0..1000 {
        sim.kernel.request_on(On::Chan(0x0040), &read_features());
        sim.pump();
    }
    assert_eq!(sim.kernel.responses.iter().filter(|(on, ..)| *on == On::Chan(0x0040)).count(), 1000);
    let credits: Vec<_> = sim.kernel.signals.iter().filter(|signal| signal[0] == 0x16).collect();
    assert_eq!(credits.len(), 7);
    assert!(credits.iter().all(|signal| signal[4..] == [0x40, 0, (RX_CREDITS - TOP_UP) as u8, 0]));
    let left = i32::from(RX_CREDITS) - 1000 + 7 * i32::from(RX_CREDITS - TOP_UP);
    assert_eq!(i32::from(sim.kernel.chans[0].tx_credits), left);
    assert_eq!(sim.kernel.chans[0].state, ChanState::Connected);
}

/// The Client Supported Features written on a bearer go into the bond, as
/// on the fixed channel.
#[test]
fn client_features_written_on_a_bearer_reach_the_bond() {
    let mut sim = Sim::reconnection(bond_with_features(0x05), Kernel::linux());
    sim.kernel.connect_eatt(2);
    sim.pump();
    sim.encrypt();
    assert_eq!(events(&mut sim), [ConnEvent::Encrypted { bonded: true }]);
    sim.kernel.request_on(On::Chan(0x0040), &write_features(&[0x07]));
    sim.pump();
    assert_eq!(sim.kernel.responses.last().unwrap().2, [0x13]);
    let Some(ConnEvent::BondUpdated(bond)) = sim.engine.take_event(sim.epoch) else { panic!("no update") };
    assert_eq!(bond.client_features, 0x07);
    // An Exchange MTU on a bearer is not served.
    sim.kernel.request_on(On::Chan(0x0040), &[0x02, 0x05, 0x02]);
    sim.pump();
    assert_eq!(sim.kernel.responses.last().unwrap().2, [0x01, 0x02, 0x00, 0x00, 0x06]);
}

/// The encryption failing refuses the held requests for security.
#[test]
fn a_failed_encryption_refuses_the_held_requests() {
    let mut sim = Sim::reconnection(bond_with_features(0x07), Kernel::linux());
    sim.kernel.connect_eatt(3);
    sim.pump();
    let now = sim.at();
    sim.engine.on_event(&Event::LtkRequest { ediv: 0, rand: [0; 8] }, now);
    assert!(sim.engine.take_command(0, now).is_some());
    sim.engine.on_event(&Event::Encryption { on: false, refresh: false, status: 0x06 }, now);
    sim.pump();
    assert_eq!(answers(&sim), [(0x0008, vec![0, 0])]);
    assert!(sim.kernel.escalated);
    assert_eq!(sim.engine.ecfc.deadline(), None);
}

/// The static RAM of the bearers (design-v2, section 6): the credit based
/// channels' state at most 144 bytes and 16 for each bearer, and each
/// further bearer, with its response slot, at most 85. The gate measures the
/// engine against a build without the feature (`-Zprint-type-sizes`).
#[test]
fn the_bearers_keep_to_their_ram() {
    assert!(size_of::<Ecfc>() <= 144 + 16 * BEARERS, "{} bytes", size_of::<Ecfc>());
    assert!(16 + size_of::<Option<Slot>>() <= 85, "{} bytes", size_of::<Option<Slot>>());
}
