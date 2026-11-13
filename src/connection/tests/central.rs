//! The answer within the interframe space against a central that follows
//! the acknowledgement rules of the Core specification (Vol 6, Part B,
//! 4.5.9), as `BlueZ`'s controller does at the start of a link: the feature
//! exchange, the version exchange, then data both ways.
//!
//! The radio is modelled as the nRF51 latches its packet pointer: the
//! connection points it at the PDU on the air at the access address, and an
//! answer that comes too late goes out as that buffer held it then. Faults
//! are injected per exchange: late answers, lost and corrupted packets each
//! way. The model of the bug of the first hardware run, a late answer that
//! sends the received packet back, reproduces its log: two new packets in
//! three events, and an `LL_FEATURE_RSP` that never arrives.

extern crate std;

use super::{super::*, connection};
use std::{collections::VecDeque, vec, vec::Vec};

/// The central's features in its `LL_FEATURE_REQ`.
const CENTRAL_FEATURES: [u8; 8] = [0xFF, 0x41, 0, 0, 0, 0, 0, 0];
/// The central's `LL_VERSION_IND`.
const CENTRAL_VERSION: [u8; 6] = [OP_VERSION_IND, 0x0D, 0x02, 0x00, 0x34, 0x12];
/// The central's ATT request, in an L2CAP frame: exchange MTU.
const CENTRAL_DATA: [u8; 7] = [3, 0, 4, 0, 0x02, 0x17, 0x00];
/// Most exchanges in one event, for the time an event has.
const EXCHANGES_MAX: usize = 4;
/// Events a link gets to finish the exchanges.
const EVENTS_MAX: u32 = 400;

/// What the radio does with an answer.
#[derive(Clone, Copy)]
enum Late {
    /// A late answer goes out as the buffer the radio points at held it.
    Latched,
    /// A late answer sends the received packet back: the radio pointed at
    /// the receive buffer, as before the fix.
    Echo,
}

/// Fault rates in per mille, from a seeded generator.
#[derive(Clone, Copy)]
struct Faults {
    /// Late answers after an acknowledgement.
    late_ack:   u32,
    /// Late answers without one.
    late_noack: u32,
    /// Packets of the central we miss entirely, which ends the event.
    missed:     u32,
    /// Packets of the central we receive with a CRC error.
    corrupted:  u32,
    /// Answers of ours the central misses, which ends the event.
    lost:       u32,
}

impl Faults {
    /// No faults.
    const NONE: Self = Self { late_ack: 0, late_noack: 0, missed: 0, corrupted: 0, lost: 0 };
}

/// A small generator for the faults.
struct Random(u64);

impl Random {
    /// Whether an event of `rate` per mille happens.
    fn chance(&mut self, rate: u32) -> bool {
        if rate == 0 {
            return false;
        }
        self.0 ^= self.0.wrapping_shl(13);
        self.0 ^= self.0.wrapping_shr(7);
        self.0 ^= self.0.wrapping_shl(17);
        u32::try_from(self.0 % 1000).unwrap() < rate
    }
}

/// A central: sequence numbers, the PDUs it sends in order, and what it
/// received.
struct Central {
    /// Sequence number of its packet on the air.
    sn:         bool,
    /// Its next expected sequence number.
    nesn:       bool,
    /// PDUs to send: LLID and payload; the first is on the air.
    outbox:     VecDeque<(Llid, Vec<u8>)>,
    /// New PDUs with a payload it received from us: LLID and payload.
    received:   Vec<(u8, Vec<u8>)>,
    /// Packet counter of our next new encrypted PDU.
    counter:    u32,
    /// Packet counter the last new PDU of ours was sealed with.
    last_count: Option<u32>,
    /// Whether the link is encrypted both ways.
    encrypted:  bool,
}

impl Central {
    fn new(encrypted: bool) -> Self {
        let mut request = vec![OP_FEATURE_REQ];
        request.extend_from_slice(&CENTRAL_FEATURES);
        Self {
            sn: false,
            nesn: false,
            outbox: VecDeque::from([(Llid::Control, request)]),
            received: Vec::new(),
            counter: 0,
            last_count: None,
            encrypted,
        }
    }

    /// Its packet: header and payload. An empty PDU is a packet as any
    /// other: sent again until acknowledged, ahead of what comes meanwhile.
    fn packet(&mut self) -> (u8, Vec<u8>) {
        if self.outbox.is_empty() {
            self.outbox.push_back((Llid::Continuation, Vec::new()));
        }
        let (llid, payload) = self.outbox.front().cloned().unwrap();
        let header = llid.bits()
            | if self.sn { SN } else { 0 }
            | if self.nesn { NESN } else { 0 }
            | if self.outbox.len() > 1 { MD } else { 0 };
        (header, payload)
    }

    /// Takes our answer as it went on the air: header, length, S1 and
    /// payload, with the MIC on an encrypted link.
    fn receive(&mut self, sent: &[u8]) {
        let header = sent[0];
        if (header & NESN != 0) != self.sn {
            // Its packet was acknowledged.
            self.sn = !self.sn;
            self.outbox.pop_front();
        }
        if (header & SN != 0) != self.nesn {
            // Our retransmission: it must be the same counter again.
            if self.encrypted && sent[1] != 0 {
                let mic = u32::from_le_bytes(sent[usize::from(sent[1]) - 1..][..4].try_into().unwrap());
                assert_eq!(Some(mic), self.last_count, "a retransmission keeps its packet counter");
            }
            return;
        }
        self.nesn = !self.nesn;
        let mut len = usize::from(sent[1]);
        if len == 0 {
            return;
        }
        let mut payload = sent[3..3 + len].to_vec();
        if self.encrypted {
            len -= 4;
            let mic = u32::from_le_bytes(sent[3 + len..3 + len + 4].try_into().unwrap());
            assert_eq!(mic, self.counter, "each new PDU takes the next packet counter, once");
            self.last_count = Some(self.counter);
            self.counter += 1;
            payload = sent[3..3 + len].iter().map(|byte| !byte).collect();
        }
        self.respond(header & LLID_MASK, &payload);
        self.received.push((header & LLID_MASK, payload));
    }

    /// What `BlueZ`'s controller sends next: the version exchange once our
    /// features came, then an ATT request.
    fn respond(&mut self, llid: u8, payload: &[u8]) {
        if llid != Llid::Control.bits() {
            return;
        }
        match payload[0] {
            OP_FEATURE_RSP => self.outbox.push_back((Llid::Control, CENTRAL_VERSION.to_vec())),
            OP_VERSION_IND => self.outbox.push_back((Llid::Start, CENTRAL_DATA.to_vec())),
            _ => {},
        }
    }
}

/// A link driven event by event through the answer path as `exchange`
/// runs it, without the radio.
struct Sim {
    link:    Connection,
    central: Central,
    shared:  Shared,
    random:  Random,
    faults:  Faults,
    late:    Late,
    /// The central's packets that reached our host.
    host_rx: Vec<Vec<u8>>,
    /// Whether the host answered the central's request.
    replied: bool,
    /// The host's packets that wait for room in the link layer's queue.
    host_tx: VecDeque<Vec<u8>>,
    rx:      [u8; BUFFER_LEN],
}

/// What the host sends once the central's request came: three packets,
/// with the data length extension the last one in fragments of the 27
/// octets the central receives.
fn host_packets() -> Vec<Vec<u8>> {
    let last = if ACL_MAX > 27 { (0..60).collect() } else { vec![0xEE; 5] };
    vec![(0..27).collect::<Vec<u8>>(), (100..120).collect(), last]
}

impl Sim {
    fn new(seed: u64, faults: Faults, late: Late, encrypted: bool) -> Self {
        let shared = Shared::new();
        shared.set_connected(true);
        let mut link = connection();
        link.encryption.tx_on = encrypted;
        link.encryption.rx_on = encrypted;
        link.start_slots(&shared);
        Self {
            link,
            central: Central::new(encrypted),
            shared,
            random: Random(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            faults,
            late,
            host_rx: Vec::new(),
            replied: false,
            host_tx: VecDeque::new(),
            rx: [0; BUFFER_LEN],
        }
    }

    /// Whether every exchange of the start of the link is through: our
    /// features and version, the central's request and our answer to it.
    fn done(&self) -> bool {
        self.replied
            && self.host_tx.is_empty()
            && self.central.received.len()
                == 2 + host_packets().iter().map(|packet| packet.len().div_ceil(27)).sum::<usize>()
            && self.link.queue.is_empty()
            && !self.link.next_ready
            && self.link.acl.is_none()
            && self.link.tx_kind == TxKind::Empty
    }

    /// One connection event.
    fn event(&mut self) {
        // Before the event, as `run_events` does.
        self.link.prepare_next(&self.shared);
        self.link.prepare_room(&self.shared);
        assert_eq!(self.link.abort, None);
        let encrypted = self.link.encryption.rx_on;
        let mut heard = false;
        for _ in 0..EXCHANGES_MAX {
            if self.random.chance(self.faults.missed) {
                // No access address: no answer, and the event ends.
                break;
            }
            heard = true;
            let (header, payload) = self.central.packet();
            self.rx.fill(0);
            self.rx[0] = header;
            let sealed_len = if encrypted && !payload.is_empty() { payload.len() + 4 } else { payload.len() };
            self.rx[1] = u8::try_from(sealed_len).unwrap();
            self.rx[3..3 + payload.len()].copy_from_slice(&payload);
            self.link.rx_plain.fill(0);
            self.link.rx_plain[0] = header;
            self.link.rx_plain[1] = u8::try_from(payload.len()).unwrap();
            self.link.rx_plain[3..3 + payload.len()].copy_from_slice(&payload);
            // The radio points at the PDU on the air from the access address.
            let latched_slot = self.link.cur;
            let latched = *self.link.current_mut().on_air();
            let crc_ok = !self.random.chance(self.faults.corrupted);
            let packet = crc_ok.then_some((header, self.rx[1], true));
            let decision = self.link.decide(packet, 1000, true, &self.shared).expect("the link goes on");
            let buffer = self.link.answer_buffer(decision.follow.md);
            let on_air = |link: &mut Connection, slot: bool| *link.slot_mut(slot).on_air();
            // Within the interframe space, only the header of the buffer
            // the radio points at changes.
            assert_eq!(on_air(&mut self.link, latched_slot).0[1..], latched.0[1..], "the latched slot was written");
            let late = self.random.chance(if decision.acked.is_some() {
                self.faults.late_ack
            } else {
                self.faults.late_noack
            });
            assert_eq!(self.link.current_mut().on_air().0.as_ptr(), buffer.cast_const());
            let answer = *self.link.current_mut().on_air();
            let sent: Vec<u8> = match (late, self.late) {
                (false, _) => answer.0.to_vec(),
                (true, Late::Latched) => latched.0.to_vec(),
                (true, Late::Echo) => self.rx[..DATA_BUFFER_LEN].to_vec(),
            };
            let rx = self.rx;
            self.link.after_answer(decision, &rx, (None, late, 0), &self.shared);
            if chip::PREPARE_IN_EVENT && decision.follow.more && !late && !self.link.next_ready {
                self.link.prepare_next(&self.shared);
            }
            if late {
                // The radio sends the latched buffer: nothing after the
                // answer may write it either.
                assert_eq!(
                    on_air(&mut self.link, latched_slot).0[1..],
                    latched.0[1..],
                    "a slot on the air was written"
                );
            }
            if self.random.chance(self.faults.lost) {
                break;
            }
            self.central.receive(&sent);
            if !decision.follow.more {
                break;
            }
        }
        if heard {
            self.link.exchanged(1000);
        }
        self.link.process(&self.rx, encrypted, &self.shared);
        assert_eq!(self.link.abort, None);
        self.link.counter = self.link.counter.wrapping_add(1);
        self.link.stats.events += 1;
        // The host takes what came and answers the request once.
        while let Some(acl) = self.shared.take_acl_in() {
            self.host_rx.push(acl.payload().to_vec());
        }
        if !self.replied && !self.host_rx.is_empty() {
            self.host_tx.extend(host_packets());
            self.replied = true;
        }
        while let Some(packet) = self.host_tx.front() {
            if !self.shared.queue_acl_for_test(packet) {
                break;
            }
            self.host_tx.pop_front();
        }
    }

    /// Runs events until the start of the link is through, and checks that
    /// everything arrived once, in order, both ways.
    fn run(&mut self) -> u32 {
        let mut events = 0;
        while !self.done() {
            assert!(events < EVENTS_MAX, "the link is stuck: {:?}", self.central.received);
            self.event();
            events += 1;
        }
        self.check();
        events
    }

    /// Everything arrived once, in order, both ways, and nothing of the
    /// central's came back to it.
    fn check(&self) {
        let received = &self.central.received;
        let mut features = vec![OP_FEATURE_RSP];
        features.extend_from_slice(&FEATURES);
        assert_eq!(received[0], (Llid::Control.bits(), features));
        let mut version = vec![OP_VERSION_IND];
        version.extend_from_slice(&VERSION);
        assert_eq!(received[1], (Llid::Control.bits(), version));
        let data: Vec<u8> = received[2..].iter().flat_map(|(_, payload)| payload.clone()).collect();
        assert_eq!(data, host_packets().concat());
        assert!(received[2..].iter().all(|&(llid, _)| llid != Llid::Control.bits()));
        assert_eq!(self.host_rx, vec![CENTRAL_DATA.to_vec()]);
        assert!(self.central.outbox.iter().all(|(_, payload)| payload.is_empty()));
    }
}

#[test]
fn without_faults_every_event_carries_a_new_packet_and_the_features_go_out_at_once() {
    for encrypted in [false, true] {
        let mut sim = Sim::new(1, Faults::NONE, Late::Latched, encrypted);
        sim.event();
        // The central's request is in; our response is prepared and goes
        // out on the next acknowledgement.
        sim.event();
        assert_eq!(sim.central.received.first().map(|(_, payload)| payload[0]), Some(OP_FEATURE_RSP));
        let events = sim.run() + 2;
        let stats = sim.link.stats;
        assert!(stats.received >= events, "{} packets in {events} events", stats.received);
        assert_eq!((stats.retx, stats.retx_with_ack, stats.late_ack, stats.late_noack), (0, 0, 0, 0));
        assert!(events < 20, "{events} events");
    }
}

#[test]
fn a_late_answer_resends_our_previous_pdu_and_the_link_goes_on() {
    for encrypted in [false, true] {
        // Every answer to an acknowledgement late: each PDU of ours takes
        // two exchanges, but every one arrives, once.
        let always = Faults { late_ack: 1000, ..Faults::NONE };
        let mut sim = Sim::new(2, always, Late::Latched, encrypted);
        sim.run();
        assert!(sim.link.stats.late_ack > 0);
        assert_eq!(sim.link.stats.late_noack, 0);
        // The central retransmits after each, without acknowledging ours
        // again.
        assert!(sim.link.stats.retx > 0);
        assert_eq!(sim.link.stats.retx_with_ack, 0);
        // Every answer late: the flags go out one exchange behind, and still
        // everything arrives.
        let both = Faults { late_ack: 1000, late_noack: 1000, ..Faults::NONE };
        let mut sim = Sim::new(3, both, Late::Latched, encrypted);
        sim.run();
        assert!(sim.link.stats.late_noack > 0);
        // A late answer without an acknowledgement sent the previous NESN:
        // the central sends its packet again and acknowledges ours, without
        // any echo.
        assert!(sim.link.stats.retx_with_ack > 0);
        assert!(sim.link.stats.retx_with_ack <= sim.link.stats.late_noack);
    }
}

#[test]
fn a_thousand_links_with_random_faults_lose_nothing_and_never_echo() {
    for seed in 0..1000_u64 {
        let rate = u32::try_from(seed % 5).unwrap() * 50;
        let faults = Faults {
            late_ack:   rate,
            late_noack: rate / 2,
            missed:     rate / 4,
            corrupted:  rate / 4,
            lost:       rate / 4,
        };
        let mut sim = Sim::new(seed, faults, Late::Latched, seed % 2 == 1);
        sim.run();
        // Without an echo, only late answers without an acknowledgement
        // make the central acknowledge ours in a retransmission.
        let stats = sim.link.stats;
        assert!(stats.retx_with_ack <= stats.late_noack, "seed {seed}: {} > {}", stats.retx_with_ack, stats.late_noack);
    }
}

#[test]
fn an_answer_that_echoes_the_received_packet_reproduces_the_first_hardware_run() {
    // The radio pointed at the receive buffer, and every answer to an
    // acknowledgement came too late: the central gets its own packet back.
    let always = Faults { late_ack: 1000, ..Faults::NONE };
    let mut sim = Sim::new(4, always, Late::Echo, false);
    for _ in 0..300 {
        sim.event();
    }
    // Two new packets in three events, as the log's 149 of 223, and our
    // features never reach the central.
    assert_eq!(sim.link.stats.received, 200);
    assert!(sim.central.received.is_empty());
    assert!(sim.link.stats.retx_with_ack > 0);
}

#[test]
fn only_a_sent_pdu_uses_up_its_packet_counter() {
    let shared = Shared::new();
    shared.set_connected(true);
    let mut link = connection();
    link.encryption.tx_on = true;
    link.start_slots(&shared);
    assert_eq!(link.encryption.tx_counter, 0);
    // Prepared again and again before events: the same counter.
    link.enqueue(Llid::Control, &[OP_PING_RSP]);
    for _ in 0..3 {
        link.prepare_next(&shared);
        assert!(link.next_ready);
        assert!(link.slot(!link.cur).encrypted);
        assert_eq!(link.slot(!link.cur).sealed.0[4..8], [0, 0, 0, 0]);
        assert_eq!(link.encryption.tx_counter, 0);
    }
    // A control PDU that came first in the meantime takes the counter.
    link.queue.clear();
    link.enqueue(Llid::Control, &[OP_PAUSE_ENC_RSP]);
    link.prepare_next(&shared);
    assert_eq!(link.slot(!link.cur).plain.0[3], OP_PAUSE_ENC_RSP);
    assert_eq!(link.slot(!link.cur).sealed.0[4..8], [0, 0, 0, 0]);
    // Sending it uses the counter up; an empty PDU uses none.
    link.commit_next();
    assert_eq!(link.encryption.tx_counter, 1);
    link.commit_empty();
    assert!(!link.current().encrypted);
    assert_eq!(link.encryption.tx_counter, 1);
    link.prepare_next(&shared);
    assert!(!link.next_ready);
    assert!(!link.slot(!link.cur).encrypted);
    link.commit_empty();
    assert_eq!(link.encryption.tx_counter, 1);
    // A plain link uses no counter.
    let mut plain = connection();
    plain.start_slots(&shared);
    plain.enqueue(Llid::Control, &[OP_PING_RSP]);
    plain.prepare_next(&shared);
    plain.commit_next();
    assert!(!plain.current().encrypted);
    assert_eq!(plain.encryption.tx_counter, 0);
}

#[test]
fn the_answer_patches_only_the_header_of_the_pdu_on_the_air() {
    let shared = Shared::new();
    shared.set_connected(true);
    for encrypted in [false, true] {
        let mut link = connection();
        link.encryption.tx_on = encrypted;
        link.start_slots(&shared);
        link.enqueue(Llid::Control, &[OP_PING_RSP]);
        link.prepare_next(&shared);
        link.commit_next();
        let before = *link.current_mut().on_air();
        link.seq.sn = true;
        link.seq.nesn = true;
        let buffer = link.answer_buffer(true);
        let after = *link.current_mut().on_air();
        assert_eq!(buffer.cast_const(), link.current_mut().on_air().0.as_ptr());
        assert_eq!(after.0[0], before.0[0] | SN | NESN | MD);
        assert_eq!(after.0[1..], before.0[1..]);
        // The plain copy keeps its header when the sealed one goes out.
        assert_eq!(link.current().plain.0[0] & (SN | NESN | MD) != 0, !encrypted);
    }
}

#[test]
fn room_is_counted_before_the_event_and_used_up_by_new_packets() {
    let shared = Shared::new();
    shared.set_connected(true);
    let mut link = connection();
    link.start_slots(&shared);
    link.prepare_room(&shared);
    let room = link.room.acl;
    assert!(room > 0);
    let mut header = Llid::Start.bits();
    for _ in 0..room {
        let decision = link.decide(Some((header, 1, true)), 1000, true, &shared).unwrap();
        assert!(link.seq.received && !decision.duplicate);
        link.seq.received = false;
        header ^= SN;
    }
    // The host's queue is full now: the next one comes again.
    let decision = link.decide(Some((header, 1, true)), 1000, true, &shared).unwrap();
    assert!(!link.seq.received && !decision.duplicate && !decision.follow.more);
}

#[test]
fn a_second_acknowledgement_in_an_event_is_answered_with_an_empty_pdu() {
    let shared = Shared::new();
    shared.set_connected(true);
    let mut link = connection();
    link.start_slots(&shared);
    link.enqueue(Llid::Control, &[OP_PING_RSP]);
    link.enqueue(Llid::Control, &[OP_PING_REQ]);
    link.prepare_next(&shared);
    link.prepare_room(&shared);
    // The first acknowledgement sends the prepared PDU.
    let empty = Llid::Continuation.bits();
    let first = link.decide(Some((empty | NESN, 0, true)), 1000, true, &shared).unwrap();
    link.after_answer(first, &[0; BUFFER_LEN], (None, false, 0), &shared);
    assert!(link.tx_kind == TxKind::Control && !first.fallback);
    assert_eq!(first.follow.md, chip::PREPARE_IN_EVENT);
    // The second, before anything is prepared again, an empty one.
    let second = link.decide(Some((empty | SN, 0, true)), 1000, true, &shared).unwrap();
    link.after_answer(second, &[0; BUFFER_LEN], (None, false, 0), &shared);
    assert!(link.tx_kind == TxKind::Empty && second.fallback);
    assert_eq!(link.stats.fallback, 1);
    assert_eq!(link.queue.len(), 1);
}

#[test]
fn a_loss_after_a_late_answer_is_not_the_path() {
    let shared = Shared::new();
    let mut link = connection();
    link.start_slots(&shared);
    link.prepare_room(&shared);
    link.stats.received = 1;
    let level = for_phy_mut(&mut link.power, link.tx_phy).level();
    // Our last answer was late: the central did not acknowledge it, as it
    // got the one before.
    link.late_answer = true;
    let decision = link.decide(Some((Llid::Continuation.bits(), 0, true)), 1000, true, &shared).unwrap();
    assert!(decision.nacked);
    link.after_answer(decision, &[0; BUFFER_LEN], (None, false, 0), &shared);
    assert_eq!(for_phy_mut(&mut link.power, link.tx_phy).level(), level);
    assert!(!link.late_answer);
}

#[test]
fn host_data_queued_during_the_sleep_goes_out_at_that_event() {
    let shared = Shared::new();
    shared.set_connected(true);
    for encrypted in [false, true] {
        let mut link = connection();
        link.encryption.tx_on = encrypted;
        link.start_slots(&shared);
        // Before the sleep, nothing to send.
        link.prepare_next(&shared);
        link.prepare_room(&shared);
        assert!(!link.next_ready);
        // The host answers during the sleep, and its wake-up prepares again
        // in time.
        let packet: Vec<u8> = (1..=9).collect();
        assert!(shared.queue_acl_for_test(&packet));
        assert!(link.prepare_after_wake(1000, 1000 + SETUP_US + PREPARE_AGAIN_US + 1, &shared));
        assert!(link.next_ready);
        // The central's acknowledgement at the event sends it.
        let decision = link.decide(Some((Llid::Continuation.bits() | NESN, 0, true)), 1000, true, &shared).unwrap();
        assert!(decision.acked.is_some() && !decision.fallback);
        assert!(link.tx_kind == TxKind::Acl);
        assert_eq!(&link.current().plain.0[DATA_HEADER_LEN..DATA_HEADER_LEN + packet.len()], &packet[..]);
        assert_eq!(link.current().encrypted, encrypted);
        // A wake-up too close to the radio's setup leaves the data for the
        // next event.
        let mut late = connection();
        late.start_slots(&shared);
        late.prepare_next(&shared);
        assert!(shared.queue_acl_for_test(&packet));
        assert!(!late.prepare_after_wake(1000, 1000 + SETUP_US + PREPARE_AGAIN_US, &shared));
        assert!(!late.next_ready);
        late.prepare_next(&shared);
        assert!(late.next_ready);
    }
}
