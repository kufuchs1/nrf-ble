//! Tests of the credit based channels: every row of the connection request's
//! checks with one bearer and with several, the hold, the other commands, the
//! credits both ways, our Disconnection Request, and a deterministic fuzz of
//! the commands and K-frames.

extern crate alloc;

extern crate std;

use super::*;
use crate::host::{
    example::PARAMS,
    l2cap::{FRAGMENT_MAX, Reassembly},
    signal::{Action, Outcome},
};
use alloc::{vec, vec::Vec};
use core::iter::repeat_with;

/// The peer's MTU and MPS in our requests: what Linux 7.3 offers on a link
/// of the default data length.
const PEER_MTU: u16 = 517;

/// See [`PEER_MTU`].
const PEER_MPS: u16 = 247;

/// The time the tests start at.
const START: u64 = 1_000;

/// A link's channels and its signalling channel, at a time of their own.
struct Fixture {
    /// The channels.
    ecfc:   Ecfc,
    /// The time.
    now:    Instant,
    /// The signalling channel, for our identifiers.
    signal: Signalling,
}

impl Fixture {
    /// Takes the command with `code`, `identifier` and `data`, on a link
    /// that is `secure` or not.
    fn command(&mut self, code: u8, identifier: u8, data: &[u8], secure: bool) -> Option<Vec<u8>> {
        let reply = self.ecfc.command(&mut self.signal, code, identifier, data, secure, self.now)?;
        Some(reply.bytes().to_vec())
    }

    /// Takes a connection request for EATT with `scids` and 10 credits.
    fn connect(&mut self, identifier: u8, scids: &[u16], secure: bool) {
        assert_eq!(self.command(0x17, identifier, &request_data(scids, 10), secure), None);
    }

    /// A new link at the start.
    fn new() -> Self { Self { ecfc: Ecfc::new(), now: at(0), signal: Signalling::new() } }

    /// Opens bearers for `scids` on a secure link and sends the response.
    fn open(&mut self, identifier: u8, scids: &[u16]) -> Vec<Vec<u8>> {
        self.connect(identifier, scids, true);
        self.send_all()
    }

    /// Renders and sends every command that waits, in order.
    fn send_all(&mut self) -> Vec<Vec<u8>> {
        let mut sent = Vec::new();
        while let Some(signal) = self.ecfc.next_signal() {
            let mut out = [0_u8; SIGNAL_MAX];
            let len = self.ecfc.render(signal, &mut out);
            assert!(len > 0 && len <= SIGNAL_MAX, "{signal:?} rendered as {len} octets");
            // It fits one link layer fragment with the L2CAP header.
            assert!(len.strict_add(4) <= FRAGMENT_MAX);
            sent.push(out.get(..len).unwrap_or_default().to_vec());
            self.ecfc.signal_sent(signal, self.now);
            assert!(sent.len() < 100, "the commands never end");
        }
        sent
    }

    /// The bearers' states.
    fn states(&self) -> Vec<State> { self.ecfc.bearers.iter().map(|bearer| bearer.state).collect() }
}

/// A deterministic xorshift generator.
struct Rng(u64);

impl Rng {
    /// A value below `bound`.
    fn below(&mut self, bound: u64) -> u64 { self.next().strict_rem(bound) }

    /// A CID a central would name, or another.
    fn cid(&mut self) -> u16 {
        match self.below(4) {
            0 => self.below(8).truncate::<u16>().strict_add(0x0040),
            1 => self.below(4).truncate::<u16>().strict_add(0x0050),
            2 => self.pick(&[0x003F, 0x0080, 0x0000, 0xFFFF]),
            _ => self.next().truncate::<u16>(),
        }
    }

    /// The next value.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13_i32;
        self.0 ^= self.0 >> 7_i32;
        self.0 ^= self.0 << 17_i32;
        self.0
    }

    /// One of `choices`.
    fn pick<T>(&mut self, choices: &[T]) -> T
    where
        T: Copy + Default,
    {
        let choice = choices.get(self.below(choices.len().strict_cast::<u64>()).strict_cast::<usize>()).copied();
        assert!(choice.is_some(), "a choice");
        choice.unwrap_or_default()
    }
}

/// What a fuzz run reached, so that it is known to cover the channels'
/// states and not only their refusals.
#[derive(Debug, Default)]
struct Seen {
    /// Our Disconnection Requests sent.
    closes:   usize,
    /// Commands the signalling channel handed to the channels.
    commands: usize,
    /// Credits indications sent.
    credits:  usize,
    /// K-frames sent.
    kframes:  usize,
    /// Bearers opened by a response that went.
    opened:   usize,
    /// PDUs too long for the reassembly buffer on a bearer's CID.
    overlong: usize,
    /// PDUs given: commands and K-frames.
    pdus:     usize,
    /// Our Disconnection Responses sent.
    releases: usize,
    /// SDUs received whole.
    sdus:     usize,
    /// Responses refused for security.
    security: usize,
}

/// The time `millis` ms after the start.
fn at(millis: u64) -> Instant { Instant::from_millis(START.strict_add(millis)) }

/// A Credit Based Connection Request's data for EATT with `scids` and
/// `credits`.
fn request_data(scids: &[u16], credits: u16) -> Vec<u8> {
    let mut data = vec![0x27, 0x00];
    data.extend_from_slice(&PEER_MTU.to_le_bytes());
    data.extend_from_slice(&PEER_MPS.to_le_bytes());
    data.extend_from_slice(&credits.to_le_bytes());
    for scid in scids {
        data.extend_from_slice(&scid.to_le_bytes());
    }
    data
}

/// The Credit Based Connection Response with `identifier`, `result` and
/// `dcids`.
fn response(identifier: u8, result: u8, dcids: &[u16]) -> Vec<u8> {
    let mut command = vec![
        0x18,
        identifier,
        dcids.len().truncate::<u8>().strict_mul(2).strict_add(8),
        0x00,
        65,
        0,
        67,
        0,
        0x00,
        0x01,
        result,
        0,
    ];
    for dcid in dcids {
        command.extend_from_slice(&dcid.to_le_bytes());
    }
    command
}

/// The destination CIDs a request with `count` ascending source CIDs gets on
/// free bearers from `first` on: ours in order, 0 past the capacity.
fn expected_dcids(first: usize, count: usize) -> Vec<u16> {
    (first..first.strict_add(count))
        .map(|bearer| if bearer < BEARERS { bearer.truncate::<u16>().strict_add(0x0040) } else { 0 })
        .collect()
}

#[test]
fn one_source_cid_gets_bearer_0_and_opens_once_answered() {
    let mut fixture = Fixture::new();
    fixture.connect(1, &[0x0040], true);
    assert!(!fixture.ecfc.is_open(BearerId::FIRST));
    assert_eq!(fixture.ecfc.att_mtu(BearerId::FIRST), None);
    assert_eq!(fixture.send_all(), [response(1, 0x00, &[0x0040])]);
    assert!(fixture.ecfc.is_open(BearerId::FIRST));
    assert_eq!(fixture.ecfc.att_mtu(BearerId::FIRST), Some(65));
    assert_eq!(fixture.ecfc.bearers[0].peer_cid, 0x0040);
    assert_eq!(fixture.ecfc.bearers[0].tx_credits, 10);
    assert_eq!(fixture.ecfc.bearers[0].rx_credits, RX_CREDITS);
    assert_eq!(fixture.ecfc.deadline(), None);
}

#[test]
fn ascending_source_cids_get_the_bearers_in_order_and_zeros_past_the_capacity() {
    for count in 1..=5_usize {
        let mut fixture = Fixture::new();
        let scids: Vec<u16> = (0..count).map(|index| 0x0041 + index.truncate::<u16>()).collect();
        let dcids = expected_dcids(0, count);
        let result = if count <= BEARERS { 0x00 } else { 0x04 };
        assert_eq!(fixture.open(7, &scids), [response(7, result, &dcids)], "{count} source CIDs");
        for (bearer, &scid) in scids.iter().enumerate().take(BEARERS) {
            assert!(fixture.ecfc.is_open(BearerId::valid(bearer.truncate::<u8>())));
            assert_eq!(fixture.ecfc.bearers.get(bearer).map(|entry| entry.peer_cid), Some(scid));
        }
        // A further request finds the bearers that are left.
        let opened = count.min(BEARERS);
        assert_eq!(fixture.open(8, &[0x0050]), [response(
            8,
            if opened < BEARERS { 0x00 } else { 0x04 },
            &expected_dcids(opened, 1)
        )]);
    }
}

#[test]
fn linux_s_order_of_source_cids_is_refused_with_zeros() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.open(3, &[0x0042, 0x0040, 0x0041]), [response(3, 0x04, &[0, 0, 0])]);
    assert!(fixture.states().iter().all(|&state| state == State::Idle));
    // Five, as Channels = 6 sends them.
    assert_eq!(fixture.open(4, &[0x0044, 0x0040, 0x0041, 0x0042, 0x0043]), [response(4, 0x04, &[0; 5])]);
    // Two equal source CIDs are not ascending either.
    assert_eq!(fixture.open(5, &[0x0040, 0x0040]), [response(5, 0x04, &[0, 0])]);
    // A single source CID is always in order.
    assert_eq!(fixture.open(6, &[0x0042]), [response(6, 0x00, &[0x0040])]);
}

#[test]
fn invalid_parameters_are_refused_with_as_many_zeros_as_source_cids() {
    let mut fixture = Fixture::new();
    let valid = request_data(&[0x0040, 0x0041], 10);
    let cases: [(Vec<u8>, usize); 9] = [
        // No source CID, and less than the fixed fields.
        (valid.get(..8).unwrap_or_default().to_vec(), 0),
        (valid.get(..6).unwrap_or_default().to_vec(), 0),
        (Vec::new(), 0),
        // An odd length.
        (valid.get(..11).unwrap_or_default().to_vec(), 1),
        // Six source CIDs.
        (request_data(&[0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045], 10), 5),
        // MTU, MPS and credits too low.
        ([&[0x27, 0x00, 63, 0, 64, 0, 1, 0][..], valid.get(8..).unwrap_or_default()].concat(), 2),
        ([&[0x27, 0x00, 64, 0, 63, 0, 1, 0][..], valid.get(8..).unwrap_or_default()].concat(), 2),
        ([&[0x27, 0x00, 64, 0, 64, 0, 0, 0][..], valid.get(8..).unwrap_or_default()].concat(), 2),
        // The least MTU and MPS, but no credits.
        ([&[0x27, 0x00, 64, 0, 64, 0, 0, 0][..], valid.get(8..10).unwrap_or_default()].concat(), 1),
    ];
    for (identifier, (data, zeros)) in (1_u8..).zip(cases) {
        // At once, also on a link that is not encrypted.
        assert_eq!(fixture.command(0x17, identifier, &data, false), None);
        assert_eq!(fixture.send_all(), [response(identifier, 0x0C, &vec![0; zeros])], "case {identifier}");
    }
    assert_eq!(fixture.ecfc.deadline(), None);
    // The least MTU and MPS with a credit are accepted.
    let least = [&[0x27, 0x00, 64, 0, 64, 0, 1, 0][..], valid.get(8..10).unwrap_or_default()].concat();
    assert_eq!(fixture.command(0x17, 20, &least, true), None);
    assert_eq!(fixture.send_all(), [response(20, 0x00, &[0x0040])]);
    assert_eq!(fixture.ecfc.att_mtu(BearerId::FIRST), Some(64));
}

#[test]
fn another_spsm_is_refused_at_once() {
    let mut fixture = Fixture::new();
    let mut data = request_data(&[0x0040, 0x0041], 10);
    *assert_some!(data.first_mut()) = 0x25;
    assert_eq!(fixture.command(0x17, 9, &data, false), None);
    assert_eq!(fixture.send_all(), [response(9, 0x02, &[0, 0])]);
    assert_eq!(fixture.ecfc.deadline(), None);
}

#[test]
fn source_cids_outside_the_dynamic_range_or_in_use_are_refused_one_by_one() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.open(1, &[0x003F]), [response(1, 0x09, &[0])]);
    assert_eq!(fixture.open(2, &[0x0080]), [response(2, 0x09, &[0])]);
    // A refused position does not stop the ones after it, and the result is
    // that of the first refused.
    assert_eq!(fixture.open(3, &[0x003F, 0x0050]), [response(3, 0x09, &[0, 0x0040])]);
    // 0x0050 is ours now: a request for it again is refused, the next one
    // gets a bearer if one is left.
    let second = if BEARERS >= 2 { 0x0041 } else { 0 };
    assert_eq!(fixture.open(4, &[0x0050, 0x0060]), [response(4, 0x0A, &[0, second])]);
    // Past the capacity, 0x0009 still comes first.
    let mut full = Fixture::new();
    let scids: Vec<u16> = (0..BEARERS.truncate::<u16>()).map(|index| 0x0040 + index).collect();
    assert_eq!(full.open(1, &scids).first().and_then(|first| first.get(10)), Some(&0x00));
    assert_eq!(full.open(2, &[0x0060, 0x0080]), [response(2, 0x04, &[0, 0])]);
    assert_eq!(full.open(3, &[0x0030, 0x0060]), [response(3, 0x09, &[0, 0])]);
    assert_eq!(full.open(4, &[0x0040, 0x0060]), [response(4, 0x0A, &[0, 0])]);
}

#[test]
fn a_request_on_an_unencrypted_link_is_held_and_answered_after_the_encryption() {
    let mut fixture = Fixture::new();
    fixture.connect(1, &[0x0040], false);
    assert_eq!(fixture.ecfc.deadline(), Some(at(2_000)));
    assert_eq!(fixture.send_all(), Vec::<Vec<u8>>::new());
    // A later one waits as well, with the first one's deadline, and takes
    // the next bearer: first come, first served.
    fixture.now = at(1_500);
    fixture.connect(2, &[0x0041], false);
    assert_eq!(fixture.ecfc.deadline(), Some(at(2_000)));
    fixture.ecfc.resolve_holds();
    assert_eq!(fixture.ecfc.deadline(), None);
    assert_eq!(fixture.send_all(), [
        response(1, 0x00, &[0x0040]),
        response(2, if BEARERS >= 2 { 0x00 } else { 0x04 }, &expected_dcids(1, 1)),
    ]);
    // A held request in Linux's order gets its refusal then.
    let mut linux = Fixture::new();
    linux.connect(1, &[0x0041, 0x0040], false);
    assert!(linux.states().iter().all(|&state| state == State::Idle));
    linux.ecfc.resolve_holds();
    assert_eq!(linux.send_all(), [response(1, 0x04, &[0, 0])]);
}

#[test]
fn held_requests_are_refused_for_security_at_the_deadline_unless_encryption_is_under_way() {
    for bonded in [false, true] {
        let mut fixture = Fixture::new();
        fixture.connect(1, &[0x0040], false);
        fixture.ecfc.on_time(at(1_999), false, bonded);
        assert_eq!(fixture.send_all(), Vec::<Vec<u8>>::new());
        fixture.ecfc.on_time(at(2_000), false, bonded);
        assert_eq!(fixture.send_all(), [response(1, if bonded { 0x08 } else { 0x05 }, &[0])]);
        // The reservation is free again.
        assert_eq!(fixture.open(2, &[0x0040]), [response(2, 0x00, &[0x0040])]);
    }
    // With a key reply or a pairing under way, the hold waits for the
    // encryption, with no deadline.
    let mut fixture = Fixture::new();
    fixture.connect(1, &[0x0040], false);
    fixture.ecfc.on_time(at(2_000), true, true);
    assert_eq!(fixture.ecfc.deadline(), None);
    assert_eq!(fixture.send_all(), Vec::<Vec<u8>>::new());
    // The encryption fails.
    fixture.ecfc.refuse_holds(true);
    assert_eq!(fixture.send_all(), [response(1, 0x08, &[0])]);
}

#[test]
fn linux_s_single_requests_after_a_refusal_for_security_are_all_answered() {
    for channels in 3..=6_usize {
        let count = channels - 1;
        let mut fixture = Fixture::new();
        // [T, D1, .., Dk]: the triggering channel's CID is the largest.
        let mut scids: Vec<u16> = (0..count.truncate::<u16>()).map(|index| 0x0040 + index).collect();
        scids.rotate_right(1);
        fixture.connect(1, &scids, false);
        fixture.ecfc.on_time(at(2_000), false, false);
        assert_eq!(fixture.send_all(), [response(1, 0x05, &vec![0; count])]);
        // After the encryption, one request per channel in a burst, before
        // our first answer.
        for (identifier, &scid) in (2_u8..).zip(&scids) {
            fixture.connect(identifier, &[scid], true);
        }
        let answers = fixture.send_all();
        assert_eq!(answers.len(), count, "Channels = {channels}");
        for (index, (answer, identifier)) in answers.iter().zip(2_u8..).enumerate() {
            assert_eq!(
                answer,
                &response(identifier, if index < BEARERS { 0x00 } else { 0x04 }, &expected_dcids(index, 1))
            );
        }
        // Each bearer has the source CID of its own request.
        for (bearer, &scid) in scids.iter().enumerate().take(BEARERS) {
            assert_eq!(fixture.ecfc.bearers.get(bearer).map(|entry| entry.peer_cid), Some(scid));
            assert!(fixture.ecfc.is_open(BearerId::valid(bearer.truncate::<u8>())));
        }
    }
}

#[test]
fn a_duplicate_identifier_is_dropped_while_its_answer_is_pending() {
    let mut fixture = Fixture::new();
    fixture.connect(1, &[0x0040], false);
    fixture.connect(1, &[0x0041], false);
    fixture.connect(1, &[0x0042], true);
    fixture.ecfc.resolve_holds();
    assert_eq!(fixture.send_all(), [response(1, 0x00, &[0x0040])]);
    // Once answered, the identifier is a new request: its source CID is in
    // use now.
    assert_eq!(fixture.open(1, &[0x0040]), [response(1, 0x0A, &[0])]);
}

#[test]
fn five_requests_wait_at_once_and_a_sixth_is_dropped() {
    let mut fixture = Fixture::new();
    for identifier in 1..=6_u8 {
        fixture.connect(identifier, &[0x003F + u16::from(identifier)], false);
    }
    fixture.ecfc.resolve_holds();
    let answers = fixture.send_all();
    assert_eq!(answers.len(), PENDING);
    for (index, (answer, identifier)) in answers.iter().zip(1_u8..).enumerate() {
        assert_eq!(answer, &response(identifier, if index < BEARERS { 0x00 } else { 0x04 }, &expected_dcids(index, 1)));
    }
    // The sixth left no trace; the entries are free again.
    assert_eq!(fixture.open(6, &[0x0050]), [response(6, 0x04, &[0])]);
}

#[test]
fn credits_add_up_ignore_zero_and_other_cids_and_close_the_bearer_above_65535() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.command(0x17, 1, &request_data(&[0x0050], 1), true), None);
    fixture.send_all();
    let segmenter = assert_some!(fixture.ecfc.kframe(BearerId::FIRST, 10));
    assert!(fixture.ecfc.kframe_queued(BearerId::FIRST, &segmenter));
    assert_eq!(fixture.ecfc.kframe(BearerId::FIRST, 10), None);
    for data in [[0x50, 0x00, 0x00, 0x00], [0x51, 0x00, 0x01, 0x00], [0x40, 0x00, 0x01, 0x00]] {
        assert_eq!(fixture.command(0x16, 2, &data, true), None);
        assert_eq!(fixture.ecfc.kframe(BearerId::FIRST, 10), None);
    }
    // A malformed indication is ignored.
    assert_eq!(fixture.command(0x16, 2, &[0x50, 0x00, 0x01], true), None);
    assert_eq!(fixture.ecfc.kframe(BearerId::FIRST, 10), None);
    assert_eq!(fixture.command(0x16, 2, &[0x50, 0x00, 0xFF, 0xFF], true), None);
    assert_eq!(fixture.ecfc.bearers[0].tx_credits, 0xFFFF);
    assert!(fixture.ecfc.kframe(BearerId::FIRST, 10).is_some());
    // One more is too many: the bearer closes.
    assert_eq!(fixture.command(0x16, 3, &[0x50, 0x00, 0x01, 0x00], true), None);
    assert!(!fixture.ecfc.is_open(BearerId::FIRST));
    assert_eq!(fixture.ecfc.kframe(BearerId::FIRST, 10), None);
    assert_eq!(fixture.send_all(), [vec![0x06, 1, 0x04, 0x00, 0x50, 0x00, 0x40, 0x00]]);
}

#[test]
fn reconfigure_checks_the_cids_then_the_values_then_the_reductions() {
    let mut fixture = Fixture::new();
    let scids: Vec<u16> = (0..BEARERS.truncate::<u16>()).map(|index| 0x0060 + index).collect();
    fixture.open(1, &scids);
    let reconfigure = |on: &mut Fixture, mtu: u16, mps: u16, cids: &[u16]| {
        let mut data = Vec::new();
        data.extend_from_slice(&mtu.to_le_bytes());
        data.extend_from_slice(&mps.to_le_bytes());
        for cid in cids {
            data.extend_from_slice(&cid.to_le_bytes());
        }
        let reply = on.command(0x19, 9, &data, true).unwrap_or_default();
        assert_eq!(reply.get(..4), Some(&[0x1A, 9, 0x02, 0x00][..]));
        let result = reply.get(4..6).and_then(|octets| <[u8; 2]>::try_from(octets).ok());
        assert!(result.is_some(), "a result");
        result.map_or(0, u16::from_le_bytes)
    };
    let values =
        |of: &Fixture| of.ecfc.bearers.iter().map(|bearer| (bearer.peer_mtu, bearer.peer_mps)).collect::<Vec<_>>();
    let before = values(&fixture);
    // An unknown CID, also beside a known one; our own CID is not the peer's.
    assert_eq!(reconfigure(&mut fixture, 600, 250, &[0x0070]), 0x0003);
    assert_eq!(reconfigure(&mut fixture, 600, 250, &[0x0060, 0x0070]), 0x0003);
    assert_eq!(reconfigure(&mut fixture, 600, 250, &[0x0040]), 0x0003);
    // Values below 64, even with a reduction too.
    assert_eq!(reconfigure(&mut fixture, 63, 250, &[0x0060]), 0x0004);
    assert_eq!(reconfigure(&mut fixture, 600, 63, &[0x0060]), 0x0004);
    // A smaller MTU.
    assert_eq!(reconfigure(&mut fixture, PEER_MTU - 1, 250, &[0x0060]), 0x0001);
    // Malformed.
    assert_eq!(reconfigure(&mut fixture, 600, 250, &[]), 0x0004);
    assert_eq!(reconfigure(&mut fixture, 600, 250, &[0x0060; 6]), 0x0004);
    assert_eq!(
        assert_some!(fixture.command(0x19, 9, &[0x58, 0x02, 0xFA, 0x00, 0x60, 0x00, 0x00], true)).get(4),
        Some(&0x04)
    );
    assert_eq!(values(&fixture), before);
    if BEARERS >= 2 {
        // A smaller MPS for two channels at once.
        assert_eq!(reconfigure(&mut fixture, 600, PEER_MPS - 1, &[0x0060, 0x0061]), 0x0002);
        assert_eq!(values(&fixture), before);
        assert_eq!(reconfigure(&mut fixture, 600, 250, &[0x0060, 0x0061]), 0x0000);
        assert_eq!(fixture.ecfc.bearers.get(1).map(|bearer| bearer.peer_mps), Some(250));
    }
    // A smaller MPS for one channel is allowed, and the next K-frame obeys it.
    assert_eq!(reconfigure(&mut fixture, 600, 64, &[0x0060]), 0x0000);
    assert_eq!((fixture.ecfc.bearers[0].peer_mtu, fixture.ecfc.bearers[0].peer_mps), (600, 64));
    assert_eq!(fixture.ecfc.att_mtu(BearerId::FIRST), Some(65));
    assert_eq!(
        assert_some!(assert_some!(fixture.ecfc.kframe(BearerId::FIRST, 65)).fragment(&[0; 65])).bytes().get(..6),
        Some(&[64, 0, 0x60, 0, 65, 0][..])
    );
}

#[test]
fn the_central_closes_a_bearer_with_its_cids_and_is_rejected_for_one_not_open() {
    let mut fixture = Fixture::new();
    fixture.open(1, &[0x0050]);
    // A wrong source CID is dropped silently.
    assert_eq!(fixture.command(0x06, 2, &[0x40, 0x00, 0x51, 0x00], true), None);
    assert!(fixture.ecfc.is_open(BearerId::FIRST));
    assert_eq!(fixture.send_all(), Vec::<Vec<u8>>::new());
    assert_eq!(fixture.command(0x06, 3, &[0x40, 0x00, 0x50, 0x00], true), None);
    assert!(!fixture.ecfc.is_open(BearerId::FIRST));
    // The same request again, before our response went: dropped, not
    // rejected, and answered once.
    assert_eq!(fixture.command(0x06, 3, &[0x40, 0x00, 0x50, 0x00], true), None);
    // It stays taken until our response went.
    assert_eq!(fixture.ecfc.next_signal(), Some(Signal::Released(BearerId::FIRST)));
    fixture.connect(4, &[0x0051], true);
    assert_eq!(fixture.send_all(), [response(4, if BEARERS >= 2 { 0x00 } else { 0x04 }, &expected_dcids(1, 1)), vec![
        0x07, 3, 0x04, 0x00, 0x40, 0x00, 0x50, 0x00
    ],]);
    assert_eq!(fixture.states().first(), Some(&State::Idle));
    // A bearer that is not open, idle or still to be answered, gets a
    // Command Reject, invalid CID.
    let reject = vec![0x01, 5, 0x06, 0x00, 0x02, 0x00, 0x40, 0x00, 0x50, 0x00];
    assert_eq!(fixture.command(0x06, 5, &[0x40, 0x00, 0x50, 0x00], true), Some(reject.clone()));
    fixture.connect(6, &[0x0052], true);
    assert_eq!(fixture.command(0x06, 5, &[0x40, 0x00, 0x50, 0x00], true), Some(reject));
}

#[test]
fn our_close_ends_with_its_response_a_command_reject_or_the_timeout() {
    for end in 0_i32..4_i32 {
        let mut fixture = Fixture::new();
        fixture.open(1, &[0x0050]);
        // A K-frame longer than our MPS.
        assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &[0; 68], true), None);
        assert!(!fixture.ecfc.is_open(BearerId::FIRST));
        assert_eq!(fixture.send_all(), [vec![0x06, 1, 0x04, 0x00, 0x50, 0x00, 0x40, 0x00]]);
        assert_eq!(fixture.ecfc.deadline(), Some(at(30_000)));
        // Data on it is dropped meanwhile.
        assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &[1, 0, 0x0A], true), None);
        // A response with other CIDs or another identifier is not ours.
        fixture.command(0x07, 1, &[0x51, 0x00, 0x40, 0x00], true);
        fixture.command(0x07, 2, &[0x50, 0x00, 0x40, 0x00], true);
        fixture.command(0x01, 2, &[0x00, 0x00], true);
        assert!(matches!(fixture.states().first(), Some(State::Closing { ident: 1, sent: true })));
        match end {
            0_i32 => _ = fixture.command(0x07, 1, &[0x50, 0x00, 0x40, 0x00], true),
            1_i32 => _ = fixture.command(0x01, 1, &[0x00, 0x00], true),
            2_i32 => fixture.ecfc.on_time(at(30_000), false, false),
            _ => {
                // The central closes it at the same time: answered.
                fixture.command(0x06, 7, &[0x40, 0x00, 0x50, 0x00], true);
                assert_eq!(fixture.send_all(), [vec![0x07, 7, 0x04, 0x00, 0x40, 0x00, 0x50, 0x00]]);
            },
        }
        assert_eq!(fixture.states().first(), Some(&State::Idle), "end {end}");
        assert_eq!(fixture.open(2, &[0x0050]), [response(2, 0x00, &[0x0040])]);
    }
}

#[test]
fn a_command_reject_of_our_close_leaves_the_parameter_request_waiting() {
    let mut fixture = Fixture::new();
    let request = assert_some!(fixture.signal.request_params(PARAMS));
    let asked = *assert_some!(request.bytes().get(1));
    fixture.open(1, &[0x0050]);
    fixture.ecfc.close(&mut fixture.signal, BearerId::FIRST);
    let close = fixture.send_all();
    let ident = *assert_some!(close.first().and_then(|pdu| pdu.get(1)));
    assert_ne!(ident, asked);
    // The central rejects our close: the signalling channel hands it to us,
    // not to the parameter request.
    let reject = [0x01, ident, 0x02, 0x00, 0x00, 0x00];
    assert_eq!(fixture.signal.receive(&reject), Some(Action::Ecfc { code: 0x01, identifier: ident }));
    fixture.command(0x01, ident, &reject[4..], true);
    assert_eq!(fixture.states().first(), Some(&State::Idle));
    assert!(fixture.signal.pending());
    // The response to the parameter request still matches it.
    assert_eq!(
        fixture.signal.receive(&[0x13, asked, 0x02, 0x00, 0x00, 0x00]),
        Some(Action::Outcome(Outcome::Accepted))
    );
}

#[test]
fn k_frames_take_credits_and_the_credits_come_back_in_steps_of_128() {
    let mut fixture = Fixture::new();
    fixture.open(1, &[0x0050]);
    let read = [3, 0, 0x0A, 0x03, 0x00];
    let mut indications = 0_i32;
    for count in 1_i32..=1_000_i32 {
        let (sdu, encrypted) = assert_some!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &read, true));
        assert_eq!((sdu, encrypted), (&read[2..], true));
        for command in fixture.send_all() {
            assert_eq!(count.strict_rem(128_i32), 0_i32);
            assert_eq!(command.first(), Some(&0x16));
            assert_eq!(command.get(2..), Some(&[0x04, 0x00, 0x40, 0x00, 128, 0x00][..]));
            indications += 1_i32;
        }
    }
    assert_eq!(indications, 7_i32);
    assert_eq!(fixture.ecfc.bearers[0].rx_credits, 256_u16.strict_sub(1_000_u16.strict_rem(128)));
    // A plaintext K-frame gives a plaintext SDU.
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &read, false), Some((&read[2..], false)));
}

#[test]
fn a_k_frame_without_a_credit_closes_the_bearer() {
    let mut fixture = Fixture::new();
    fixture.open(1, &[0x0050]);
    for _ in 0_i32..256_i32 {
        assert!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &[1, 0, 0x0A], true).is_some());
    }
    // The 0x16 was owed but not sent.
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &[1, 0, 0x0A], true), None);
    assert!(!fixture.ecfc.is_open(BearerId::FIRST));
    let sent = fixture.send_all();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent.first().and_then(|pdu| pdu.first()), Some(&0x06));
}

#[test]
fn a_split_sdu_is_joined_and_k_frames_that_break_the_rules_close_the_bearer() {
    let sdu: Vec<u8> = (0..65).collect();
    let mut fixture = Fixture::new();
    fixture.open(1, &[0x0050]);
    let first = [&[65, 0][..], sdu.get(..30).unwrap_or_default()].concat();
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &first, true), None);
    assert_eq!(
        fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, sdu.get(30..).unwrap_or_default(), false),
        Some(((&*sdu), false))
    );
    // An SDU longer than our MTU.
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &[66, 0, 0x0A], true), None);
    assert!(!fixture.ecfc.is_open(BearerId::FIRST));
    for kframe in [&[0_u8][..], &[1, 0, 0x0A, 0x0B][..], &[0; 68][..]] {
        let mut fresh = Fixture::new();
        fresh.open(1, &[0x0050]);
        assert_eq!(fresh.ecfc.receive(&mut fresh.signal, BearerId::FIRST, kframe, true), None);
        assert!(!fresh.ecfc.is_open(BearerId::FIRST), "{kframe:?}");
    }
    if BEARERS >= 2 {
        // A second split SDU while the first fills the buffer closes its
        // bearer only.
        fixture = Fixture::new();
        fixture.open(1, &[0x0050, 0x0051]);
        assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &first, true), None);
        // A whole SDU on the other bearer passes meanwhile.
        assert_eq!(
            fixture.ecfc.receive(&mut fixture.signal, BearerId::valid(1), &[1, 0, 0x0A], true),
            Some((&[0x0A][..], true))
        );
        assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::valid(1), &first, true), None);
        assert!(fixture.ecfc.is_open(BearerId::FIRST));
        assert!(!fixture.ecfc.is_open(BearerId::valid(1)));
        assert_eq!(
            fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, sdu.get(30..).unwrap_or_default(), true),
            Some(((&*sdu), true))
        );
    }
}

#[test]
fn closing_a_bearer_drops_its_split_sdu() {
    let sdu: Vec<u8> = (0..65).collect();
    let mut fixture = Fixture::new();
    fixture.open(1, &[0x0050]);
    let first = [&[65, 0][..], sdu.get(..30).unwrap_or_default()].concat();
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &first, true), None);
    fixture.command(0x06, 2, &[0x40, 0x00, 0x50, 0x00], true);
    fixture.send_all();
    fixture.open(3, &[0x0051]);
    // The new bearer's first K-frame is a first one, and the buffer is free.
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &first, true), None);
    assert_eq!(
        fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, sdu.get(30..).unwrap_or_default(), true),
        Some(((&*sdu), true))
    );
}

#[test]
fn data_is_dropped_on_a_bearer_that_is_not_open() {
    let mut fixture = Fixture::new();
    let read = [1, 0, 0x0A];
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &read, true), None);
    fixture.connect(1, &[0x0050], false);
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &read, true), None);
    fixture.ecfc.resolve_holds();
    assert_eq!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &read, true), None);
    fixture.send_all();
    assert!(fixture.ecfc.receive(&mut fixture.signal, BearerId::FIRST, &read, true).is_some());
    assert_eq!(BearerId::new(BEARERS), None);
}

#[test]
fn an_sdu_goes_out_in_k_frames_of_the_peer_s_mps_one_credit_each() {
    for (mps, kframes) in [(64_u16, vec![64_usize, 3]), (67, vec![67]), (247, vec![67])] {
        let mut fixture = Fixture::new();
        let mut data = request_data(&[0x0050], 1);
        data.get_mut(4..6).unwrap_or_default().copy_from_slice(&mps.to_le_bytes());
        fixture.command(0x17, 1, &data, true);
        fixture.send_all();
        let sdu: Vec<u8> = (100..165).collect();
        let mut joined = Vec::new();
        for (index, &len) in kframes.iter().enumerate() {
            let Some(mut segmenter) = ({
                let value = fixture.ecfc.kframe(BearerId::FIRST, sdu.len());
                assert!(value.is_some(), "no credit for K-frame {index} at MPS {mps}");
                value
            }) else {
                return;
            };
            assert_eq!(segmenter.channel(), Channel::Eatt(BearerId::FIRST));
            let mut frame = Vec::new();
            let mut fragments = Vec::new();
            while let Some(fragment) = segmenter.fragment(&sdu) {
                assert_eq!(fragment.start(), frame.is_empty());
                if fragment.start() {
                    // The credit goes with the first fragment.
                    let last = fixture.ecfc.kframe_queued(BearerId::FIRST, &segmenter);
                    assert_eq!(last, index + 1 == kframes.len());
                }
                fragments.push(fragment.bytes().len());
                frame.extend_from_slice(fragment.bytes());
                segmenter.advance();
            }
            // The peer's CID, not ours, is in the header.
            assert_eq!(frame.get(..4), Some(&[len.truncate::<u8>(), 0, 0x50, 0x00][..]));
            assert_eq!(frame.len(), 4 + len);
            if index == 0 {
                assert_eq!(frame.get(4..6), Some(&[65, 0][..]));
                joined.extend_from_slice(frame.get(6..).unwrap_or_default());
            } else {
                joined.extend_from_slice(frame.get(4..).unwrap_or_default());
            }
            if len == 67 {
                assert_eq!(fragments, [27, 27, 17]);
            }
            assert_eq!(fixture.ecfc.kframe(BearerId::FIRST, sdu.len()), None, "one credit, one K-frame");
            fixture.command(0x16, 2, &[0x50, 0x00, 0x01, 0x00], true);
        }
        assert_eq!(joined, sdu);
        // The next SDU starts with a first K-frame again.
        let next = assert_some!(fixture.ecfc.kframe(BearerId::FIRST, 5));
        assert_eq!(assert_some!(next.fragment(&[1, 2, 3, 4, 5])).bytes(), [7, 0, 0x50, 0x00, 5, 0, 1, 2, 3, 4, 5]);
    }
}

/// Checks what must hold of the channels whatever they were given.
fn check(ecfc: &Ecfc) {
    let used: Vec<u16> =
        ecfc.bearers.iter().filter(|bearer| bearer.state != State::Idle).map(|bearer| bearer.peer_cid).collect();
    for (index, cid) in used.iter().enumerate() {
        assert!((0x0040..=0x007F).contains(cid));
        assert!(!used.get(index.strict_add(1)..).unwrap_or_default().contains(cid), "a source CID on two bearers");
    }
    for entry in ecfc.pending.iter().filter(|entry| entry.ident != 0) {
        assert!(usize::from(entry.count) <= 5);
        assert_eq!(ecfc.pending.iter().filter(|other| other.ident == entry.ident).count(), 1);
    }
    for bearer in &ecfc.bearers {
        if let State::Answer { ident, pos } | State::Held { ident, pos } = bearer.state {
            let entry = assert_some!(
                ecfc.pending.iter().find(|entry| entry.ident == ident),
                "a reservation without its request"
            );
            assert!(pos < entry.count);
            assert_eq!(matches!(bearer.state, State::Held { ident: _, pos: _ }), entry.held);
        }
        assert!(bearer.rx_credits <= RX_CREDITS);
    }
}

/// A fuzz step: a command through the signalling channel, of `data` mostly
/// well formed.
fn fuzz_command(rng: &mut Rng, fixture: &mut Fixture, data: &mut [u8; 24], seen: &mut Seen) {
    seen.pdus = seen.pdus.strict_add(1);
    let code = rng.pick(&[0x01, 0x06, 0x07, 0x13, 0x14, 0x16, 0x17, 0x17, 0x17, 0x17, 0x18, 0x19, 0x1A, 0x30]);
    let identifier = if rng.below(20) == 0 { 0 } else { rng.below(8).truncate::<u8>().strict_add(1) };
    let mut len = rng.below(23).strict_cast::<usize>();
    match code {
        0x17 if rng.below(4) != 0 => {
            let count = rng.below(5).strict_cast::<usize>().strict_add(1);
            data[..2].copy_from_slice(&[0x27, 0x00]);
            data[2..4].copy_from_slice(&rng.pick(&[64_u16, 65, 517, 517, 63]).to_le_bytes());
            data[4..6].copy_from_slice(&rng.pick(&[64_u16, 67, 247, 247, 63]).to_le_bytes());
            data[6..8].copy_from_slice(&rng.pick(&[1_u16, 10, 10, 0xFFFF, 0]).to_le_bytes());
            let mut cid = rng.cid();
            for pos in 0..count {
                let at = pos.strict_mul(2).strict_add(8);
                data.get_mut(at..at.strict_add(2)).unwrap_or_default().copy_from_slice(&cid.to_le_bytes());
                cid = if rng.below(4) == 0 { rng.cid() } else { cid.wrapping_add(1) };
            }
            len = count.strict_mul(2).strict_add(8);
        },
        0x06 | 0x07 | 0x16 if rng.below(4) != 0 => {
            // Mostly with the CIDs of a bearer, ours and the peer's,
            // in the order of the command.
            let bearer = rng.below(BEARERS.strict_cast::<u64>()).strict_cast::<usize>();
            let ours = bearer.truncate::<u16>().strict_add(0x0040);
            let peer =
                if rng.below(4) == 0 { rng.cid() } else { assert_some!(fixture.ecfc.bearers.get(bearer)).peer_cid };
            let (first, second) = match code {
                0x06 => (ours, peer),
                0x07 => (peer, ours),
                _ => (peer, rng.pick(&[1, 128, 0, 0xFFFF])),
            };
            data[..2].copy_from_slice(&first.to_le_bytes());
            data[2..4].copy_from_slice(&second.to_le_bytes());
            len = 4;
        },
        _ => {},
    }
    let mut pdu = vec![code, identifier, len.truncate::<u8>(), 0];
    pdu.extend_from_slice(data.get(..len).unwrap_or_default());
    if rng.below(30) == 0 {
        pdu.truncate(rng.below(pdu.len().strict_cast::<u64>().strict_add(1)).strict_cast::<usize>());
    }
    if let Some(Action::Ecfc { code: handed_code, identifier: handed_identifier }) = fixture.signal.receive(&pdu) {
        seen.commands = seen.commands.strict_add(1);
        let secure = rng.below(3) != 0;
        if let Some(reply) = fixture.ecfc.command(
            &mut fixture.signal,
            handed_code,
            handed_identifier,
            pdu.get(4..).unwrap_or_default(),
            secure,
            fixture.now,
        ) {
            assert!(reply.bytes().len() <= 12);
        }
    }
}

/// A fuzz step: a K-frame on a bearer, whole, split or broken.
fn fuzz_kframe(rng: &mut Rng, fixture: &mut Fixture, reassembly: &mut Reassembly, seen: &mut Seen) {
    seen.pdus = seen.pdus.strict_add(1);
    let number = rng.below(BEARERS.strict_cast::<u64>().strict_add(1)).truncate::<u8>();
    let bearer = BearerId::new(usize::from(number));
    let len = match rng.below(20) {
        // Whole SDUs mostly, of 1 to 65 octets.
        0..=15 => rng.below(65).strict_cast::<usize>().strict_add(3),
        16 => rng.pick(&[0, 1, 2]),
        _ => rng.pick(&[30, 32, 35, 66, 68, 69, 70]),
    };
    let mut kframe: Vec<u8> = repeat_with(|| rng.next().truncate::<u8>()).take(len).collect();
    if rng.below(10) != 0 && len >= 2 {
        let total =
            if rng.below(4) != 0 { len.truncate::<u16>().strict_sub(2) } else { rng.pick(&[65, 64, 66, 0, 33]) };
        kframe.get_mut(..2).unwrap_or_default().copy_from_slice(&total.to_le_bytes());
    }
    let encrypted = rng.below(2) == 0;
    if rng.below(2) == 0 {
        // Directly.
        if let Some(on) = bearer
            && let Some((sdu, _)) = fixture.ecfc.receive(&mut fixture.signal, on, &kframe, encrypted)
        {
            assert!(sdu.len() <= 65);
            seen.sdus = seen.sdus.strict_add(1);
        }
    } else {
        // Through the reassembly, in fragments of up to 27.
        let mut frame = kframe.len().truncate::<u16>().to_le_bytes().to_vec();
        frame.extend_from_slice(&(0x0040 + u16::from(number)).to_le_bytes());
        frame.extend_from_slice(&kframe);
        for (index, fragment) in frame.chunks(27).enumerate() {
            if let Some(pdu) = reassembly.push(index == 0, encrypted, fragment) {
                let Channel::Eatt(on) = ({
                    let value = pdu.channel;
                    assert!(matches!(value, Channel::Eatt(_)), "{:?}", pdu.channel);
                    value
                }) else {
                    return;
                };
                assert_eq!(Some(on), bearer);
                let payload = pdu.payload.to_vec();
                if let Some((sdu, _)) = fixture.ecfc.receive(&mut fixture.signal, on, &payload, pdu.encrypted) {
                    assert!(sdu.len() <= 65);
                    seen.sdus = seen.sdus.strict_add(1);
                }
            }
        }
        if let Some(on) = reassembly.take_overlong() {
            assert_eq!((Some(on), len > 68), (bearer, true));
            seen.overlong = seen.overlong.strict_add(1);
            fixture.ecfc.close(&mut fixture.signal, on);
        }
    }
}

/// A fuzz step: our side sends what waits, or part of it.
fn fuzz_signals(rng: &mut Rng, fixture: &mut Fixture, seen: &mut Seen) {
    for _ in 0..rng.below(4) {
        let Some(signal) = fixture.ecfc.next_signal() else { break };
        let mut out = [0_u8; SIGNAL_MAX];
        let len = fixture.ecfc.render(signal, &mut out);
        assert!(len > 0 && len <= SIGNAL_MAX);
        match signal {
            Signal::Response(_) => {
                assert!(len.strict_sub(12).strict_div(2) <= 5);
                let (pairs, odd) = out.get(12..len).unwrap_or_default().as_chunks::<2>();
                assert!(odd.is_empty(), "destination CIDs of two octets");
                let dcids: Vec<u16> =
                    pairs.iter().map(|&cid| u16::from_le_bytes(cid)).filter(|&cid| cid != 0).collect();
                for (index, dcid) in dcids.iter().enumerate() {
                    assert!(BearerId::from_cid(*dcid).is_some());
                    assert!(!dcids.get(index.strict_add(1)..).unwrap_or_default().contains(dcid));
                }
                seen.opened = seen.opened.strict_add(dcids.len());
                if matches!(out[10], 0x05 | 0x08) {
                    seen.security = seen.security.strict_add(1);
                }
            },
            Signal::Close(_) => seen.closes = seen.closes.strict_add(1),
            Signal::Released(_) => seen.releases = seen.releases.strict_add(1),
            Signal::Credits { bearer: _, credits } => {
                assert!(credits >= 128);
                seen.credits = seen.credits.strict_add(1);
            },
        }
        fixture.ecfc.signal_sent(signal, fixture.now);
    }
}

/// A fuzz step: an SDU goes out on a bearer.
fn fuzz_sdu(rng: &mut Rng, fixture: &mut Fixture, seen: &mut Seen) {
    let bearer = BearerId::valid(rng.below(BEARERS.strict_cast::<u64>()).truncate::<u8>());
    let len = rng.below(65).strict_cast::<usize>().strict_add(1);
    let sdu: Vec<u8> = repeat_with(|| rng.next().truncate::<u8>()).take(len).collect();
    if let Some(mut segmenter) = fixture.ecfc.kframe(bearer, sdu.len()) {
        seen.kframes = seen.kframes.strict_add(1);
        let mut first = true;
        while let Some(fragment) = segmenter.fragment(&sdu) {
            assert!(fragment.bytes().len() <= FRAGMENT_MAX);
            if first {
                fixture.ecfc.kframe_queued(bearer, &segmenter);
                first = false;
            }
            segmenter.advance();
        }
    }
}

/// A fuzz step: a burst of SDUs, the holds, a close, a new link or the
/// deadline.
fn fuzz_other(rng: &mut Rng, fixture: &mut Fixture, seen: &mut Seen) {
    match rng.below(6) {
        5 if rng.below(8) == 0 => {
            // A burst of whole SDUs on one bearer, past the top up.
            let bearer = BearerId::valid(rng.below(BEARERS.strict_cast::<u64>()).truncate::<u8>());
            for _ in 0_i32..130_i32 {
                seen.pdus = seen.pdus.strict_add(1);
                if fixture.ecfc.receive(&mut fixture.signal, bearer, &[1, 0, 0x0A], true).is_some() {
                    seen.sdus = seen.sdus.strict_add(1);
                }
            }
        },
        0 => fixture.ecfc.resolve_holds(),
        1 => fixture.ecfc.refuse_holds(rng.below(2) == 0),
        2 if rng.below(10) == 0 => {
            if let Some(bearer) =
                BearerId::new(rng.below(BEARERS.strict_cast::<u64>().strict_add(1)).strict_cast::<usize>())
            {
                fixture.ecfc.close(&mut fixture.signal, bearer);
            }
        },
        3 if rng.below(100) == 0 => *fixture = Fixture { now: fixture.now, ..Fixture::new() },
        _ => {
            if fixture.ecfc.deadline().is_some_and(|deadline| deadline <= fixture.now) {
                fixture.ecfc.on_time(fixture.now, rng.below(2) == 0, rng.below(2) == 0);
            }
        },
    }
}

#[test]
fn fuzzing_commands_and_k_frames_never_panics_and_keeps_the_invariants() {
    // `cargo test` builds with overflow checks, so any overflow panics.
    const { assert!(cfg!(overflow_checks)) };
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let mut fixture = Fixture::new();
    let mut reassembly = Reassembly::new();
    let mut seen = Seen::default();
    let mut millis = 0_u64;
    while seen.pdus < 100_000 {
        millis += rng.below(50);
        fixture.now = at(millis);
        let mut data = [0_u8; 24];
        for octet in &mut data {
            *octet = rng.next().truncate::<u8>();
        }
        match rng.below(10) {
            0..=4 => fuzz_command(&mut rng, &mut fixture, &mut data, &mut seen),
            5 | 6 => fuzz_kframe(&mut rng, &mut fixture, &mut reassembly, &mut seen),
            7 => fuzz_signals(&mut rng, &mut fixture, &mut seen),
            8 => fuzz_sdu(&mut rng, &mut fixture, &mut seen),
            _ => fuzz_other(&mut rng, &mut fixture, &mut seen),
        }
        check(&fixture.ecfc);
    }
    for (what, count) in [
        ("opened", seen.opened),
        ("commands", seen.commands),
        ("sdus", seen.sdus),
        ("closes", seen.closes),
        ("releases", seen.releases),
        ("security", seen.security),
        ("kframes", seen.kframes),
        ("overlong", seen.overlong),
    ] {
        assert!(count >= 100, "only {count} {what}: {seen:?}");
    }
    assert!(seen.credits >= 5, "only {} credits: {seen:?}", seen.credits);
}

#[test]
fn the_channels_take_16_bytes_per_bearer_beside_the_requests_deadlines_and_sdu_buffer() {
    assert_eq!(size_of::<Bearer>(), 16);
    assert_eq!(size_of::<Pending>(), 4);
    assert_eq!(size_of::<SduRx>(), 70);
    // Two deadlines of 16 bytes, 5 requests of 4, the SDU buffer, padding.
    assert!(size_of::<Ecfc>() <= 128 + 16 * BEARERS);
}
