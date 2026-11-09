//! Tests of the advertising data writer, the modes and their setup of the
//! link layer.

use super::*;
use crate::{
    host::{
        gatt::spotlight::DB,
        identity::{DeviceSecret, Variant},
        test_aes::Software,
    },
    link::Shared,
};
use core::cell::RefCell;

/// The bonded central: BlueZ's public identity address.
const CENTRAL: Peer = Peer::new([1, 2, 3, 4, 5, 6], false);
/// The central's identity resolving key.
const CENTRAL_IRK: [u8; 16] = [0x33; 16];

/// A call as the stand-in records it, with the data copied.
#[derive(Clone, Copy, PartialEq)]
enum Seen {
    /// See [`Call::AcceptListAdd`].
    AcceptListAdd(Peer),
    /// See [`Call::AcceptListClear`].
    AcceptListClear,
    /// See [`Call::AddPeer`].
    AddPeer(Peer, [u8; 16], [u8; 16]),
    /// See [`Call::Advertise`]: filter policy, interval, private, the data.
    Advertise(u8, u16, bool, Data, Data),
    /// See [`Call::ClearPeers`].
    ClearPeers,
    /// See [`Call::SetAddressResolution`].
    SetAddressResolution(bool),
    /// See [`Call::SetIdentity`].
    SetIdentity([u8; 6]),
    /// See [`Call::SetPrivacyMode`].
    SetPrivacyMode(Peer, bool),
    /// See [`Call::SetRpaTimeout`].
    SetRpaTimeout(u16),
    /// See [`Call::StopAdvertising`].
    StopAdvertising,
}

/// A stand-in for the link layer: records the calls, and refuses the one
/// at `fail_at` if set.
struct Recorder {
    /// The calls so far and their number.
    calls:   RefCell<([Option<Seen>; 16], usize)>,
    /// The index of the call to refuse, with [`link::Error::Disallowed`].
    fail_at: Option<usize>,
}

impl Recorder {
    /// A recorder that refuses nothing.
    const fn new() -> Self { Self { calls: RefCell::new(([None; 16], 0)), fail_at: None } }

    /// Whether the calls so far are `expected`.
    fn saw(&self, expected: &[Seen]) -> bool {
        let calls = self.calls.borrow();
        calls.1 == expected.len() && calls.0.iter().zip(expected).all(|(seen, wanted)| *seen == Some(*wanted))
    }
}

impl Control for Recorder {
    fn call(&self, call: Call<'_>) -> Result<(), link::Error> {
        let seen = match call {
            Call::AcceptListAdd(peer) => Seen::AcceptListAdd(peer),
            Call::AcceptListClear => Seen::AcceptListClear,
            Call::AddPeer { identity, local_irk, peer_irk } => Seen::AddPeer(identity, peer_irk, local_irk),
            Call::Advertise { adv, params, scan } => {
                let mut data = Data::new();
                let mut response = Data::new();
                data.bytes[..adv.len()].copy_from_slice(adv);
                data.len = u8::try_from(adv.len()).unwrap();
                response.bytes[..scan.len()].copy_from_slice(scan);
                response.len = u8::try_from(scan.len()).unwrap();
                assert!(params.kind == Kind::ConnectableUndirected && params.channel_map == 0x07);
                Seen::Advertise(params.filter_policy, params.interval, params.private, data, response)
            },
            Call::ClearPeers => Seen::ClearPeers,
            Call::SetAddressResolution(enable) => Seen::SetAddressResolution(enable),
            Call::SetIdentity(address) => Seen::SetIdentity(address),
            Call::SetPrivacyMode { device, identity } => Seen::SetPrivacyMode(identity, device),
            Call::SetRpaTimeout(seconds) => Seen::SetRpaTimeout(seconds),
            Call::StopAdvertising => Seen::StopAdvertising,
        };
        let mut calls = self.calls.borrow_mut();
        let index = calls.1;
        if self.fail_at == Some(index) {
            return Err(link::Error::Disallowed);
        }
        calls.0[index] = Some(seen);
        calls.1 += 1;
        Ok(())
    }
}

/// Our identity in generation `generation`.
fn identity(generation: u8) -> LocalIdentity {
    LocalIdentity::derive(&Software, &DeviceSecret::new([1; 16], [2; 16]), Variant::new(0, generation))
}

/// A bond with [`CENTRAL`] under our identity of generation 1, with the
/// central's key if `irk`.
fn bond(irk: bool) -> Bond { Bond::new(CENTRAL, irk.then_some(CENTRAL_IRK), [0x44; 16], Variant::new(0, 1), &DB) }

#[test]
fn structures_are_written_with_their_length_and_type() {
    let mut data = Data::new();
    assert!(data.is_empty());
    data.flags(0x06).unwrap().services(&[0x1812, 0x180F]).unwrap().appearance(0x03C1).unwrap();
    data.name(b"Ab").unwrap().short_name(b"A").unwrap().tx_power(-4).unwrap();
    assert_eq!(data.as_bytes(), &[
        2, 0x01, 0x06, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0xC1, 0x03, 3, 0x09, b'A', b'b', 2, 0x08, b'A', 2,
        0x0A, 0xFC,
    ]);
    assert_eq!(data.len(), 23);
    assert!(Data::default() == Data::new());
}

#[test]
fn a_structure_that_does_not_fit_is_refused_and_changes_nothing() {
    let mut data = Data::new();
    // 29 octets of data fill the 31 exactly.
    data.push(0xFF, &[7; 29]).unwrap();
    assert_eq!(data.len(), DATA_MAX);
    assert_eq!(data.flags(0x06).err(), Some(Overflow::TooLong));
    let mut data = Data::new();
    data.flags(0x06).unwrap();
    let before = data;
    assert_eq!(data.push(0xFF, &[7; 27]).err(), Some(Overflow::TooLong));
    assert!(data == before);
    // Fourteen services fit an empty set, fifteen do not.
    assert!(Data::new().services(&[0x1800; 14]).is_ok());
    assert_eq!(Data::new().services(&[0x1800; 15]).err(), Some(Overflow::TooLong));
    assert_eq!(Data::new().push(0xFF, &[0; 300]).err(), Some(Overflow::TooLong));
}

#[test]
fn a_long_name_is_shortened_at_a_character_boundary() {
    let mut data = Data::new();
    assert_eq!(data.name_fitting(b"Spotlight"), Ok(false));
    assert_eq!(data.as_bytes()[..2], [10, AD_NAME]);
    // 27 octets of data leave room for a name of 2 octets: "a" and the
    // first octet of a two octet character would be cut before the latter.
    let mut data = Data::new();
    data.push(0xFF, &[0; 25]).unwrap();
    assert_eq!(data.name_fitting("a\u{e4}b".as_bytes()), Ok(true));
    assert_eq!(data.as_bytes()[27..], [2, AD_SHORT_NAME, b'a']);
    // No room for a single character.
    let mut data = Data::new();
    data.push(0xFF, &[0; 26]).unwrap();
    assert_eq!(data.name_fitting("\u{e4}\u{e4}".as_bytes()), Err(Overflow::TooLong));
    assert_eq!(data.len(), 28);
}

#[test]
fn the_spotlight_pairs_discoverably_with_its_name() {
    let advertising = Advertising::spotlight(Mode::Pairing, None).unwrap();
    let adv = advertising.data().as_bytes();
    let head = [2, 0x01, 0x06, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0xC1, 0x03];
    assert_eq!(adv[..head.len()], head);
    if option_env!("SPOTLIGHT_DEVICE_NAME").is_none() {
        // "Presenter Zuhause" (17 octets) leaves 16 in the advertising: the
        // name is shortened there and complete in the scan response.
        assert_eq!(adv[head.len()..], *[&[17, AD_SHORT_NAME][..], b"Presenter Zuhaus"].concat());
        assert_eq!(advertising.scan().as_bytes(), [&[18, AD_NAME][..], b"Presenter Zuhause"].concat());
    }
    assert!(advertising.schedule() == &SPOTLIGHT_PAIRING);
    assert!(advertising.mode().pairable() && advertising.mode().discoverable());
}

#[test]
fn the_spotlight_reconnects_without_name_or_discoverability() {
    let bond = bond(false);
    let advertising = Advertising::spotlight(Mode::Reconnect(&bond), Some(-8)).unwrap();
    assert_eq!(advertising.data().as_bytes(), &[2, 0x01, 0x04, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0xC1, 0x03]);
    assert_eq!(advertising.scan().as_bytes(), &[2, AD_TX_POWER, 0xF8]);
    assert!(advertising.schedule() == &SPOTLIGHT_RECONNECT);
    assert!(!advertising.mode().pairable() && !advertising.mode().discoverable());
}

#[test]
fn a_name_too_long_for_the_advertising_data_is_complete_in_the_scan_response() {
    let content = Content { name: b"A remote with a long name", ..Content::SPOTLIGHT };
    let (adv, scan) = content.data(true).unwrap();
    assert_eq!(adv.len(), DATA_MAX);
    assert_eq!(adv.as_bytes()[13..15], [17, AD_SHORT_NAME]);
    assert_eq!(&adv.as_bytes()[15..], b"A remote with a ");
    assert_eq!(scan.as_bytes()[..2], [26, AD_NAME]);
    assert_eq!(&scan.as_bytes()[2..], b"A remote with a long name");
    // A name that fits neither is refused.
    let content = Content { name: &[b'x'; 30], ..Content::SPOTLIGHT };
    assert_eq!(content.data(true).err(), Some(Overflow::TooLong));
    // Without discoverability the name does not matter.
    assert!(content.data(false).is_ok());
}

#[test]
fn the_spotlight_phases_take_a_minute() {
    let schedule = SPOTLIGHT_PAIRING;
    assert_eq!(schedule.total(), Duration::from_secs(60));
    assert_eq!(schedule.security_deadline, Duration::from_secs(60));
    assert_eq!(SPOTLIGHT_RECONNECT.security_deadline, Duration::from_secs(20));
    let interval = |millis| schedule.phase_at(Duration::from_millis(millis)).map(|phase| phase.interval);
    assert_eq!(interval(0), Some(32));
    assert_eq!(interval(2_999), Some(32));
    assert_eq!(interval(3_000), Some(80));
    assert_eq!(interval(14_999), Some(80));
    assert_eq!(interval(15_000), Some(640));
    assert_eq!(interval(59_999), Some(640));
    assert_eq!(interval(60_000), None);
    // 20 ms, 50 ms and 400 ms.
    assert_eq!(SPOTLIGHT_PHASES.map(|phase| u32::from(phase.interval) * 625), [20_000, 50_000, 400_000]);
}

#[test]
fn reconnection_filters_on_the_accept_list_and_both_modes_are_private() {
    let bond = bond(false);
    let phase = SPOTLIGHT_PHASES[1];
    let pairing = Mode::Pairing.params(&phase);
    assert!(pairing.filter_policy == 0 && pairing.private && pairing.interval == 80);
    let reconnect = Mode::Reconnect(&bond).params(&phase);
    assert!(reconnect.filter_policy == 0x03 && reconnect.private && reconnect.interval == 80);
}

#[test]
fn pairing_sets_our_key_and_no_central() {
    let recorder = Recorder::new();
    let identity = identity(1);
    let advertising = Advertising::spotlight(Mode::Pairing, None).unwrap();
    advertising.configure(&recorder, &identity).unwrap();
    assert!(recorder.saw(&[
        Seen::StopAdvertising,
        Seen::SetAddressResolution(false),
        Seen::SetIdentity(identity.address()),
        Seen::ClearPeers,
        Seen::AcceptListClear,
        Seen::AddPeer(NO_PEER, [0; 16], identity.irk()),
        Seen::SetRpaTimeout(900),
    ]));
}

#[test]
fn reconnection_lets_only_the_bonded_central_in_through_the_resolving_list() {
    let recorder = Recorder::new();
    let identity = identity(1);
    let bond = bond(true);
    let advertising = Advertising::spotlight(Mode::Reconnect(&bond), None).unwrap();
    advertising.configure(&recorder, &identity).unwrap();
    assert!(recorder.saw(&[
        Seen::StopAdvertising,
        Seen::SetAddressResolution(false),
        Seen::SetIdentity(identity.address()),
        Seen::ClearPeers,
        Seen::AcceptListClear,
        Seen::AddPeer(CENTRAL, CENTRAL_IRK, identity.irk()),
        Seen::SetPrivacyMode(CENTRAL, true),
        Seen::AcceptListAdd(CENTRAL),
        Seen::SetAddressResolution(true),
        Seen::SetRpaTimeout(900),
    ]));
}

#[test]
fn a_bond_of_another_identity_is_refused_before_any_call() {
    let recorder = Recorder::new();
    let bond = bond(false);
    let advertising = Advertising::spotlight(Mode::Reconnect(&bond), None).unwrap();
    assert_eq!(advertising.configure(&recorder, &identity(2)), Err(Error::WrongIdentity));
    assert!(recorder.saw(&[]));
}

#[test]
fn a_refused_call_ends_the_setup() {
    let recorder = Recorder { fail_at: Some(2), ..Recorder::new() };
    let advertising = Advertising::spotlight(Mode::Pairing, None).unwrap();
    assert_eq!(advertising.configure(&recorder, &identity(0)), Err(Error::Link(link::Error::Disallowed)));
    assert!(recorder.saw(&[Seen::StopAdvertising, Seen::SetAddressResolution(false)]));
}

#[test]
fn each_phase_starts_with_its_interval_and_the_modes_data() {
    let recorder = Recorder::new();
    let bond = bond(false);
    let advertising = Advertising::spotlight(Mode::Reconnect(&bond), None).unwrap();
    for phase in &SPOTLIGHT_PHASES {
        advertising.start(&recorder, phase).unwrap();
    }
    let seen = |interval| Seen::Advertise(0x03, interval, true, *advertising.data(), *advertising.scan());
    assert!(recorder.saw(&[seen(32), seen(80), seen(640)]));
}

#[test]
fn the_link_layer_takes_the_reconnection_setup() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let identity = identity(1);
    let bond = bond(true);
    let advertising = Advertising::spotlight(Mode::Reconnect(&bond), None).unwrap();
    advertising.configure(&link, &identity).unwrap();
    // A private address needs the chip's RNG and AES, so the link layer is
    // checked advertising from the identity address.
    let params = advertising.mode().params(&SPOTLIGHT_PHASES[0]).private(false);
    link.advertise(&params, advertising.data().as_bytes(), advertising.scan().as_bytes()).unwrap();
    let settings = shared.advertising().unwrap();
    assert!(settings.address == identity.peer() && settings.own == identity.peer());
    assert_eq!(settings.filter_policy, 0x03);
    assert!(settings.filter.contains(CENTRAL));
    assert!(settings.resolution_enabled);
    assert_eq!(settings.resolving.local_key(None), Some(identity.irk()));
    assert_eq!(settings.interval, 20_000);
    // Setting up again stops the advertising first, and pairing forgets the
    // central.
    let pairing = Advertising::spotlight(Mode::Pairing, None).unwrap();
    pairing.configure(&link, &identity).unwrap();
    assert!(shared.advertising().is_none());
    link.advertise(&pairing.mode().params(&SPOTLIGHT_PHASES[0]).private(false), &[], &[]).unwrap();
    let settings = shared.advertising().unwrap();
    assert_eq!(settings.filter_policy, 0);
    assert!(!settings.filter.contains(CENTRAL));
    assert!(!settings.resolution_enabled);
    assert_eq!(settings.resolving.local_key(None), Some(identity.irk()));
    assert_eq!(settings.resolving.local_key(Some(CENTRAL)), None);
}

#[test]
fn the_link_layer_refuses_to_start_while_a_central_is_connected() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let advertising = Advertising::spotlight(Mode::Pairing, None).unwrap();
    // Without an identity address.
    assert_eq!(advertising.start(&link, &SPOTLIGHT_PHASES[0]), Err(Error::Link(link::Error::Invalid)));
    advertising.configure(&link, &identity(0)).unwrap();
    shared.set_connected(true);
    assert_eq!(advertising.start(&link, &SPOTLIGHT_PHASES[0]), Err(Error::Link(link::Error::Disallowed)));
    assert!(shared.advertising().is_none());
}

#[test]
fn the_spotlight_name_is_shortened_in_the_advertising_and_complete_in_the_scan_response() {
    let (adv, scan) = Content::SPOTLIGHT.data(true).unwrap();
    let field = |data: &[u8], kind: u8| {
        let mut rest = data;
        while let [len, kind_here, tail @ ..] = rest {
            let len = usize::from(*len);
            let (value, next) = tail.split_at(len - 1);
            if *kind_here == kind {
                return Some(value.to_vec());
            }
            rest = next;
        }
        None
    };
    let complete = field(scan.as_bytes(), AD_NAME).unwrap_or_else(|| field(adv.as_bytes(), AD_NAME).unwrap());
    assert_eq!(complete, spotlight::NAME);
    if let Some(short) = field(adv.as_bytes(), AD_SHORT_NAME) {
        assert!(spotlight::NAME.starts_with(&short));
    }
    assert!(adv.as_bytes().len() <= 31 && scan.as_bytes().len() <= 31);
}
