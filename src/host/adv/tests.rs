//! Tests of the advertising data writer, the modes and their setup of the
//! link layer.

extern crate alloc;

use super::*;
use crate::{
    host::{
        example::{self, DB},
        identity::{DeviceSecret, Variant},
        test_aes::Software,
    },
    link::Shared,
    pdu::IdentityAddress,
};
use alloc::boxed::Box;
use core::cell::RefCell;

/// The bonded central: `BlueZ`'s public identity address.
const CENTRAL: Peer = Peer::new([1, 2, 3, 4, 5, 6], false);
/// The central's identity resolving key.
const CENTRAL_IRK: [u8; 16] = [0x33; 16];

/// A call as the stand-in records it, with the data copied.
#[derive(Clone, PartialEq)]
enum Seen {
    /// See [`Call::AcceptListAdd`].
    AcceptListAdd(Peer),
    /// See [`Call::AcceptListClear`].
    AcceptListClear,
    /// See [`Call::AddPeer`].
    AddPeer(Peer, [u8; 16], [u8; 16]),
    /// See [`Call::Advertise`]: filter policy, interval, private, the data
    /// and the scan response data.
    Advertise(u8, u16, bool, Box<(Data, Data)>),
    /// See [`Call::ClearPeers`].
    ClearPeers,
    /// See [`Call::Advertise`], directed: the target, private.
    Directed(Peer, bool),
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
    const fn new() -> Self { Self { calls: RefCell::new(([const { None }; 16], 0)), fail_at: None } }

    /// Records `seen`, the next call.
    fn record(&self, seen: Seen) {
        let mut calls = self.calls.borrow_mut();
        let index = calls.1;
        *assert_some!(calls.0.get_mut(index), "room for call {index}") = Some(seen);
        calls.1 = index.strict_add(1);
    }

    /// Whether the calls so far are `expected`.
    fn saw(&self, expected: &[Seen]) -> bool {
        let calls = self.calls.borrow();
        calls.1 == expected.len() && calls.0.iter().zip(expected).all(|(seen, wanted)| seen.as_ref() == Some(wanted))
    }
}

impl Control for Recorder {
    fn call(&self, call: Call<'_>) -> Result<(), link::Error> {
        let seen = seen(call);
        if self.fail_at == Some(self.calls.borrow().1) {
            return Err(link::Error::Disallowed);
        }
        self.record(seen);
        Ok(())
    }
}

/// The call `call` as the stand-in records it, checked for the parameters
/// every advertising call has.
fn seen(call: Call<'_>) -> Seen {
    match call {
        Call::AcceptListAdd(peer) => Seen::AcceptListAdd(peer),
        Call::AcceptListClear => Seen::AcceptListClear,
        Call::AddPeer { identity, local_irk, peer_irk } => Seen::AddPeer(identity, peer_irk, local_irk),
        Call::Advertise { adv, params, scan } => {
            let mut data = Data::new();
            let mut response = Data::new();
            data.bytes.get_mut(..adv.len()).unwrap_or_default().copy_from_slice(adv);
            data.len = adv.len().strict_cast();
            response.bytes.get_mut(..scan.len()).unwrap_or_default().copy_from_slice(scan);
            response.len = scan.len().strict_cast();
            assert_eq!(params.channel_map, 0x07);
            if params.kind.is_directed() {
                Seen::Directed(params.peer, params.private)
            } else {
                assert!(params.kind == Kind::ConnectableUndirected);
                Seen::Advertise(params.filter_policy, params.interval, params.private, Box::new((data, response)))
            }
        },
        Call::ClearPeers => Seen::ClearPeers,
        Call::SetAddressResolution(enable) => Seen::SetAddressResolution(enable),
        Call::SetIdentity(address) => Seen::SetIdentity(address),
        Call::SetPrivacyMode { device, identity } => Seen::SetPrivacyMode(identity, device),
        Call::SetRpaTimeout(seconds) => Seen::SetRpaTimeout(seconds),
        Call::StopAdvertising => Seen::StopAdvertising,
    }
}

/// Our identity in generation `generation`.
fn identity(generation: u8) -> identity::Local {
    identity::Local::derive(&Software, &DeviceSecret::new([1; 16], [2; 16]), Variant::new(0, generation))
}

/// A bond with [`CENTRAL`] under our identity of generation 1, with the
/// central's key if `irk`.
fn bond(irk: bool) -> Bond {
    Bond::new(IdentityAddress::valid(CENTRAL), irk.then_some(CENTRAL_IRK), [0x44; 16], Variant::new(0, 1), &DB)
}

#[test]
fn structures_are_written_with_their_length_and_type() {
    let mut data = Data::new();
    assert!(data.is_empty());
    assert_ok!(
        data.flags(0x06)
            .and_then(|written| written.services(&[0x1812, 0x180F]))
            .and_then(|written| written.appearance(0x03C1))
    );
    assert_ok!(data.name(b"Ab").and_then(|written| written.short_name(b"A")).and_then(|written| written.tx_power(-4)));
    assert_eq!(data.as_bytes(), &[
        2, 0x01, 0x06, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0xC1, 0x03, 3, 0x09, b'A', b'b', 2, 0x08, b'A', 2,
        0x0A, 0xFC,
    ]);
    assert_eq!(data.len(), 23);
    assert_eq!(Data::default(), Data::new());
}

#[test]
fn a_structure_that_does_not_fit_is_refused_and_changes_nothing() {
    let mut data = Data::new();
    // 29 octets of data fill the 31 exactly; with extended advertising 243
    // the 245 of the nRF52 chips, 240 the 242 of the nRF51.
    let extended = if cfg!(feature = "nrf51") { 242 } else { 245 };
    assert_eq!(DATA_MAX, if cfg!(feature = "extended-advertising") { extended } else { 31 });
    assert_ok!(data.push(0xFF, &[7; DATA_MAX - 2]));
    assert_eq!(data.len(), DATA_MAX);
    assert_eq!(data.flags(0x06).err(), Some(Overflow::TooLong));
    let mut flagged = Data::new();
    assert_ok!(flagged.flags(0x06));
    let before = flagged;
    assert_eq!(flagged.push(0xFF, &[7; DATA_MAX - 4]).err(), Some(Overflow::TooLong));
    assert_eq!(flagged, before);
    // Fourteen services fit an empty set, fifteen do not; 121 and 122 with
    // extended advertising on the nRF52 chips, 120 and 121 on the nRF51.
    let services = (DATA_MAX - 2).strict_div(2);
    assert_eq!(Data::new().services([0x1800; 121].get(..services).unwrap_or_default()).err(), None);
    assert_eq!(Data::new().services([0x1800; 122].get(..=services).unwrap_or_default()).err(), Some(Overflow::TooLong));
    assert_eq!(Data::new().push(0xFF, &[0; 300]).err(), Some(Overflow::TooLong));
}

#[test]
fn a_long_name_is_shortened_at_a_character_boundary() {
    let mut data = Data::new();
    assert_eq!(data.name_fitting(b"My remote"), Ok(false));
    assert_eq!(data.as_bytes().get(..2), Some(&[10, AD_NAME][..]));
    // 27 octets of data leave room for a name of 2 octets: "a" and the
    // first octet of a two octet character would be cut before the latter.
    let mut cut = Data::new();
    assert_ok!(cut.push(0xFF, &[0; DATA_MAX - 6]));
    assert_eq!(cut.name_fitting("a\u{e4}b".as_bytes()), Ok(true));
    assert_eq!(cut.as_bytes().get(DATA_MAX - 4..), Some(&[2, AD_SHORT_NAME, b'a'][..]));
    // No room for a single character.
    let mut full = Data::new();
    assert_ok!(full.push(0xFF, &[0; DATA_MAX - 5]));
    assert_eq!(full.name_fitting("\u{e4}\u{e4}".as_bytes()), Err(Overflow::TooLong));
    assert_eq!(full.len(), DATA_MAX - 3);
}

#[cfg(not(feature = "extended-advertising"))]
#[test]
fn pairing_is_discoverable_with_the_name() {
    let advertising = assert_ok!(example::advertising(Mode::Pairing, None));
    let adv = advertising.data().as_bytes();
    let head = [2, 0x01, 0x06, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0xC1, 0x03];
    assert_eq!(adv.get(..head.len()), Some(&head[..]));
    // "Example HID Remote" (18 octets) leaves 16 in the advertising: the
    // name is shortened there and complete in the scan response.
    assert_eq!(adv.get(head.len()..), Some(&*[&[17, AD_SHORT_NAME][..], b"Example HID Remo"].concat()));
    assert_eq!(advertising.scan().as_bytes(), [&[19, AD_NAME][..], b"Example HID Remote"].concat());
    assert_eq!(advertising.schedule(), &example::PAIRING);
    assert!(advertising.mode().pairable() && advertising.mode().discoverable());
}

#[cfg(not(feature = "extended-advertising"))]
#[test]
fn reconnection_is_without_name_or_discoverability() {
    let bond = bond(false);
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), Some(-8)));
    assert_eq!(advertising.data().as_bytes(), &[2, 0x01, 0x04, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0xC1, 0x03]);
    assert_eq!(advertising.scan().as_bytes(), &[2, AD_TX_POWER, 0xF8]);
    assert_eq!(advertising.schedule(), &example::RECONNECT);
    assert!(!advertising.mode().pairable() && !advertising.mode().discoverable());
}

#[cfg(not(feature = "extended-advertising"))]
#[test]
fn a_name_too_long_for_the_advertising_data_is_complete_in_the_scan_response() {
    let content = Content { name: b"A remote with a long name", ..example::CONTENT };
    let (adv, scan) = assert_ok!(content.data(true));
    assert_eq!(adv.len(), DATA_MAX);
    assert_eq!(adv.as_bytes().get(13..15), Some(&[17, AD_SHORT_NAME][..]));
    assert_eq!(adv.as_bytes().get(15..), Some(&b"A remote with a "[..]));
    assert_eq!(scan.as_bytes().get(..2), Some(&[26, AD_NAME][..]));
    assert_eq!(scan.as_bytes().get(2..), Some(&b"A remote with a long name"[..]));
    // A name that fits neither is refused.
    let too_long = Content { name: &[b'x'; 30], ..example::CONTENT };
    assert_eq!(too_long.data(true).err(), Some(Overflow::TooLong));
    // Without discoverability the name does not matter.
    assert_eq!(too_long.data(false).err(), None);
}

#[cfg(feature = "extended-advertising")]
#[test]
fn extended_pairing_data_holds_the_complete_name_and_there_is_no_scan_response() {
    let advertising = assert_ok!(example::advertising(Mode::Pairing, Some(-8)));
    let adv = advertising.data().as_bytes();
    let head = [2, 0x01, 0x06, 5, 0x03, 0x12, 0x18, 0x0F, 0x18, 3, 0x19, 0xC1, 0x03];
    assert_eq!(adv.get(..head.len()), Some(&head[..]));
    // The TX power level, then "Example HID Remote" complete.
    assert_eq!(
        adv.get(head.len()..),
        Some(&*[&[2, AD_TX_POWER, 0xF8, 19, AD_NAME][..], b"Example HID Remote"].concat())
    );
    assert!(advertising.scan().is_empty());
    assert!(advertising.mode().pairable() && advertising.mode().discoverable());
    // A long name, too.
    let content = Content { name: b"A remote with a long name", ..example::CONTENT };
    let (long_adv, long_scan) = assert_ok!(content.data(true));
    assert_eq!(long_adv.as_bytes().get(13..15), Some(&[26, AD_NAME][..]));
    assert!(long_scan.is_empty());
}

#[cfg(feature = "extended-advertising")]
#[test]
fn extended_reconnection_data_is_without_the_name_and_fits_directed_advertising() {
    let bond = bond(false);
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), Some(-8)));
    assert_eq!(advertising.data().as_bytes(), &[
        2,
        0x01,
        0x04,
        5,
        0x03,
        0x12,
        0x18,
        0x0F,
        0x18,
        3,
        0x19,
        0xC1,
        0x03,
        2,
        AD_TX_POWER,
        0xF8
    ]);
    assert!(advertising.scan().is_empty());
    assert!(!advertising.mode().pairable() && !advertising.mode().discoverable());
    // The flags, the services and the appearance take 9 + 2n octets. With
    // the fewest services too many for directed advertising, 241 of its 239
    // octets on the nRF52 chips (116 services) and 237 of 236 on the nRF51
    // (114), reconnection refuses them; pairing shortens the name to the
    // octets left of 245, or 242 on the nRF51.
    let directed = Kind::DirectedLowDuty.data_max();
    assert_eq!((DATA_MAX, directed), if cfg!(feature = "nrf51") { (242, 236) } else { (245, 239) });
    let services = (directed - 9).strict_div(2) + 1;
    assert_eq!(services, if cfg!(feature = "nrf51") { 114 } else { 116 });
    let content = Content { services: [0x1800; 116].get(..services).unwrap_or_default(), ..example::CONTENT };
    assert_eq!(content.data(false).err(), Some(Overflow::TooLong));
    let (adv, _) = assert_ok!(content.data(true));
    assert_eq!(adv.len(), DATA_MAX);
    let short = DATA_MAX - (9 + 2 * services) - 2;
    let header = [assert_ok!(u8::try_from(short + 1)), AD_SHORT_NAME];
    assert_eq!(
        adv.as_bytes().get(9 + 2 * services..),
        Some(&*[&header[..], b"Example".get(..short).unwrap_or_default()].concat())
    );
    let fewer = Content { services: [0x1800; 116].get(..services - 1).unwrap_or_default(), ..example::CONTENT };
    assert_eq!(assert_ok!(fewer.data(false)).0.len(), 9 + 2 * (services - 1));
    assert!(assert_ok!(fewer.data(false)).0.len() <= directed);
}

#[test]
fn the_example_phases_take_a_minute() {
    let schedule = example::PAIRING;
    assert_eq!(schedule.total(), Duration::from_secs(60));
    assert_eq!(schedule.security_deadline, Duration::from_secs(60));
    assert_eq!(example::RECONNECT.security_deadline, Duration::from_secs(20));
    let interval = |millis| schedule.phase_at(Duration::from_millis(millis)).map(|phase| phase.interval);
    assert_eq!(interval(0), Some(32));
    assert_eq!(interval(2_999), Some(32));
    assert_eq!(interval(3_000), Some(80));
    assert_eq!(interval(14_999), Some(80));
    assert_eq!(interval(15_000), Some(640));
    assert_eq!(interval(59_999), Some(640));
    assert_eq!(interval(60_000), None);
    // 20 ms, 50 ms and 400 ms.
    assert_eq!(example::PHASES.map(|phase| u32::from(phase.interval) * 625), [20_000, 50_000, 400_000]);
}

#[test]
fn reconnection_filters_on_the_accept_list_and_both_modes_are_private() {
    let bond = bond(false);
    let phase = example::PHASES[1];
    let pairing = Mode::Pairing.params(&phase);
    assert!(pairing.filter_policy == 0 && pairing.private && pairing.interval == 80);
    let reconnect = Mode::Reconnect(&bond).params(&phase);
    assert!(reconnect.filter_policy == 0x03 && reconnect.private && reconnect.interval == 80);
}

#[test]
fn pairing_sets_our_key_and_no_central() {
    let recorder = Recorder::new();
    let identity = identity(1);
    let advertising = assert_ok!(example::advertising(Mode::Pairing, None));
    assert_ok!(advertising.configure(&recorder, &identity));
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
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), None));
    assert_ok!(advertising.configure(&recorder, &identity));
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
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), None));
    assert_eq!(advertising.configure(&recorder, &identity(2)), Err(Error::WrongIdentity));
    assert!(recorder.saw(&[]));
}

#[test]
fn a_refused_call_ends_the_setup() {
    let recorder = Recorder { fail_at: Some(2), ..Recorder::new() };
    let advertising = assert_ok!(example::advertising(Mode::Pairing, None));
    assert_eq!(advertising.configure(&recorder, &identity(0)), Err(Error::Link(link::Error::Disallowed)));
    assert!(recorder.saw(&[Seen::StopAdvertising, Seen::SetAddressResolution(false)]));
}

#[test]
fn each_phase_starts_with_its_interval_and_the_modes_data() {
    let recorder = Recorder::new();
    let bond = bond(false);
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), None));
    for phase in &example::PHASES {
        assert_ok!(advertising.start(&recorder, phase));
    }
    let seen = |interval| Seen::Advertise(0x03, interval, true, Box::new((*advertising.data(), *advertising.scan())));
    assert!(recorder.saw(&[seen(32), seen(80), seen(640)]));
}

#[test]
fn the_link_layer_takes_the_reconnection_setup() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let identity = identity(1);
    let bond = bond(true);
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), None));
    assert_ok!(advertising.configure(&link, &identity));
    // A private address needs the chip's RNG and AES, so the link layer is
    // checked advertising from the identity address.
    let params = advertising.mode().params(&example::PHASES[0]).private(false);
    assert_ok!(link.advertise(&params, advertising.data().as_bytes(), advertising.scan().as_bytes()));
    let settings = assert_some!(shared.advertising());
    assert!(settings.address == identity.peer() && settings.own == identity.peer());
    assert_eq!(settings.filter_policy, 0x03);
    assert!(settings.filter.contains(CENTRAL));
    assert!(settings.resolution_enabled);
    assert_eq!(settings.resolving.local_key(None), Some(identity.irk()));
    assert_eq!(settings.interval, 20_000);
    // Setting up again stops the advertising first, and pairing forgets the
    // central.
    let pairing = assert_ok!(example::advertising(Mode::Pairing, None));
    assert_ok!(pairing.configure(&link, &identity));
    assert!(shared.advertising().is_none());
    assert_ok!(link.advertise(&pairing.mode().params(&example::PHASES[0]).private(false), &[], &[]));
    let pairing_settings = assert_some!(shared.advertising());
    assert_eq!(pairing_settings.filter_policy, 0);
    assert!(!pairing_settings.filter.contains(CENTRAL));
    assert!(!pairing_settings.resolution_enabled);
    assert_eq!(pairing_settings.resolving.local_key(None), Some(identity.irk()));
    assert_eq!(pairing_settings.resolving.local_key(Some(CENTRAL)), None);
}

#[test]
fn the_link_layer_refuses_to_start_while_a_central_is_connected() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let advertising = assert_ok!(example::advertising(Mode::Pairing, None));
    // Without an identity address.
    assert_eq!(advertising.start(&link, &example::PHASES[0]), Err(Error::Link(link::Error::Invalid)));
    assert_ok!(advertising.configure(&link, &identity(0)));
    shared.set_connected(true);
    assert_eq!(advertising.start(&link, &example::PHASES[0]), Err(Error::Link(link::Error::Disallowed)));
    assert!(shared.advertising().is_none());
}

#[cfg(feature = "extended-advertising")]
#[test]
fn the_secondary_phy_reaches_the_link_layer_where_the_chip_has_it() {
    use crate::radio::Phy;
    use core::cell::Cell;
    /// A stand-in that keeps the parameters of the last advertising.
    struct Params(Cell<Option<AdvParams>>);
    impl Control for Params {
        fn call(&self, call: Call<'_>) -> Result<(), link::Error> {
            if let Call::Advertise { params, adv: _, scan: _ } = call {
                self.0.set(Some(params));
            }
            Ok(())
        }
    }
    let control = Params(Cell::new(None));
    let advertising = assert_ok!(example::advertising(Mode::Pairing, None));
    assert!(advertising.secondary_phy() == Phy::M1);
    assert_ok!(advertising.start(&control, &example::PHASES[0]));
    assert!(assert_some!(control.0.get()).secondary_phy == Phy::M1);
    // LE 2M on the nRF52 chips; the nRF51, with LE 1M alone, keeps it.
    let fast = advertising.with_secondary_phy(Phy::M2);
    let expected = if cfg!(feature = "nrf51") { Phy::M1 } else { Phy::M2 };
    assert!(fast.secondary_phy() == expected);
    assert_ok!(fast.start(&control, &example::PHASES[0]));
    let params = assert_some!(control.0.get());
    assert!(params.secondary_phy == expected && params.kind == Kind::ConnectableUndirected && params.private);
}

/// LE Coded reaches the link layer on the primary and the secondary
/// channels; LE 2M, which no primary channel takes, keeps the primaries on
/// LE 1M.
#[cfg(all(feature = "extended-advertising", feature = "coded-phy"))]
#[test]
fn le_coded_reaches_the_link_layer_on_both_channels() {
    use crate::radio::Phy;
    use core::cell::Cell;
    /// A stand-in that keeps the parameters of the last advertising.
    struct Params(Cell<Option<AdvParams>>);
    impl Control for Params {
        fn call(&self, call: Call<'_>) -> Result<(), link::Error> {
            if let Call::Advertise { params, adv: _, scan: _ } = call {
                self.0.set(Some(params));
            }
            Ok(())
        }
    }
    let control = Params(Cell::new(None));
    let advertising = || example::advertising(Mode::Pairing, None);
    assert!(assert_ok!(advertising()).primary_phy() == Phy::M1);
    assert!(assert_ok!(advertising()).with_primary_phy(Phy::M2).primary_phy() == Phy::M1);
    let long_range = assert_ok!(advertising()).with_primary_phy(Phy::CodedS8).with_secondary_phy(Phy::CodedS2);
    assert_ok!(long_range.start(&control, &example::PHASES[0]));
    let params = assert_some!(control.0.get());
    assert!(params.primary_phy == Phy::CodedS8 && params.secondary_phy == Phy::CodedS2);
}

#[test]
fn the_name_is_shortened_in_the_advertising_and_complete_in_the_scan_response() {
    use crate::advertiser::SCAN_DATA_MAX;

    let (adv, scan) = assert_ok!(example::CONTENT.data(true));
    let field = |data: &[u8], kind: u8| {
        let mut rest = data;
        while let Some((&len, tail)) = rest.split_first() {
            assert_ne!(len, 0, "an empty structure");
            let split = tail.split_at_checked(usize::from(len));
            assert!(split.is_some(), "a structure of {len} octets overruns the data");
            let (structure, next) = split?;
            if structure.first() == Some(&kind) {
                return structure.get(1..).map(<[u8]>::to_vec);
            }
            rest = next;
        }
        None
    };
    let complete = field(scan.as_bytes(), AD_NAME).or_else(|| field(adv.as_bytes(), AD_NAME));
    assert_eq!(complete.as_deref(), Some(example::NAME));
    if let Some(short) = field(adv.as_bytes(), AD_SHORT_NAME) {
        assert!(example::NAME.starts_with(&short));
    }
    assert!(adv.as_bytes().len() <= DATA_MAX && SCAN_DATA_MAX.checked_sub(scan.as_bytes().len()).is_some());
}

#[cfg(feature = "directed-advertising")]
#[test]
fn a_directed_phase_lasts_at_most_the_link_layer_s_time() {
    let phase = Phase::directed(Duration::from_secs(3));
    assert!(phase.directed && phase.duration == DIRECTED_MAX && phase.interval == DIRECTED_FALLBACK);
    assert_eq!(Phase::directed(Duration::from_millis(500)).duration, Duration::from_millis(500));
    assert!(!example::PHASES[0].directed);
}

#[cfg(feature = "directed-advertising")]
#[test]
fn a_directed_phase_targets_the_bonded_central_s_identity_only_when_reconnecting() {
    let phase = Phase::directed(DIRECTED_MAX);
    let recorder = Recorder::new();
    // A central without host privacy, which sent no key.
    let bond = bond(false);
    let reconnect = assert_ok!(example::advertising(Mode::Reconnect(&bond), None));
    assert!(reconnect.mode().directs(&phase) && !reconnect.mode().directs(&example::PHASES[0]));
    let params = reconnect.mode().params(&phase);
    assert!(params.kind == DIRECTED && params.peer == CENTRAL && params.private);
    assert_ok!(reconnect.start(&recorder, &phase));
    assert!(recorder.saw(&[Seen::Directed(CENTRAL, true)]));
    // Never in pairing mode, which has no central to direct it to: it
    // advertises undirected at 20 ms instead.
    let pairing = assert_ok!(example::advertising(Mode::Pairing, None));
    assert!(!pairing.mode().directs(&phase));
    let pairing_params = pairing.mode().params(&phase);
    assert!(
        pairing_params.kind == Kind::ConnectableUndirected
            && pairing_params.interval == 32
            && pairing_params.filter_policy == 0
    );
    // A static random identity can be targeted. A private address, which
    // cannot be, is no identity address, so no bond holds one.
    let mut targeted = bond;
    targeted.peer = IdentityAddress::valid(Peer::new([1, 2, 3, 4, 5, 0xC6], true));
    assert!(Mode::Reconnect(&targeted).directs(&phase));
    assert!(IdentityAddress::new(Peer::new([1, 2, 3, 4, 5, 0x46], true)).is_none());
    // An undirected phase stays undirected.
    assert!(Mode::Reconnect(&targeted).params(&example::PHASES[0]).kind == Kind::ConnectableUndirected);
}

#[cfg(feature = "directed-advertising")]
#[test]
fn a_central_that_sent_its_key_is_directed_to_until_it_goes_unanswered() {
    // It scans from resolvable private addresses: the host directs to its
    // identity, and the link layer targets a private address made with the
    // key the resolving list holds for it.
    let phase = Phase::directed(DIRECTED_MAX);
    let mut bond = bond(true);
    assert!(Mode::Reconnect(&bond).directs(&phase));
    let params = Mode::Reconnect(&bond).params(&phase);
    assert!(params.kind == DIRECTED && params.peer == CENTRAL && params.private);
    let recorder = Recorder::new();
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), None));
    assert_ok!(advertising.configure(&recorder, &identity(1)));
    assert!(recorder.calls.borrow().0.contains(&Some(Seen::AddPeer(CENTRAL, CENTRAL_IRK, identity(1).irk()))));
    assert!(!Mode::Reconnect(&bond).skips(&phase) && !Mode::Pairing.skips(&phase));
    // Once directed advertising went unanswered, the host skips the phase,
    // whether the central sent its key or not; started anyway, it
    // advertises undirected at 20 ms, from the accept list only. Undirected
    // phases are never skipped.
    bond.directed_works = false;
    assert!(Mode::Reconnect(&bond).skips(&phase));
    assert!(!Mode::Reconnect(&bond).skips(&Phase::new(32, DIRECTED_MAX)));
    assert!(!Mode::Reconnect(&bond).directs(&phase));
    let skipped_params = Mode::Reconnect(&bond).params(&phase);
    assert!(
        skipped_params.kind == Kind::ConnectableUndirected
            && skipped_params.interval == 32
            && skipped_params.filter_policy == 0x03
    );
    assert!(skipped_params.private);
    bond.peer_irk = None;
    assert!(!Mode::Reconnect(&bond).directs(&phase));
}

#[cfg(feature = "directed-advertising")]
#[test]
fn the_link_layer_takes_a_directed_phase() {
    #[cfg(not(feature = "extended-advertising"))]
    use crate::pdu::ADV_DIRECT_IND;
    #[cfg(feature = "extended-advertising")]
    use crate::pdu::ADV_EXT_IND;

    let shared = Shared::new();
    let link = Link::new(&shared);
    let identity = identity(1);
    let bond = bond(false);
    let advertising = assert_ok!(example::advertising(Mode::Reconnect(&bond), None));
    assert_ok!(advertising.configure(&link, &identity));
    let params = advertising.mode().params(&Phase::directed(DIRECTED_MAX));
    assert!(params.private && params.filter_policy == 0x03);
    // A private address needs the chip's RNG and AES, and its cache the
    // time driver, none of which the host tests have, so the link layer is
    // given the host's parameters as they are but for `private`, with the
    // identity address, also random, as our own. Our private address would
    // come from our key of the central's entry, the same as for the
    // undirected phases.
    assert_ok!(link.advertise(&params.private(false), advertising.data().as_bytes(), advertising.scan().as_bytes()));
    let settings = assert_some!(shared.advertising());
    assert!(settings.kind == DIRECTED && settings.peer == CENTRAL);
    assert!(settings.filter_policy == 0x03 && settings.own == identity.peer());
    assert_eq!(settings.resolving.local_key(Some(CENTRAL)), Some(identity.irk()));
    // ADV_DIRECT_IND, or with extended advertising an AUX_ADV_IND with
    // AdvA and TargetA after its extended header length and flags.
    #[cfg(not(feature = "extended-advertising"))]
    let (pdu, (kind, addresses)) = (advertiser::legacy::pdus(&settings).0, (ADV_DIRECT_IND, 2));
    #[cfg(feature = "extended-advertising")]
    let (pdu, (kind, addresses)) = (advertiser::extended::auxiliary(&settings), (ADV_EXT_IND, 4));
    let header = *assert_some!(pdu.as_bytes().first());
    assert_eq!(header & 0x0F, kind);
    // TxAdd: our address is random, as a private one is; RxAdd: the
    // central's identity is public, as BlueZ without host privacy scans
    // from it.
    assert!(identity.peer().random && header & 0x40 != 0);
    assert!(!CENTRAL.random && header & 0x80 == 0);
    assert_eq!(pdu.as_bytes().get(addresses..addresses + 6), Some(&identity.peer().address[..]));
    assert_eq!(pdu.as_bytes().get(addresses + 6..addresses + 12), Some(&CENTRAL.address[..]));
    // From the identity address the target stays the central's identity,
    // also with its key in the resolving list.
    assert_eq!(settings.target, CENTRAL);
    let keyed = super::tests::bond(true);
    let keyed_advertising = assert_ok!(example::advertising(Mode::Reconnect(&keyed), None));
    assert_ok!(keyed_advertising.configure(&link, &identity));
    assert!(shared.advertising().is_none());
    let keyed_params = keyed_advertising.mode().params(&Phase::directed(DIRECTED_MAX));
    assert_ok!(link.advertise(&keyed_params.private(false), keyed_advertising.data().as_bytes(), &[]));
    let keyed_settings = assert_some!(shared.advertising());
    assert_eq!(keyed_settings.resolving.peer_key(CENTRAL), Some(CENTRAL_IRK));
    assert!(keyed_settings.target == CENTRAL && keyed_settings.peer == CENTRAL);
}
