//! Tests of the settings both advertising variants share: the connection
//! requests they accept and the addresses they resolve, with the resolving
//! list behind them.

use super::*;
use crate::{
    crypto::{resolvable_address_with, resolves_with},
    host::{Aes as _, test_aes::Software},
};

/// The identity resolving key of the sample of the random address hash
/// function ah (Core, Vol 3, Part H, D.7), `ec0234a3 57c8ad05 341010a6
/// 0a397d9b`, least significant octet first as the resolving list keeps it.
pub(super) const SAMPLE_IRK: [u8; 16] =
    [0x9B, 0x7D, 0x39, 0x0A, 0xA6, 0x10, 0x10, 0x34, 0x05, 0xAD, 0xC8, 0x57, 0xA3, 0x34, 0x02, 0xEC];
/// The sample's prand, `708194`, least significant octet first.
pub(super) const SAMPLE_PRAND: [u8; 3] = [0x94, 0x81, 0x70];
/// The sample's resolvable private address: hash `0dfbaa` below prand.
pub(super) const SAMPLE_RPA: [u8; 6] = [0xAA, 0xFB, 0x0D, 0x94, 0x81, 0x70];
/// The central's identity: `BlueZ`'s public address.
pub(super) const CENTRAL: Peer = Peer::new([1, 2, 3, 4, 5, 6], false);
/// Our own key.
pub(super) const LOCAL_IRK: [u8; 16] = [0x5A; 16];

/// Software AES-128 in place of the ECB.
fn software(key: [u8; 16], block: [u8; 16]) -> [u8; 16] { Software.encrypt(key, block) }

/// Whether `address` resolves with `irk`, in software.
pub(super) fn resolves(irk: [u8; 16], address: [u8; 6]) -> bool { resolves_with(irk, address, software) }

/// A resolvable private address of `irk` from `prand`, in software.
pub(super) fn rpa(irk: [u8; 16], prand: [u8; 3]) -> Peer {
    Peer::new(resolvable_address_with(irk, prand, software), true)
}

/// Directed advertising from a private address of ours to [`CENTRAL`], with
/// its key in the resolving list and address resolution on, as the host sets
/// it up for a reconnection. Low duty cycle, the directed type every variant
/// has: a connection request is checked the same way for both directed
/// types.
pub(super) fn directed() -> Settings {
    let mut settings = Settings::new();
    assert!(settings.resolving.add_keys(CENTRAL, SAMPLE_IRK, LOCAL_IRK));
    assert!(settings.resolving.set_mode(CENTRAL, true));
    assert!(settings.filter.add(CENTRAL));
    settings.resolution_enabled = true;
    settings.kind = Kind::DirectedLowDuty;
    settings.filter_policy = 0x03;
    settings.private = true;
    settings.own = rpa(LOCAL_IRK, [7, 8, 9]);
    settings.peer = CENTRAL;
    settings
}

/// A connection request from `central` to `advertiser`, with valid
/// parameters.
fn connect_ind(central: Peer, advertiser: Peer) -> [u8; 36] {
    let mut bytes = [0; 36];
    // CONNECT_IND, ChSel, TxAdd for the initiator, RxAdd for us; 34 octets.
    bytes[0] = 0x05 | 0x20 | if central.random { 0x40 } else { 0 } | if advertiser.random { 0x80 } else { 0 };
    bytes[1] = 34;
    bytes[2..8].copy_from_slice(&central.address);
    bytes[8..14].copy_from_slice(&advertiser.address);
    bytes[14..18].copy_from_slice(&0x9A32_8370_u32.to_le_bytes());
    bytes[21] = 1;
    bytes[24] = 12;
    bytes[28..30].copy_from_slice(&600_u16.to_le_bytes());
    bytes[30..35].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]);
    bytes[35] = 5;
    bytes
}

/// Whether `settings` accept a connection request from `central`, parsed
/// as the advertising event parses it, resolving in software.
fn accepts(settings: &Settings, central: Peer) -> bool {
    parse(&connect_ind(central, settings.own), settings.own)
        .is_some_and(|request| settings.accepts_connection_with(request.central(), resolves))
}

/// A connection request as the variant's event parses it: a `CONNECT_IND`.
#[cfg(not(feature = "extended-advertising"))]
fn parse(pdu: &[u8], advertiser: Peer) -> Option<ConnectInd> { ConnectInd::parse(pdu, advertiser) }

/// A connection request as the variant's event parses it: an
/// `AUX_CONNECT_REQ`, of the same layout.
#[cfg(feature = "extended-advertising")]
fn parse(pdu: &[u8], advertiser: Peer) -> Option<ConnectInd> { ConnectInd::parse_aux(pdu, advertiser) }

#[test]
fn the_sample_key_makes_the_sample_address_and_resolves_it() {
    let target = rpa(SAMPLE_IRK, SAMPLE_PRAND);
    assert!(target.random && target.address == SAMPLE_RPA);
    assert!(resolves(SAMPLE_IRK, target.address));
    let mut other = SAMPLE_IRK;
    other[15] ^= 1;
    assert!(!resolves(other, target.address));
}

#[cfg(feature = "directed-advertising")]
#[test]
fn the_link_layer_finds_the_central_s_key_by_its_identity() {
    let settings = directed();
    // Never a key that is zero.
    assert_eq!(settings.resolving.peer_key(CENTRAL), Some(SAMPLE_IRK));
    assert_eq!(settings.resolving.peer_key(Peer::new([1, 2, 3, 4, 5, 7], false)), None);
    let mut keyless = ResolvingList::new();
    assert!(keyless.add_keys(CENTRAL, [0; 16], LOCAL_IRK));
    assert_eq!(keyless.peer_key(CENTRAL), None);
}

#[test]
fn a_directed_connection_request_from_another_private_address_of_the_key_is_accepted() {
    let settings = directed();
    // The central initiates from a resolvable private address of its own,
    // never the one the advertising targets (Core, Vol 6, Part B, 6.4).
    let initiator = rpa(SAMPLE_IRK, [0x12, 0x34, 0x56]);
    assert!(initiator.address != SAMPLE_RPA);
    assert!(accepts(&settings, initiator));
    // From its identity too: its entry is in device privacy mode.
    assert!(accepts(&settings, CENTRAL));
    // Not from an address of another key, another identity, or one that is
    // not resolvable; not addressed to another advertiser.
    assert!(!accepts(&settings, rpa([0x77; 16], [0x12, 0x34, 0x56])));
    assert!(!accepts(&settings, Peer::new([1, 2, 3, 4, 5, 7], false)));
    assert!(!accepts(&settings, Peer::new([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC], true)));
    assert!(parse(&connect_ind(initiator, CENTRAL), settings.own).is_none());
    // The resolved identity is what the link reports.
    assert_eq!(settings.resolve_with(initiator, resolves), Some(CENTRAL));
    // Without address resolution only the identity counts, and in network
    // privacy mode not even it.
    let mut unresolved = directed();
    unresolved.resolution_enabled = false;
    assert!(!accepts(&unresolved, initiator));
    assert!(accepts(&unresolved, CENTRAL));
    assert_eq!(unresolved.resolve_with(initiator, resolves), None);
    let mut network = directed();
    assert!(network.resolving.set_mode(CENTRAL, false));
    assert!(!accepts(&network, CENTRAL));
    assert!(accepts(&network, initiator));
}

#[test]
fn undirected_advertising_resolves_the_accept_list_the_same_way() {
    let mut settings = directed();
    settings.kind = Kind::ConnectableUndirected;
    assert!(accepts(&settings, rpa(SAMPLE_IRK, [0x12, 0x34, 0x56])));
    assert!(!accepts(&settings, rpa([0x77; 16], [0x12, 0x34, 0x56])));
    // Without the filter, anyone.
    settings.filter_policy = 0;
    assert!(accepts(&settings, rpa([0x77; 16], [0x12, 0x34, 0x56])));
}
