//! Tests of the security manager: complete pairings against a reference
//! central built from the toolbox and a second key pair, with every PDU
//! compared octet for octet, and every way a pairing is refused, fails or
//! times out.

use super::*;
use crate::{
    host::{smp::toolbox::tests::hex, test_aes::Software},
    link::{ConnectionParams, Epoch},
};
use core::cell::Cell;

/// The private key of the reference central: device A of P-256 data set 2.
pub(crate) const CENTRAL_SECRET: &str = "06a51669 3c9aa31a 6084545d 0c5db641 b48572b9 7203ddff b7ac73f7 d0457663";

/// The central's address on the air: a public address.
pub(crate) const CENTRAL_ADDRESS: [u8; 6] = [0xCE, 0xBF, 0x37, 0x37, 0x12, 0x56];

/// The central's identity resolving key, least significant octet first.
pub(crate) const CENTRAL_IRK: [u8; 16] = [0xA5; 16];

/// The central's identity address, public.
pub(crate) const CENTRAL_IDENTITY: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

/// Our identity resolving key, least significant octet first.
pub(crate) const OUR_IRK: [u8; 16] =
    [0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F];

/// Our static random identity address, least significant octet first.
pub(crate) const OUR_ADDRESS: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0xC6];

/// The `AuthReq` of a Linux central: bonding, MITM, Secure Connections and
/// CT2.
pub(crate) const LINUX_AUTH: u8 = 0x2D;

/// The time the pairing starts at.
const START: u64 = 1_000;

/// AES and a seeded xorshift generator: the device for the state machine.
#[derive(Clone)]
pub(crate) struct Device(pub(crate) u64);

impl Aes for Device {
    fn encrypt(&self, key: [u8; 16], block: [u8; 16]) -> [u8; 16] { Software.encrypt(key, block) }
}

impl Random for Device {
    fn fill(&mut self, out: &mut [u8]) {
        for octet in out {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *octet = self.0.to_le_bytes()[0];
        }
    }
}

/// The variants of a complete pairing.
#[derive(Clone, Copy)]
struct Variant {
    /// The central offers its identity keys.
    central_id:      bool,
    /// The central's `DHKey` check arrives before the Diffie-Hellman key.
    check_before_dh: bool,
    /// The key pair is made before pairing, as pairable advertising does.
    key_pair_first:  bool,
    /// The central asks for our identity keys.
    our_id:          bool,
}

/// The reference central: the initiator's side of Just Works, from the
/// toolbox and a key pair of its own.
pub(crate) struct Central {
    /// Its address on the air: A.
    pub(crate) address:   Peer,
    /// Our confirm value as received.
    pub(crate) confirm:   [u8; 16],
    /// The long term key, most significant octet first.
    pub(crate) ltk:       [u8; 16],
    /// The `MacKey`.
    pub(crate) mac_key:   [u8; 16],
    /// Its nonce.
    pub(crate) na:        [u8; 16],
    /// Our nonce as received.
    pub(crate) nb:        [u8; 16],
    /// Its key pair.
    pub(crate) pair:      KeyPair,
    /// Our public key as received, most significant octet first.
    pub(crate) peer_key:  [u8; PUBLIC_KEY_LEN],
    /// Its Pairing Request.
    pub(crate) request:   [u8; 7],
    /// Our address as the central sees it: B.
    pub(crate) responder: Peer,
}

impl Central {
    /// Its Pairing DHKey Check: computes the keys from our public key and
    /// nonce.
    pub(crate) fn check(&mut self) -> [u8; 17] {
        let dh_key = self.pair.dh_key(&self.peer_key, || ()).expect("our public key is valid");
        let (a, b) = (address(self.address), address(self.responder));
        (self.mac_key, self.ltk) = f5(&Software, &dh_key, (&self.na, &self.nb), (&a, &b));
        let io_cap = [self.request[3], self.request[2], self.request[1]];
        let ea = f6(&Software, &self.mac_key, (&self.na, &self.nb), &[0; 16], io_cap, (&a, &b));
        pdu(PAIRING_DHKEY_CHECK, &reversed(&ea))
    }

    /// Our Pairing DHKey Check as it must be.
    pub(crate) fn expected_check(&self) -> [u8; 17] {
        let (a, b) = (address(self.address), address(self.responder));
        let eb = f6(&Software, &self.mac_key, (&self.nb, &self.na), &[0; 16], [0x09, 0x00, 0x03], (&b, &a));
        pdu(PAIRING_DHKEY_CHECK, &reversed(&eb))
    }

    /// A central with the given request parameters, which takes our address
    /// on the air as `responder`.
    pub(crate) fn new(params: [u8; 6], responder: Peer) -> Self {
        let mut secret = hex::<KEY_LEN>(CENTRAL_SECRET);
        let mut request = [PAIRING_REQUEST; 7];
        request[1..].copy_from_slice(&params);
        Self {
            address: Peer::new(CENTRAL_ADDRESS, false),
            confirm: [0; 16],
            ltk: [0; 16],
            mac_key: [0; 16],
            na: hex("d5cb8454 d177733e ffffb2ec 712baeab"),
            nb: [0; 16],
            pair: KeyPair::generate(&mut secret, || ()).expect("a valid private key"),
            peer_key: [0; PUBLIC_KEY_LEN],
            request,
            responder,
        }
    }

    /// Its Pairing Public Key.
    pub(crate) fn public_key(&self) -> [u8; 65] { pdu(PAIRING_PUBLIC_KEY, &flip_coordinates(self.pair.public_key())) }

    /// Its Pairing Random.
    pub(crate) fn random(&self) -> [u8; 17] { pdu(PAIRING_RANDOM, &reversed(&self.na)) }

    /// Takes our Pairing Confirm.
    pub(crate) fn take_confirm(&mut self, pdu: &[u8]) {
        assert_eq!(pdu[0], PAIRING_CONFIRM);
        self.confirm = reversed(pdu[1..].try_into().unwrap());
    }

    /// Takes our Pairing Public Key.
    pub(crate) fn take_public_key(&mut self, pdu: &[u8]) {
        assert_eq!(pdu[0], PAIRING_PUBLIC_KEY);
        self.peer_key = flip_coordinates(pdu[1..].try_into().unwrap());
    }

    /// Takes our Pairing Random and checks our confirm value with it, as an
    /// initiator does.
    pub(crate) fn take_random(&mut self, pdu: &[u8]) {
        assert_eq!(pdu[0], PAIRING_RANDOM);
        self.nb = reversed(pdu[1..].try_into().unwrap());
        let own_x = self.pair.public_key()[..KEY_LEN].try_into().unwrap();
        let peer_x = self.peer_key[..KEY_LEN].try_into().unwrap();
        assert_eq!(self.confirm, f4(&Software, peer_x, own_x, &self.nb, 0), "Cb = f4(PKbx, PKax, Nb, 0)");
    }
}

/// A PDU of `code` and `params`.
pub(crate) fn pdu<const N: usize>(code: u8, params: &[u8]) -> [u8; N] {
    let mut out = [code; N];
    out[1..].copy_from_slice(params);
    out
}

/// The time `millis` milliseconds into the test.
fn at(millis: u64) -> Instant { Instant::from_millis(millis) }

/// The link information of a link from `peer` to our address `local`.
fn info(peer: Peer, local: Peer) -> Info {
    Info {
        central_accuracy: 0,
        epoch: Epoch::for_test(1),
        identity: None,
        local,
        params: ConnectionParams::new(24, 0, 72),
        peer,
    }
}

/// A resolvable private address of our identity resolving key, as the link
/// layer advertises with: B of a pairing with privacy.
pub(crate) fn local_rpa() -> Peer {
    let prand = [0x48, 0x12, 0x34];
    let hash = toolbox::ah(&Software, &reversed(&OUR_IRK), prand);
    Peer::new([hash[2], hash[1], hash[0], prand[2], prand[1], prand[0]], true)
}

/// The next PDU, queued whole at `now`, and the outcome that gives.
fn out(responder: &mut Responder, now: Instant) -> (Output, Option<Outcome>) {
    let output = responder.next_pdu().expect("a PDU to send");
    let outcome = responder.pdu_sent(now);
    (output, outcome)
}

/// Runs every job that waits, as the crypto task does, and returns the
/// last outcome.
fn run_jobs(responder: &mut Responder, device: &mut Device) -> Option<Outcome> {
    let mut outcome = None;
    while let Some(job) = responder.take_job() {
        let result = job.run(&mut device.clone(), || ());
        outcome = responder.job_done(device, result);
    }
    outcome
}

/// A security manager for a link from the central's address to `local`,
/// with our identity, which takes pairing requests.
fn responder(local: Peer) -> Responder {
    let mut responder = Responder::new();
    responder.set_identity(OUR_IRK, OUR_ADDRESS);
    responder.set_pairable(true);
    responder.connected(&info(Peer::new(CENTRAL_ADDRESS, false), local));
    responder
}

/// The request parameters of a Linux central: keyboard and display, no OOB
/// data, `AuthReq` 0x2D, 16 octets, and its identity keys if `central_id`
/// besides encryption and signing, ours if `our_id`.
pub(crate) const fn linux_request(central_id: bool, our_id: bool) -> [u8; 6] {
    let init = if central_id { 0x07 } else { 0x05 };
    let resp = if our_id { 0x07 } else { 0x05 };
    [0x04, 0x00, LINUX_AUTH, 0x10, init, resp]
}

/// Pairs up to the moment the central checks our `DHKey` check: the
/// Pairing Response, our public key, Cb, Nb and Eb, each compared octet for
/// octet.
fn pair_up_to_encryption(variant: Variant) -> (Responder, Device, Central) {
    let local = local_rpa();
    let mut responder = responder(local);
    let mut device = Device(0x0123_4567_89AB_CDEF);
    let mut central = Central::new(linux_request(variant.central_id, variant.our_id), local);
    // Our key pair comes from the device's first 32 octets.
    let expected_pair = {
        let mut secret = [0; KEY_LEN];
        device.clone().fill(&mut secret);
        KeyPair::generate(&mut secret, || ()).unwrap()
    };
    if variant.key_pair_first {
        responder.prepare_key_pair();
        assert!(!responder.has_key_pair());
        run_jobs(&mut responder, &mut device);
        assert!(responder.has_key_pair());
    }

    assert_eq!(responder.receive(&mut device, &central.request, false, at(START)), Some(Outcome::Started));
    assert!(responder.is_pairing());
    assert_eq!(responder.deadline(), Some(at(START + 30_000)));
    let (response, outcome) = out(&mut responder, at(START + 10));
    assert_eq!(outcome, None);
    let dist = |id| if id { 0x02 } else { 0x00 };
    assert_eq!(response.bytes(), &[0x02, 0x03, 0x00, 0x09, 0x10, dist(variant.central_id), dist(variant.our_id)]);
    assert_eq!(responder.deadline(), Some(at(START + 30_010)));

    assert_eq!(responder.receive(&mut device, &central.public_key(), false, at(START + 20)), None);
    if !variant.key_pair_first {
        // The key pair is made now, and our public key waits for it.
        assert!(!responder.has_output());
        assert!(responder.take_job().is_some_and(|job| job.is_key_pair()));
        let result = Job { kind: JobKind::KeyPair }.run(&mut device.clone(), || ());
        assert_eq!(responder.job_done(&mut device, result), None);
    }
    // Our public key, then Cb; the Diffie-Hellman job waits for both.
    let (public_key, _) = out(&mut responder, at(START + 30));
    assert_eq!(public_key.bytes(), &pdu::<65>(PAIRING_PUBLIC_KEY, &flip_coordinates(expected_pair.public_key())));
    central.take_public_key(public_key.bytes());
    assert!(!responder.has_job());
    let (confirm, _) = out(&mut responder, at(START + 30));
    assert_eq!(confirm.bytes().len(), 17);
    central.take_confirm(confirm.bytes());
    assert!(responder.has_job());
    if !variant.check_before_dh {
        assert_eq!(run_jobs(&mut responder, &mut device), None);
    }

    assert_eq!(responder.receive(&mut device, &central.random(), false, at(START + 40)), None);
    let (random, _) = out(&mut responder, at(START + 50));
    central.take_random(random.bytes());
    assert_eq!(random.bytes(), &pdu::<17>(PAIRING_RANDOM, &reversed(&central.nb)));

    let check = central.check();
    assert_eq!(responder.receive(&mut device, &check, false, at(START + 60)), None);
    if variant.check_before_dh {
        // Ea waits for the Diffie-Hellman key.
        assert!(!responder.has_output());
        assert_eq!(responder.ltk_request(0, [0; 8]), None);
        assert_eq!(run_jobs(&mut responder, &mut device), None);
    }
    let (our_check, _) = out(&mut responder, at(START + 70));
    assert_eq!(our_check.bytes(), &central.expected_check());
    // The secrets of the derivation are gone, but for the long term key.
    assert_eq!(responder.dh_key, [0; KEY_LEN]);
    assert!(!responder.has_key_pair());
    (responder, device, central)
}

/// Pairs completely in `variant` and returns the bond.
fn pair(variant: Variant) -> (Responder, Device, Central, Bonded) {
    let (mut responder, mut device, central) = pair_up_to_encryption(variant);
    // The link layer asks for the key with EDIV 0 and Rand 0 only.
    let ltk = reversed(&central.ltk);
    assert_eq!(responder.ltk_request(0, [0; 8]), Some(ltk));
    assert_eq!(responder.ltk_request(1, [0; 8]), None);
    assert_eq!(responder.ltk_request(0, [0, 0, 0, 0, 0, 0, 0, 1]), None);

    let mut bonded = responder.encryption_changed(true);
    if variant.our_id {
        assert_eq!(bonded, None);
        let (info, outcome) = out(&mut responder, at(START + 80));
        assert_eq!(outcome, None);
        assert_eq!(info.bytes(), &pdu::<17>(IDENTITY_INFORMATION, &OUR_IRK));
        let (address, outcome) = out(&mut responder, at(START + 80));
        assert_eq!(address.bytes(), &[0x09, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0xC6]);
        bonded = outcome;
    }
    if variant.central_id {
        assert_eq!(bonded, None);
        assert_eq!(
            responder.receive(&mut device, &pdu::<17>(IDENTITY_INFORMATION, &CENTRAL_IRK), true, at(START + 90)),
            None
        );
        let mut address = [IDENTITY_ADDRESS_INFORMATION, 0x00, 0, 0, 0, 0, 0, 0];
        address[2..].copy_from_slice(&CENTRAL_IDENTITY);
        bonded = responder.receive(&mut device, &address, true, at(START + 90));
    }
    let Some(Outcome::Bonded(bond)) = bonded else { panic!("no bond: {bonded:?}") };
    assert_eq!(bond.ltk, ltk);
    // The pairing is over, with its secrets and its timer.
    assert!(!responder.is_pairing());
    assert!(!responder.has_output());
    assert_eq!(responder.deadline(), None);
    assert_eq!(responder.ltk, [0; 16]);
    assert_eq!(responder.ltk_request(0, [0; 8]), None);
    (responder, device, central, bond)
}

/// The variant BlueZ pairs with when host privacy is on.
const BOTH_WAYS: Variant =
    Variant { central_id: true, check_before_dh: false, key_pair_first: true, our_id: true };

#[test]
fn a_pairing_distributes_identity_keys_both_ways() {
    let (.., bond) = pair(BOTH_WAYS);
    let identity = bond.identity.expect("the central's identity");
    assert!(identity.address == Peer::new(CENTRAL_IDENTITY, false));
    assert_eq!(identity.irk, CENTRAL_IRK);
}

#[test]
fn a_pairing_without_the_central_s_identity_bonds_once_ours_is_queued() {
    let (.., bond) = pair(Variant { central_id: false, ..BOTH_WAYS });
    assert!(bond.identity.is_none());
}

#[test]
fn a_pairing_without_identity_keys_bonds_at_the_encryption() {
    let (.., bond) = pair(Variant { central_id: false, our_id: false, ..BOTH_WAYS });
    assert!(bond.identity.is_none());
}

#[test]
fn a_dhkey_check_before_the_diffie_hellman_key_waits_for_it() {
    pair(Variant { check_before_dh: true, ..BOTH_WAYS });
    pair(Variant { check_before_dh: true, key_pair_first: false, central_id: false, ..BOTH_WAYS });
}

#[test]
fn a_public_key_before_our_key_pair_waits_for_its_job() { pair(Variant { key_pair_first: false, ..BOTH_WAYS }); }

#[test]
fn the_long_term_key_is_reversed_for_the_link_layer() {
    // The sample data of f5 (appendix D.3), with the addresses of the
    // samples on the air: the key the link layer takes is the sample's,
    // least significant octet first.
    let mut responder = responder(local_rpa());
    responder.central = Peer::new([0xCE, 0xBF, 0x37, 0x37, 0x12, 0x56], false);
    responder.local = Peer::new([0xC1, 0xCF, 0x2D, 0x70, 0x13, 0xA7], false);
    responder.na = hex("d5cb8454 d177733e ffffb2ec 712baeab");
    responder.nb = hex("a6e8e7cc 25a75f6e 216583f7 ff3dc4cf");
    responder.dh_key = hex("ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698");
    responder.io_cap = [0x2D, 0x00, 0x04];
    let mac_key = hex("2965f176 a1084a02 fd3f6a20 ce636e20");
    let (a, b) = (address(responder.central), address(responder.local));
    responder.check = f6(&Software, &mac_key, (&responder.na, &responder.nb), &[0; 16], responder.io_cap, (&a, &b));
    responder.state = State::Check(true);
    assert_eq!(responder.verify(&Software), Ok(None));
    let ltk = responder.ltk_request(0, [0; 8]).unwrap();
    assert_eq!(ltk, reversed(&hex("69867911 69d7cd23 980522b5 94750a38")));
    // The link layer's session key derivation reverses it again into the
    // key AES takes, most significant octet first, which is f5's.
    let skd = [0x5A; 16];
    let session = Software.encrypt(reversed(&ltk), reversed(&skd));
    assert_eq!(session, Software.encrypt(hex("69867911 69d7cd23 980522b5 94750a38"), reversed(&skd)));
    assert_eq!(responder.dh_key, [0; KEY_LEN]);
}

#[test]
fn b_is_our_address_on_the_air_and_a_the_central_s() {
    // A central that takes our identity address as B computes another Ea.
    let local = local_rpa();
    for (central_view, responder_view) in
        [(Peer::new(CENTRAL_ADDRESS, false), Peer::new(OUR_ADDRESS, true)), (Peer::new(CENTRAL_ADDRESS, true), local)]
    {
        let mut responder = responder(local);
        let mut device = Device(7);
        let mut central = Central::new(linux_request(true, true), responder_view);
        central.address = central_view;
        responder.receive(&mut device, &central.request, false, at(0));
        out(&mut responder, at(0));
        responder.receive(&mut device, &central.public_key(), false, at(0));
        run_jobs(&mut responder, &mut device);
        central.take_public_key(out(&mut responder, at(0)).0.bytes());
        central.take_confirm(out(&mut responder, at(0)).0.bytes());
        run_jobs(&mut responder, &mut device);
        responder.receive(&mut device, &central.random(), false, at(0));
        central.take_random(out(&mut responder, at(0)).0.bytes());
        let outcome = responder.receive(&mut device, &central.check(), false, at(0));
        assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::DHKEY_CHECK_FAILED }));
        assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, 0x0B]);
    }
}

/// Sends `request` to a fresh security manager and returns its outcome and
/// the PDU it answers with.
fn refused(responder: &mut Responder, request: &[u8]) -> (Option<Outcome>, Output) {
    let outcome = responder.receive(&mut Device(1), request, false, at(0));
    let answer = responder.next_pdu().unwrap();
    assert_eq!(responder.pdu_sent(at(0)), None);
    assert!(!responder.has_output());
    assert!(!responder.is_pairing());
    assert_eq!(responder.deadline(), None);
    (outcome, answer)
}

#[test]
fn requests_out_of_policy_or_range_are_refused() {
    let cases: [(&[u8], u8); 12] = [
        // Without Secure Connections, or without bonding.
        (&[0x01, 0x04, 0x00, 0x05, 0x10, 0x07, 0x07], 0x03),
        (&[0x01, 0x04, 0x00, 0x2C, 0x10, 0x07, 0x07], 0x03),
        // A key size under 16 octets, and out of the range 7 to 16.
        (&[0x01, 0x04, 0x00, 0x2D, 0x0F, 0x07, 0x07], 0x06),
        (&[0x01, 0x04, 0x00, 0x2D, 0x07, 0x07, 0x07], 0x06),
        (&[0x01, 0x04, 0x00, 0x2D, 0x06, 0x07, 0x07], 0x0A),
        (&[0x01, 0x04, 0x00, 0x2D, 0x11, 0x07, 0x07], 0x0A),
        // A reserved IO capability or OOB data flag.
        (&[0x01, 0x05, 0x00, 0x2D, 0x10, 0x07, 0x07], 0x0A),
        (&[0x01, 0x04, 0x02, 0x2D, 0x10, 0x07, 0x07], 0x0A),
        // Out of band data, which we lack.
        (&[0x01, 0x04, 0x01, 0x2D, 0x10, 0x07, 0x07], 0x02),
        // The wrong length.
        (&[0x01, 0x04, 0x00, 0x2D, 0x10, 0x07], 0x0A),
        (&[0x01, 0x04, 0x00, 0x2D, 0x10, 0x07, 0x07, 0x00], 0x0A),
        (&[0x01], 0x0A),
    ];
    for (request, reason) in cases {
        let mut responder = responder(local_rpa());
        let (outcome, answer) = refused(&mut responder, request);
        assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason(reason) }), "{request:02X?}");
        assert_eq!(answer.bytes(), &[PAIRING_FAILED, reason], "{request:02X?}");
    }
}

#[test]
fn a_request_is_refused_while_pairing_is_not_allowed() {
    let mut responder = responder(local_rpa());
    responder.set_pairable(false);
    let (outcome, answer) = refused(&mut responder, &pdu::<7>(PAIRING_REQUEST, &linux_request(true, true)));
    assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::PAIRING_NOT_SUPPORTED }));
    assert_eq!(answer.bytes(), &[0x05, 0x05]);
    // No key pair is made for it.
    assert!(!responder.has_job());
}

#[test]
fn unknown_codes_get_command_not_supported() {
    for code in [0x00, 0x0F, 0x10, 0xFF] {
        // Without a pairing: answered, not reported.
        let mut responder = responder(local_rpa());
        let (outcome, answer) = refused(&mut responder, &[code, 0x00]);
        assert_eq!(outcome, None);
        assert_eq!(answer.bytes(), &[PAIRING_FAILED, 0x07]);
        // During a pairing: it ends, and the Pairing Failed replaces the
        // response still queued.
        let mut device = Device(3);
        responder.receive(&mut device, &pdu::<7>(PAIRING_REQUEST, &linux_request(true, true)), false, at(0));
        let outcome = responder.receive(&mut device, &[code], false, at(0));
        assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::COMMAND_NOT_SUPPORTED }));
        assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, 0x07]);
        assert!(!responder.has_output());
    }
    // An empty PDU has no code, and is dropped.
    let mut responder = responder(local_rpa());
    assert_eq!(responder.receive(&mut Device(3), &[], false, at(0)), None);
    assert!(!responder.has_output());
}

/// A pairing that has reached each state, by the PDUs the central sent:
/// 0 after the request, 1 after the public key, 2 after the nonce, 3 after
/// the `DHKey` check.
fn pairing_at(step: usize) -> (Responder, Device, Central) {
    let local = local_rpa();
    let mut responder = responder(local);
    let mut device = Device(5);
    let mut central = Central::new(linux_request(true, true), local);
    responder.prepare_key_pair();
    run_jobs(&mut responder, &mut device);
    responder.receive(&mut device, &central.request, false, at(0));
    out(&mut responder, at(0));
    if step >= 1 {
        responder.receive(&mut device, &central.public_key(), false, at(0));
        central.take_public_key(out(&mut responder, at(0)).0.bytes());
        central.take_confirm(out(&mut responder, at(0)).0.bytes());
        run_jobs(&mut responder, &mut device);
    }
    if step >= 2 {
        responder.receive(&mut device, &central.random(), false, at(0));
        central.take_random(out(&mut responder, at(0)).0.bytes());
    }
    if step >= 3 {
        let check = central.check();
        responder.receive(&mut device, &check, false, at(0));
        assert_eq!(out(&mut responder, at(0)).0.bytes(), &central.expected_check());
    }
    assert!(!responder.has_output());
    (responder, device, central)
}

/// Sends `pdu`, `encrypted` or not, to the pairing at `step`, which must
/// fail with `reason`.
fn fails_with(step: usize, pdu: &[u8], encrypted: bool, reason: Reason) {
    let (mut responder, mut device, _) = pairing_at(step);
    let outcome = responder.receive(&mut device, pdu, encrypted, at(0));
    assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason }), "step {step}, {pdu:02X?}");
    assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, reason.code()], "step {step}, {pdu:02X?}");
    assert!(!responder.is_pairing());
    assert!(!responder.has_output());
    assert_eq!(responder.ltk_request(0, [0; 8]), None);
    assert_eq!(responder.ltk, [0; 16]);
    assert_eq!(responder.dh_key, [0; KEY_LEN]);
}

#[test]
fn pdus_out_of_turn_get_unspecified_reason() {
    let central = Central::new(linux_request(true, true), local_rpa());
    let request = pdu::<7>(PAIRING_REQUEST, &linux_request(true, true));
    let value = [0x77; 16];
    let random = pdu::<17>(PAIRING_RANDOM, &value);
    let check = pdu::<17>(PAIRING_DHKEY_CHECK, &value);
    let info = pdu::<17>(IDENTITY_INFORMATION, &value);
    let address = [IDENTITY_ADDRESS_INFORMATION, 0, 1, 2, 3, 4, 5, 6];
    // A second request, the central's public key, nonce or check out of
    // turn, and keys before the encryption.
    for step in 0..=3 {
        fails_with(step, &request, false, Reason::UNSPECIFIED);
        fails_with(step, &info, false, Reason::UNSPECIFIED);
        fails_with(step, &address, false, Reason::UNSPECIFIED);
    }
    for step in 1..=3 {
        fails_with(step, &central.public_key(), false, Reason::UNSPECIFIED);
    }
    for step in [0, 2, 3] {
        fails_with(step, &random, false, Reason::UNSPECIFIED);
    }
    for step in [0, 1, 3] {
        fails_with(step, &check, false, Reason::UNSPECIFIED);
    }
    // Codes the central never sends in a Just Works pairing as initiator:
    // response, confirm, the legacy and signing keys, a security request and
    // keypresses.
    for code in [0x02, 0x03, 0x06, 0x07, 0x0A, 0x0B, 0x0E] {
        let mut wrong = [code; 17];
        wrong[1..].fill(0);
        fails_with(1, &wrong, false, Reason::UNSPECIFIED);
    }
}

#[test]
fn pdus_of_the_wrong_length_get_invalid_parameters() {
    let central = Central::new(linux_request(true, true), local_rpa());
    fails_with(0, &central.public_key()[..64], false, Reason::INVALID_PARAMETERS);
    fails_with(1, &[PAIRING_RANDOM; 16], false, Reason::INVALID_PARAMETERS);
    fails_with(2, &[PAIRING_DHKEY_CHECK; 18], false, Reason::INVALID_PARAMETERS);
}

#[test]
fn refused_public_keys_get_dhkey_check_failed() {
    let central = Central::new(linux_request(true, true), local_rpa());
    let own = *pairing_at(0).0.pair.as_ref().unwrap().public_key();
    let mut off_curve = *central.pair.public_key();
    off_curve[63] ^= 1;
    // The negation: the same X, and the field prime less Y.
    let mut own_negated = own;
    let prime = hex::<KEY_LEN>("ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff");
    let mut borrow = 0_i16;
    for index in (0..KEY_LEN).rev() {
        let difference = i16::from(prime[index]) - i16::from(own[KEY_LEN + index]) - borrow;
        borrow = i16::from(difference < 0);
        own_negated[KEY_LEN + index] = (difference + 256 * borrow) as u8;
    }
    for key in [off_curve, ecc::DEBUG_PUBLIC_KEY, own, own_negated] {
        fails_with(0, &pdu::<65>(PAIRING_PUBLIC_KEY, &flip_coordinates(&key)), false, Reason::DHKEY_CHECK_FAILED);
    }
    // A key that arrives before our key pair fails once the pair is there.
    let mut responder = responder(local_rpa());
    let mut device = Device(9);
    responder.receive(&mut device, &central.request, false, at(0));
    out(&mut responder, at(0));
    let key = pdu::<65>(PAIRING_PUBLIC_KEY, &flip_coordinates(&ecc::DEBUG_PUBLIC_KEY));
    assert_eq!(responder.receive(&mut device, &key, false, at(0)), None);
    let outcome = run_jobs(&mut responder, &mut device);
    assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::DHKEY_CHECK_FAILED }));
    assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, 0x0B]);
    // The key pair was never shown: it stays for the next pairing.
    assert!(responder.has_key_pair());
}

#[test]
fn a_wrong_dhkey_check_fails_and_wipes_the_keys() {
    for check_before_dh in [false, true] {
        let local = local_rpa();
        let mut responder = responder(local);
        let mut device = Device(11);
        let mut central = Central::new(linux_request(true, true), local);
        responder.prepare_key_pair();
        run_jobs(&mut responder, &mut device);
        responder.receive(&mut device, &central.request, false, at(0));
        out(&mut responder, at(0));
        responder.receive(&mut device, &central.public_key(), false, at(0));
        central.take_public_key(out(&mut responder, at(0)).0.bytes());
        central.take_confirm(out(&mut responder, at(0)).0.bytes());
        if !check_before_dh {
            run_jobs(&mut responder, &mut device);
        }
        responder.receive(&mut device, &central.random(), false, at(0));
        central.take_random(out(&mut responder, at(0)).0.bytes());
        let mut check = central.check();
        check[16] ^= 0x80;
        let mut outcome = responder.receive(&mut device, &check, false, at(0));
        if check_before_dh {
            assert_eq!(outcome, None);
            outcome = run_jobs(&mut responder, &mut device);
        }
        assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::DHKEY_CHECK_FAILED }));
        assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, 0x0B]);
        assert!(!responder.has_output());
        assert_eq!(responder.ltk_request(0, [0; 8]), None);
        assert_eq!(responder.ltk, [0; 16]);
        assert_eq!(responder.dh_key, [0; KEY_LEN]);
    }
}

#[test]
fn a_pairing_failed_from_the_central_ends_the_pairing_unanswered() {
    for step in 0..=3 {
        let (mut responder, mut device, _) = pairing_at(step);
        let outcome = responder.receive(&mut device, &[PAIRING_FAILED, 0x04], false, at(0));
        assert_eq!(outcome, Some(Outcome::Failed { by_central: true, reason: Reason::CONFIRM_VALUE_FAILED }));
        assert!(!responder.has_output());
        assert!(!responder.is_pairing());
        assert_eq!(responder.deadline(), None);
        assert_eq!(responder.ltk_request(0, [0; 8]), None);
        // Another is not answered either, and nothing is reported.
        assert_eq!(responder.receive(&mut device, &[PAIRING_FAILED, 0x08], false, at(0)), None);
        assert!(!responder.has_output());
    }
    // Without a reason, it is unspecified.
    let (mut responder, mut device, _) = pairing_at(1);
    let outcome = responder.receive(&mut device, &[PAIRING_FAILED], false, at(0));
    assert_eq!(outcome, Some(Outcome::Failed { by_central: true, reason: Reason::UNSPECIFIED }));
}

#[test]
fn a_late_diffie_hellman_result_is_dropped() {
    let local = local_rpa();
    let mut responder = responder(local);
    let mut device = Device(13);
    let mut central = Central::new(linux_request(true, true), local);
    responder.prepare_key_pair();
    run_jobs(&mut responder, &mut device);
    responder.receive(&mut device, &central.request, false, at(0));
    out(&mut responder, at(0));
    responder.receive(&mut device, &central.public_key(), false, at(0));
    central.take_public_key(out(&mut responder, at(0)).0.bytes());
    central.take_confirm(out(&mut responder, at(0)).0.bytes());
    let job = responder.take_job().unwrap();
    assert!(!job.is_key_pair());
    // The central gives up while the job runs, and pairs again.
    responder.receive(&mut device, &[PAIRING_FAILED, 0x08], false, at(0));
    assert_eq!(responder.receive(&mut device, &central.request, false, at(0)), Some(Outcome::Started));
    out(&mut responder, at(0));
    let result = job.run(&mut device.clone(), || ());
    assert_eq!(responder.job_done(&mut device, result), None);
    assert_eq!(responder.dh_key, [0; KEY_LEN]);
    // The new pairing makes a key pair of its own and goes on.
    assert!(responder.take_job().unwrap().is_key_pair());
    assert!(!responder.has_output());
}

#[test]
fn the_pairing_times_out_30_s_after_the_last_pdu_queued() {
    let (mut responder, mut device, central) = pairing_at(1);
    // The confirm value was the last PDU queued, at time 0.
    assert_eq!(responder.deadline(), Some(at(30_000)));
    responder.receive(&mut device, &central.random(), false, at(10_000));
    // Receiving does not restart the timer; queueing does.
    assert_eq!(responder.deadline(), Some(at(30_000)));
    assert_eq!(responder.on_time(at(15_000)), None);
    out(&mut responder, at(20_000));
    assert_eq!(responder.deadline(), Some(at(50_000)));
    assert_eq!(responder.on_time(at(49_999)), None);
    assert!(responder.is_pairing());
    assert_eq!(responder.on_time(at(50_000)), Some(Outcome::TimedOut));
    assert!(!responder.is_pairing());
    assert_eq!(responder.deadline(), None);
    assert_eq!(responder.on_time(at(90_000)), None);
    // No more security manager PDUs on this link, in or out.
    assert!(!responder.has_output());
    assert_eq!(responder.receive(&mut device, &central.request, false, at(50_001)), None);
    assert_eq!(responder.receive(&mut device, &[0xFF], false, at(50_001)), None);
    assert!(!responder.has_output());
    // A new link pairs again.
    responder.connected(&info(Peer::new(CENTRAL_ADDRESS, false), local_rpa()));
    responder.prepare_key_pair();
    run_jobs(&mut responder, &mut device);
    assert_eq!(responder.receive(&mut device, &central.request, false, at(60_000)), Some(Outcome::Started));
}

#[test]
fn the_timer_runs_until_the_identity_keys_complete() {
    let (mut responder, mut device, _) = pair_up_to_encryption(BOTH_WAYS);
    assert_eq!(responder.deadline(), Some(at(START + 30_070)));
    assert_eq!(responder.encryption_changed(true), None);
    out(&mut responder, at(START + 80));
    out(&mut responder, at(START + 90));
    // The central never sends its keys.
    assert_eq!(responder.on_time(at(START + 30_090)), Some(Outcome::TimedOut));
    assert_eq!(responder.ltk, [0; 16]);
    let info = pdu::<17>(IDENTITY_INFORMATION, &CENTRAL_IRK);
    assert_eq!(responder.receive(&mut device, &info, true, at(START + 30_100)), None);
}

#[test]
fn a_failed_encryption_fails_the_pairing() {
    let (mut responder, ..) = pair_up_to_encryption(BOTH_WAYS);
    let outcome = responder.encryption_changed(false);
    assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::UNSPECIFIED }));
    assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, 0x08]);
    assert_eq!(responder.ltk_request(0, [0; 8]), None);
    // Without a pairing, the encryption is not the security manager's.
    assert_eq!(responder.encryption_changed(true), None);
    assert_eq!(responder.encryption_changed(false), None);
}

#[test]
fn the_central_s_keys_must_come_encrypted_and_in_order() {
    let info = pdu::<17>(IDENTITY_INFORMATION, &CENTRAL_IRK);
    let mut address = [IDENTITY_ADDRESS_INFORMATION, 0x00, 0, 0, 0, 0, 0, 0];
    address[2..].copy_from_slice(&CENTRAL_IDENTITY);
    let attempts: [(&[&[u8]], bool, u8); 4] = [
        // Not encrypted.
        (&[&info], false, 0x08),
        // The address before the key, or twice the key.
        (&[&address], true, 0x08),
        (&[&info, &info], true, 0x08),
        // A reserved address type.
        (&[&info, &[IDENTITY_ADDRESS_INFORMATION, 0x02, 1, 2, 3, 4, 5, 6]], true, 0x0A),
    ];
    for (pdus, encrypted, reason) in attempts {
        let (mut responder, mut device, _) = pair_up_to_encryption(BOTH_WAYS);
        assert_eq!(responder.encryption_changed(true), None);
        let (last, first) = pdus.split_last().unwrap();
        for pdu in first {
            assert_eq!(responder.receive(&mut device, pdu, encrypted, at(0)), None);
        }
        let outcome = responder.receive(&mut device, last, encrypted, at(0));
        assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason(reason) }));
    }
    // Keys the central did not offer.
    let (mut responder, mut device, _) = pair_up_to_encryption(Variant { central_id: false, ..BOTH_WAYS });
    let outcome = responder.receive(&mut device, &info, true, at(0));
    assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::UNSPECIFIED }));
}

#[test]
fn the_central_s_keys_may_overtake_the_encryption_event() {
    let (mut responder, mut device, central) = pair_up_to_encryption(BOTH_WAYS);
    let mut address = [IDENTITY_ADDRESS_INFORMATION, 0x00, 0, 0, 0, 0, 0, 0];
    address[2..].copy_from_slice(&CENTRAL_IDENTITY);
    assert_eq!(responder.receive(&mut device, &pdu::<17>(IDENTITY_INFORMATION, &CENTRAL_IRK), true, at(0)), None);
    assert_eq!(responder.receive(&mut device, &address, true, at(0)), None);
    // The bond waits for the encryption and our own keys.
    assert_eq!(responder.encryption_changed(true), None);
    out(&mut responder, at(0));
    let Some(Outcome::Bonded(bond)) = out(&mut responder, at(0)).1 else { panic!("no bond") };
    assert_eq!(bond.ltk, reversed(&central.ltk));
    assert!(bond.identity.unwrap().address == Peer::new(CENTRAL_IDENTITY, false));
}

#[test]
fn an_identity_address_that_is_not_static_is_dropped_with_its_key() {
    for (kind, top) in [(0x01, 0x40), (0x01, 0x00), (0x01, 0x80)] {
        let (mut responder, mut device, _) = pair_up_to_encryption(Variant { our_id: false, ..BOTH_WAYS });
        assert_eq!(responder.encryption_changed(true), None);
        responder.receive(&mut device, &pdu::<17>(IDENTITY_INFORMATION, &CENTRAL_IRK), true, at(0));
        let address = [IDENTITY_ADDRESS_INFORMATION, kind, 1, 2, 3, 4, 5, top];
        let Some(Outcome::Bonded(bond)) = responder.receive(&mut device, &address, true, at(0)) else {
            panic!("no bond")
        };
        assert!(bond.identity.is_none());
        assert_eq!(responder.peer_irk, [0; 16]);
    }
    // A static random identity is kept.
    let (mut responder, mut device, _) = pair_up_to_encryption(Variant { our_id: false, ..BOTH_WAYS });
    responder.encryption_changed(true);
    responder.receive(&mut device, &pdu::<17>(IDENTITY_INFORMATION, &CENTRAL_IRK), true, at(0));
    let address = [IDENTITY_ADDRESS_INFORMATION, 0x01, 1, 2, 3, 4, 5, 0xC0];
    let Some(Outcome::Bonded(bond)) = responder.receive(&mut device, &address, true, at(0)) else { panic!("no bond") };
    assert!(bond.identity.unwrap().address == Peer::new([1, 2, 3, 4, 5, 0xC0], true));
}

#[test]
fn a_failure_waits_for_the_public_key_being_sent() {
    let (mut responder, mut device, central) = pairing_at(0);
    responder.receive(&mut device, &central.public_key(), false, at(0));
    // The first fragment of our public key went out.
    let public_key = responder.next_pdu().unwrap();
    let outcome = responder.receive(&mut device, &[0xFF], false, at(0));
    assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::COMMAND_NOT_SUPPORTED }));
    // The rest of it comes from the same PDU, then the Pairing Failed, but
    // not the confirm value.
    assert_eq!(responder.next_pdu(), Some(public_key));
    assert_eq!(responder.pdu_sent(at(0)), None);
    assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, 0x07]);
    assert!(!responder.has_output());
    // No Diffie-Hellman job for the failed pairing; the key pair stays.
    assert!(!responder.has_job());
    assert!(responder.has_key_pair());
}

#[test]
fn a_new_link_forgets_the_pairing_but_not_the_key_pair() {
    let (mut responder, mut device, central) = pairing_at(0);
    responder.connected(&info(Peer::new(CENTRAL_ADDRESS, false), local_rpa()));
    assert!(!responder.is_pairing());
    assert!(!responder.has_output());
    assert_eq!(responder.deadline(), None);
    assert!(responder.has_key_pair());
    // The public key of the old pairing is out of turn on the new link.
    let outcome = responder.receive(&mut device, &central.public_key(), false, at(0));
    assert_eq!(outcome, None);
    assert_eq!(out(&mut responder, at(0)).0.bytes(), &[PAIRING_FAILED, 0x08]);
    responder.disconnected();
    assert!(!responder.has_output());
}

#[test]
fn a_key_pair_is_made_once() {
    let mut responder = Responder::new();
    responder.prepare_key_pair();
    responder.prepare_key_pair();
    let job = responder.take_job().unwrap();
    assert!(job.is_key_pair());
    // Not again while it runs, nor once it is there.
    responder.prepare_key_pair();
    assert!(!responder.has_job());
    let calls = Cell::new(0);
    let result = job.run(&mut Device(17), || calls.set(calls.get() + 1));
    assert_eq!(calls.get(), 1);
    assert_eq!(responder.job_done(&mut Device(17), result), None);
    responder.prepare_key_pair();
    assert!(!responder.has_job());
    // A second key pair is dropped.
    let result = Job { kind: JobKind::KeyPair }.run(&mut Device(19), || ());
    let first = *responder.pair.as_ref().unwrap().public_key();
    assert_eq!(responder.job_done(&mut Device(19), result), None);
    assert_eq!(responder.pair.as_ref().unwrap().public_key(), &first);
}

#[test]
fn the_diffie_hellman_job_calls_the_hook_once_and_drops_the_key_pair() {
    let (mut responder, mut device, central) = pairing_at(0);
    responder.receive(&mut device, &central.public_key(), false, at(0));
    out(&mut responder, at(0));
    out(&mut responder, at(0));
    let job = responder.take_job().unwrap();
    assert!(!job.is_key_pair());
    assert!(!responder.has_key_pair());
    let calls = Cell::new(0);
    let result = job.run(&mut device.clone(), || calls.set(calls.get() + 1));
    assert_eq!(calls.get(), 1);
    assert_eq!(responder.job_done(&mut device, result), None);
    assert_eq!(responder.dh, Dh::Ready);
}

#[test]
fn a_pairing_can_follow_a_bond_on_the_same_link_only_while_pairable() {
    let (mut responder, mut device, central, _) = pair(BOTH_WAYS);
    responder.set_pairable(false);
    let outcome = responder.receive(&mut device, &central.request, true, at(0));
    assert_eq!(outcome, Some(Outcome::Failed { by_central: false, reason: Reason::PAIRING_NOT_SUPPORTED }));
    out(&mut responder, at(0));
    responder.set_pairable(true);
    assert_eq!(responder.receive(&mut device, &central.request, true, at(0)), Some(Outcome::Started));
    // A new key pair is made for it.
    assert!(responder.take_job().unwrap().is_key_pair());
}

#[test]
fn reasons_carry_their_codes() {
    assert_eq!(Reason::from_code(0x0B), Reason::DHKEY_CHECK_FAILED);
    assert_eq!(Reason::REPEATED_ATTEMPTS.code(), 0x09);
    assert_eq!(Reason::AUTHENTICATION_REQUIREMENTS.code(), 0x03);
}

#[test]
fn debug_output_leaves_the_keys_out() {
    let bond =
        Bonded { identity: Some(Identity { address: Peer::new([1; 6], true), irk: [0xEE; 16] }), ltk: [0xDD; 16] };
    let mut text = Text::default();
    core::fmt::write(&mut text, format_args!("{:?}", Outcome::Bonded(bond))).unwrap();
    let written = core::str::from_utf8(&text.bytes[..text.len]).unwrap();
    assert!(written.contains("address"), "{written}");
    assert!(!written.contains("221") && !written.contains("238"), "{written}");
}

/// A fixed buffer for formatted text.
struct Text {
    /// The text.
    bytes: [u8; 256],
    /// Its length.
    len:   usize,
}

impl Default for Text {
    fn default() -> Self { Self { bytes: [0; 256], len: 0 } }
}

impl core::fmt::Write for Text {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len + text.len();
        self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
