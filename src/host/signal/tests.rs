//! Tests of the LE signalling channel.

use super::*;
use crate::host::gatt::{ppcp, spotlight::PARAMS};

/// Sends a request for the Spotlight parameters and returns its identifier.
fn request(signalling: &mut Signalling) -> u8 {
    let command = signalling.request_params(PARAMS).unwrap();
    command.bytes()[1]
}

#[test]
fn the_request_carries_the_same_parameters_as_the_ppcp() {
    let mut signalling = Signalling::new();
    let command = signalling.request_params(PARAMS).unwrap();
    assert_eq!(command.bytes(), &[0x12, 0x01, 0x08, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x1E, 0x00, 0x58, 0x02]);
    assert_eq!(command.bytes()[4..], ppcp(PARAMS));
    assert!(signalling.pending());
    // One request at a time.
    assert_eq!(signalling.request_params(PARAMS), None);
}

#[test]
fn the_response_gives_the_outcome() {
    let mut signalling = Signalling::new();
    let id = request(&mut signalling);
    assert_eq!(signalling.receive(&[0x13, id, 0x02, 0x00, 0x00, 0x00]), Some(Action::Outcome(Outcome::Accepted)));
    assert!(!signalling.pending());
    // A second response to the same request is dropped.
    assert_eq!(signalling.receive(&[0x13, id, 0x02, 0x00, 0x00, 0x00]), None);
    let id = request(&mut signalling);
    assert_eq!(id, 2);
    assert_eq!(signalling.receive(&[0x13, id, 0x02, 0x00, 0x01, 0x00]), Some(Action::Outcome(Outcome::Rejected)));
}

#[test]
fn a_command_reject_of_our_request_rejects_it() {
    let mut signalling = Signalling::new();
    let id = request(&mut signalling);
    // Another identifier: dropped, and never answered.
    assert_eq!(signalling.receive(&[0x01, id + 1, 0x02, 0x00, 0x00, 0x00]), None);
    assert!(signalling.pending());
    assert_eq!(signalling.receive(&[0x01, id, 0x02, 0x00, 0x00, 0x00]), Some(Action::Outcome(Outcome::Rejected)));
    assert!(!signalling.pending());
}

#[test]
fn responses_with_identifier_0_a_wrong_length_or_another_identifier_are_dropped() {
    let mut signalling = Signalling::new();
    let id = request(&mut signalling);
    assert_eq!(signalling.receive(&[0x13, 0x00, 0x02, 0x00, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x13, id, 0x03, 0x00, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x13, id, 0x02, 0x00, 0x00, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x13, id, 0x01, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x13, id + 1, 0x02, 0x00, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x13, id]), None);
    assert_eq!(signalling.receive(&[]), None);
    assert!(signalling.pending());
}

#[test]
fn other_responses_are_never_answered() {
    let mut signalling = Signalling::new();
    let id = request(&mut signalling);
    // Disconnection, LE credit based connection and credit based
    // connection responses.
    assert_eq!(signalling.receive(&[0x07, id, 0x04, 0x00, 0x40, 0x00, 0x40, 0x00]), None);
    assert_eq!(signalling.receive(&[0x15, 0x09, 0x0A, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    assert_eq!(signalling.receive(&[0x18, 0x09, 0x02, 0x00, 0, 0]), None);
    assert!(signalling.pending());
    // Without a request waiting, a response is dropped as well.
    let mut idle = Signalling::new();
    assert_eq!(idle.receive(&[0x13, 0x01, 0x02, 0x00, 0x00, 0x00]), None);
    assert_eq!(idle.receive(&[0x01, 0x01, 0x02, 0x00, 0x00, 0x00]), None);
}

#[test]
fn a_request_we_do_not_serve_gets_a_command_reject() {
    let mut signalling = Signalling::new();
    // An LE Credit Based Connection Request.
    let Some(Action::Reply(reply)) =
        signalling.receive(&[0x14, 0x07, 0x0A, 0x00, 0x80, 0x00, 0x40, 0x00, 0x17, 0x00, 0x17, 0x00, 0x01, 0x00])
    else {
        panic!("no Command Reject");
    };
    assert_eq!(reply.bytes(), &[0x01, 0x07, 0x02, 0x00, 0x00, 0x00]);
    // A Connection Parameter Update Request from the central.
    let Some(Action::Reply(reply)) =
        signalling.receive(&[0x12, 0x08, 0x08, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0A, 0x00])
    else {
        panic!("no Command Reject");
    };
    assert_eq!(reply.bytes(), &[0x01, 0x08, 0x02, 0x00, 0x00, 0x00]);
    // An unknown code.
    let Some(Action::Reply(reply)) = signalling.receive(&[0x30, 0x09, 0x00, 0x00]) else {
        panic!("no Command Reject");
    };
    assert_eq!(reply.bytes(), &[0x01, 0x09, 0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn a_disconnection_request_names_its_channels_in_the_reject() {
    let mut signalling = Signalling::new();
    let Some(Action::Reply(reply)) = signalling.receive(&[0x06, 0x05, 0x04, 0x00, 0x40, 0x00, 0x41, 0x00]) else {
        panic!("no Command Reject");
    };
    assert_eq!(reply.bytes(), &[0x01, 0x05, 0x06, 0x00, 0x02, 0x00, 0x40, 0x00, 0x41, 0x00]);
    // One with the wrong data length is not understood.
    let Some(Action::Reply(reply)) = signalling.receive(&[0x06, 0x06, 0x02, 0x00, 0x40, 0x00]) else {
        panic!("no Command Reject");
    };
    assert_eq!(reply.bytes(), &[0x01, 0x06, 0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn requests_with_identifier_0_or_a_wrong_length_are_dropped() {
    let mut signalling = Signalling::new();
    assert_eq!(signalling.receive(&[0x06, 0x00, 0x04, 0x00, 0x40, 0x00, 0x41, 0x00]), None);
    assert_eq!(signalling.receive(&[0x06, 0x05, 0x04, 0x00, 0x40, 0x00, 0x41]), None);
    assert_eq!(signalling.receive(&[0x14, 0x05, 0x02, 0x00, 0x40, 0x00, 0x41]), None);
    assert_eq!(signalling.receive(&[0x14, 0x05, 0x02]), None);
}

#[test]
fn identifiers_skip_0_and_a_cancelled_request_ignores_its_late_response() {
    let mut signalling = Signalling::new();
    for expected in 1..=255_u8 {
        assert_eq!(request(&mut signalling), expected);
        signalling.cancel();
    }
    assert_eq!(request(&mut signalling), 1);
    signalling.cancel();
    assert!(!signalling.pending());
    assert_eq!(signalling.receive(&[0x13, 0x01, 0x02, 0x00, 0x00, 0x00]), None);
}
