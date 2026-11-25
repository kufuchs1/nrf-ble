//! Tests of the LE signalling channel.

use super::*;
use crate::host::{example::PARAMS, gatt::ppcp};

/// Sends a request for the example parameters and returns its identifier.
fn request(signalling: &mut Signalling) -> u8 {
    let identifier = signalling.request_params(PARAMS).and_then(|command| command.bytes().get(1).copied());
    assert!(identifier.is_some(), "a request with its identifier");
    identifier.unwrap_or_default()
}

#[test]
fn the_request_carries_the_same_parameters_as_the_ppcp() {
    let mut signalling = Signalling::new();
    let command = assert_some!(signalling.request_params(PARAMS));
    assert_eq!(command.bytes(), &[0x12, 0x01, 0x08, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x1E, 0x00, 0x58, 0x02]);
    assert_eq!(command.bytes().get(4..), Some(&ppcp(PARAMS)[..]));
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
    let next_id = request(&mut signalling);
    assert_eq!(next_id, 2);
    assert_eq!(signalling.receive(&[0x13, next_id, 0x02, 0x00, 0x01, 0x00]), Some(Action::Outcome(Outcome::Rejected)));
}

#[test]
fn a_command_reject_of_our_request_rejects_it() {
    let mut signalling = Signalling::new();
    let id = request(&mut signalling);
    // Another identifier: never answered, and with `eatt` handed to the
    // credit based channels, as it may reject one of their requests.
    #[cfg(not(feature = "eatt"))]
    assert_eq!(signalling.receive(&[0x01, id + 1, 0x02, 0x00, 0x00, 0x00]), None);
    #[cfg(feature = "eatt")]
    assert_eq!(
        signalling.receive(&[0x01, id + 1, 0x02, 0x00, 0x00, 0x00]),
        Some(Action::Ecfc { code: 0x01, identifier: id + 1 })
    );
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
    // Disconnection (with `eatt` for the credit based channels), LE credit
    // based connection, credit based connection and reconfigure responses.
    #[cfg(not(feature = "eatt"))]
    assert_eq!(signalling.receive(&[0x07, id, 0x04, 0x00, 0x40, 0x00, 0x40, 0x00]), None);
    #[cfg(feature = "eatt")]
    assert_eq!(
        signalling.receive(&[0x07, id, 0x04, 0x00, 0x40, 0x00, 0x40, 0x00]),
        Some(Action::Ecfc { code: 0x07, identifier: id })
    );
    assert_eq!(signalling.receive(&[0x15, 0x09, 0x0A, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    assert_eq!(signalling.receive(&[0x18, 0x09, 0x02, 0x00, 0, 0]), None);
    assert_eq!(signalling.receive(&[0x1A, 0x09, 0x02, 0x00, 0, 0]), None);
    assert!(signalling.pending());
    // Without a request waiting, a response is dropped as well (with `eatt`
    // a Command Reject goes to the credit based channels).
    let mut idle = Signalling::new();
    assert_eq!(idle.receive(&[0x13, 0x01, 0x02, 0x00, 0x00, 0x00]), None);
    #[cfg(not(feature = "eatt"))]
    assert_eq!(idle.receive(&[0x01, 0x01, 0x02, 0x00, 0x00, 0x00]), None);
}

#[test]
fn a_request_we_do_not_serve_gets_a_command_reject() {
    let mut signalling = Signalling::new();
    // An LE Credit Based Connection Request.
    let Some(Action::Reply(reply)) = ({
        let value =
            signalling.receive(&[0x14, 0x07, 0x0A, 0x00, 0x80, 0x00, 0x40, 0x00, 0x17, 0x00, 0x17, 0x00, 0x01, 0x00]);
        assert!(matches!(value, Some(Action::Reply(_))), "no Command Reject");
        value
    }) else {
        return;
    };
    assert_eq!(reply.bytes(), &[0x01, 0x07, 0x02, 0x00, 0x00, 0x00]);
    // A Connection Parameter Update Request from the central.
    let Some(Action::Reply(parameter_reject)) = ({
        let value = signalling.receive(&[0x12, 0x08, 0x08, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0A, 0x00]);
        assert!(matches!(value, Some(Action::Reply(_))), "no Command Reject");
        value
    }) else {
        return;
    };
    assert_eq!(parameter_reject.bytes(), &[0x01, 0x08, 0x02, 0x00, 0x00, 0x00]);
    // An unknown code.
    let Some(Action::Reply(unknown_reject)) = ({
        let value = signalling.receive(&[0x30, 0x09, 0x00, 0x00]);
        assert!(matches!(value, Some(Action::Reply(_))), "no Command Reject");
        value
    }) else {
        return;
    };
    assert_eq!(unknown_reject.bytes(), &[0x01, 0x09, 0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn a_disconnection_request_names_its_channels_in_the_reject() {
    #[cfg(feature = "eatt")]
    use crate::host::ecfc::BEARERS;

    let mut signalling = Signalling::new();
    // 0x0040, or with `eatt` the CID after the enhanced bearers'.
    #[cfg(feature = "eatt")]
    let dcid = 0x40 + BEARERS.truncate::<u8>();
    #[cfg(not(feature = "eatt"))]
    let dcid = 0x40;
    let Some(Action::Reply(reply)) = ({
        let value = signalling.receive(&[0x06, 0x05, 0x04, 0x00, dcid, 0x00, 0x41, 0x00]);
        assert!(matches!(value, Some(Action::Reply(_))), "no Command Reject");
        value
    }) else {
        return;
    };
    assert_eq!(reply.bytes(), &[0x01, 0x05, 0x06, 0x00, 0x02, 0x00, dcid, 0x00, 0x41, 0x00]);
    // One with the wrong data length is not understood.
    let Some(Action::Reply(malformed_reject)) = ({
        let value = signalling.receive(&[0x06, 0x06, 0x02, 0x00, 0x40, 0x00]);
        assert!(matches!(value, Some(Action::Reply(_))), "no Command Reject");
        value
    }) else {
        return;
    };
    assert_eq!(malformed_reject.bytes(), &[0x01, 0x06, 0x02, 0x00, 0x00, 0x00]);
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

/// The credit based channels' commands go to them, the others stay.
#[cfg(feature = "eatt")]
#[test]
fn the_credit_based_channels_get_their_commands() {
    use crate::host::ecfc::BEARERS;
    let mut signalling = Signalling::new();
    for pdu in [
        &[0x17, 0x03, 0x0A, 0x00, 0x27, 0x00, 0x00, 0x02, 0xF7, 0x00, 0x0A, 0x00, 0x40, 0x00][..],
        // Malformed ones too: the channels answer them.
        &[0x17, 0x03, 0x00, 0x00][..],
        &[0x16, 0x03, 0x04, 0x00, 0x40, 0x00, 0x01, 0x00][..],
        &[0x19, 0x03, 0x06, 0x00, 0x41, 0x00, 0x43, 0x00, 0x40, 0x00][..],
        &[0x07, 0x03, 0x04, 0x00, 0x40, 0x00, 0x40, 0x00][..],
        &[0x01, 0x03, 0x02, 0x00, 0x00, 0x00][..],
    ] {
        assert_eq!(signalling.receive(pdu), pdu.first().map(|&code| Action::Ecfc { code, identifier: 3 }), "{pdu:?}");
    }
    // A Disconnection Request for each of our bearers' CIDs, and none past
    // them.
    for bearer in 0..BEARERS.truncate::<u8>() {
        let pdu = [0x06, 0x04, 0x04, 0x00, 0x40 + bearer, 0x00, 0x50, 0x00];
        assert_eq!(signalling.receive(&pdu), Some(Action::Ecfc { code: 0x06, identifier: 4 }));
    }
    let past = [0x06, 0x04, 0x04, 0x00, 0x40 + BEARERS.truncate::<u8>(), 0x00, 0x50, 0x00];
    assert!(matches!(signalling.receive(&past), Some(Action::Reply(_))));
    // Responses to requests we never send, the LE credit based connection
    // request, and identifier 0 stay as they are.
    assert_eq!(signalling.receive(&[0x18, 0x03, 0x02, 0x00, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x1A, 0x03, 0x02, 0x00, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x17, 0x00, 0x00, 0x00]), None);
    let Some(Action::Reply(reply)) = ({
        let value =
            signalling.receive(&[0x14, 0x07, 0x0A, 0x00, 0x27, 0x00, 0x40, 0x00, 0x17, 0x00, 0x17, 0x00, 0x01, 0x00]);
        assert!(matches!(value, Some(Action::Reply(_))), "no Command Reject");
        value
    }) else {
        return;
    };
    assert_eq!(reply.bytes(), &[0x01, 0x07, 0x02, 0x00, 0x00, 0x00]);
}

/// Our Disconnection Requests and the parameter request share the counter,
/// and the request's response still matches it.
#[cfg(feature = "eatt")]
#[test]
fn identifiers_of_our_disconnection_requests_follow_the_parameter_request_s() {
    let mut signalling = Signalling::new();
    assert_eq!(signalling.next_identifier(), 1);
    let id = request(&mut signalling);
    assert_eq!(id, 2);
    assert_eq!(signalling.next_identifier(), 3);
    assert_eq!(signalling.next_identifier(), 4);
    // A Command Reject of our Disconnection Request is not the parameter
    // request's.
    assert_eq!(
        signalling.receive(&[0x01, 3, 0x02, 0x00, 0x00, 0x00]),
        Some(Action::Ecfc { code: 0x01, identifier: 3 })
    );
    assert!(signalling.pending());
    assert_eq!(signalling.receive(&[0x13, 4, 0x02, 0x00, 0x00, 0x00]), None);
    assert_eq!(signalling.receive(&[0x13, id, 0x02, 0x00, 0x00, 0x00]), Some(Action::Outcome(Outcome::Accepted)));
    // A Command Reject of the parameter request rejects it.
    let rejected_id = request(&mut signalling);
    assert_eq!(rejected_id, 5);
    assert_eq!(signalling.next_identifier(), 6);
    assert_eq!(
        signalling.receive(&[0x01, rejected_id, 0x02, 0x00, 0x00, 0x00]),
        Some(Action::Outcome(Outcome::Rejected))
    );
    // Once answered, a Command Reject with its identifier goes to the
    // channels.
    assert_eq!(
        signalling.receive(&[0x01, rejected_id, 0x02, 0x00, 0x00, 0x00]),
        Some(Action::Ecfc { code: 0x01, identifier: rejected_id })
    );
    // The counter skips 0.
    for expected in 7..=255 {
        assert_eq!(signalling.next_identifier(), expected);
    }
    assert_eq!(signalling.next_identifier(), 1);
}

#[cfg(feature = "eatt")]
#[test]
fn the_answers_the_credit_based_channels_give_at_once() {
    assert_eq!(Command::reconfigure_response(9, 0x0003).bytes(), &[0x1A, 9, 0x02, 0x00, 0x03, 0x00]);
    assert_eq!(Command::reject_cid(9, 0x0041, 0x0050).bytes(), &[
        0x01, 9, 0x06, 0x00, 0x02, 0x00, 0x41, 0x00, 0x50, 0x00
    ]);
}
