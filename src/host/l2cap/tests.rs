//! Tests of reassembly, demultiplexing and fragmenting.

use super::*;
use crate::{link::Shared, pdu::Llid};

/// An SMP Pairing Public Key as L2CAP carries it: header, code 0x0C and 64
/// octets of key, 69 octets in all.
fn public_key_frame() -> [u8; 69] {
    let mut frame = [0_u8; 69];
    frame[..4].copy_from_slice(&[65, 0, 6, 0]);
    frame[4] = 0x0C;
    for (index, byte) in frame[5..].iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap().wrapping_mul(7);
    }
    frame
}

/// An ATT Read Request for handle 3, as L2CAP carries it.
const READ_FRAME: [u8; 7] = [3, 0, 4, 0, 0x0A, 0x03, 0x00];

#[test]
fn a_public_key_is_joined_from_27_27_and_15_octets() {
    let frame = public_key_frame();
    let mut reassembly = Reassembly::new();
    assert_eq!(reassembly.push(true, true, &frame[..27]), None);
    assert_eq!(reassembly.push(false, true, &frame[27..54]), None);
    let pdu = reassembly.push(false, true, &frame[54..]).unwrap();
    assert_eq!(pdu.channel, Channel::SecurityManager);
    assert!(pdu.encrypted);
    assert_eq!(pdu.payload, &frame[4..]);
    assert_eq!(pdu.payload.len(), 65);
}

#[test]
fn the_buffer_holds_the_largest_pdu_and_no_more() {
    assert_eq!(RX_MAX, 72);
    let mut reassembly = Reassembly::new();
    let mut frame = [0_u8; 72];
    frame[..4].copy_from_slice(&[68, 0, 6, 0]);
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
    assert_eq!(reassembly.push(false, false, &frame[54..]).unwrap().payload.len(), 68);
}

#[test]
fn a_continuation_without_a_start_is_dropped() {
    let frame = public_key_frame();
    let mut reassembly = Reassembly::new();
    assert_eq!(reassembly.push(false, false, &READ_FRAME), None);
    assert_eq!(reassembly.push(false, false, &frame[54..]), None);
    // The next start is taken as usual.
    assert_eq!(reassembly.push(true, false, &READ_FRAME).unwrap().payload, &[0x0A, 0x03, 0x00]);
    // A continuation after a complete PDU is an orphan too.
    assert_eq!(reassembly.push(false, false, &[0x0A, 0x03, 0x00]), None);
}

#[test]
fn a_pdu_longer_than_the_buffer_is_dropped_with_its_continuations() {
    let mut reassembly = Reassembly::new();
    // 69 octets of payload: 73 with the header, one more than the buffer.
    let mut frame = [0_u8; 73];
    frame[..4].copy_from_slice(&[69, 0, 6, 0]);
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
    assert_eq!(reassembly.push(false, false, &frame[54..]), None);
    // A header announcing more than the buffer holds is dropped at once.
    assert_eq!(reassembly.push(true, false, &[0xFF, 0x00, 4, 0, 0x0A]), None);
    assert_eq!(reassembly.push(false, false, &[0; 20]), None);
    assert!(reassembly.push(true, false, &READ_FRAME).is_some());
}

#[test]
fn a_start_while_incomplete_drops_the_old_pdu() {
    let frame = public_key_frame();
    let mut reassembly = Reassembly::new();
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    let pdu = reassembly.push(true, false, &READ_FRAME).unwrap();
    assert_eq!(pdu.channel, Channel::Att);
    assert_eq!(pdu.payload, &[0x0A, 0x03, 0x00]);
    // The rest of the dropped key is an orphan now.
    assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
    assert_eq!(reassembly.push(false, false, &frame[54..]), None);
    // A restart of the key itself completes.
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
    assert_eq!(reassembly.push(false, false, &frame[54..]).unwrap().payload, &frame[4..]);
}

#[test]
fn more_octets_than_the_header_announces_drop_the_pdu() {
    let mut reassembly = Reassembly::new();
    assert_eq!(reassembly.push(true, false, &[2, 0, 4, 0, 0x0A, 0x03, 0x00]), None);
    assert_eq!(reassembly.push(true, false, &[3, 0, 4, 0, 0x0A, 0x03]), None);
    assert_eq!(reassembly.push(false, false, &[0x00, 0x00]), None);
}

#[test]
fn channels_are_found_by_cid_and_others_dropped() {
    let mut reassembly = Reassembly::new();
    assert_eq!(reassembly.push(true, false, &[1, 0, 4, 0, 0x1E]).unwrap().channel, Channel::Att);
    assert_eq!(reassembly.push(true, false, &[1, 0, 5, 0, 0x01]).unwrap().channel, Channel::Signalling);
    assert_eq!(reassembly.push(true, false, &[1, 0, 6, 0, 0x05]).unwrap().channel, Channel::SecurityManager);
    assert_eq!(reassembly.push(true, false, &[1, 0, 0x40, 0, 0x00]), None);
    assert_eq!(reassembly.push(true, false, &[1, 0, 7, 0, 0x00]), None);
    assert_eq!(reassembly.push(true, false, &[1, 0, 0, 0, 0x00]), None);
    for channel in [Channel::Att, Channel::Signalling, Channel::SecurityManager] {
        assert_eq!(Channel::from_cid(channel.cid()), Some(channel));
    }
}

#[test]
fn a_header_split_over_fragments_and_empty_pdus_are_taken() {
    let mut reassembly = Reassembly::new();
    assert_eq!(reassembly.push(true, false, &[3, 0]), None);
    assert_eq!(reassembly.push(false, false, &[]), None);
    assert_eq!(reassembly.push(false, false, &[4, 0, 0x0A]), None);
    assert_eq!(reassembly.push(false, false, &[0x03, 0x00]).unwrap().payload, &[0x0A, 0x03, 0x00]);
    let empty = reassembly.push(true, false, &[0, 0, 4, 0]).unwrap();
    assert!(empty.payload.is_empty());
}

#[test]
fn a_pdu_is_encrypted_only_if_every_fragment_was() {
    let frame = public_key_frame();
    let mut reassembly = Reassembly::new();
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert_eq!(reassembly.push(false, true, &frame[27..54]), None);
    assert!(!reassembly.push(false, true, &frame[54..]).unwrap().encrypted);
    assert_eq!(reassembly.push(true, true, &frame[..27]), None);
    assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
    assert!(!reassembly.push(false, true, &frame[54..]).unwrap().encrypted);
    // A restart forgets the plaintext fragment of the dropped PDU.
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert!(reassembly.push(true, true, &READ_FRAME).unwrap().encrypted);
}

#[test]
fn fragments_from_the_link_layer_carry_their_flags() {
    let shared = Shared::new();
    let frame = public_key_frame();
    let mut reassembly = Reassembly::new();
    assert!(shared.push_acl_in(Llid::Start, &frame[..27], true));
    assert!(shared.push_acl_in(Llid::Continuation, &frame[27..54], true));
    assert_eq!(reassembly.push_acl(&shared.take_acl_in().unwrap()), None);
    assert_eq!(reassembly.push_acl(&shared.take_acl_in().unwrap()), None);
    assert!(shared.push_acl_in(Llid::Continuation, &frame[54..], true));
    let pdu = reassembly.push_acl(&shared.take_acl_in().unwrap()).unwrap();
    assert!(pdu.encrypted);
    assert_eq!(pdu.payload, &frame[4..]);
}

#[test]
fn a_public_key_goes_out_as_27_27_and_15_octets_and_joins_again() {
    let frame = public_key_frame();
    let payload = &frame[4..];
    let mut segmenter = Segmenter::new(Channel::SecurityManager, payload.len()).unwrap();
    let mut reassembly = Reassembly::new();
    let mut lengths = [0_usize; 3];
    let mut count = 0;
    assert!(!segmenter.is_mid_pdu());
    while let Some(fragment) = segmenter.fragment(payload) {
        // Rendering again without queueing gives the same fragment.
        assert_eq!(segmenter.fragment(payload), Some(fragment));
        assert_eq!(fragment.start(), count == 0);
        lengths[count] = fragment.bytes().len();
        let joined = reassembly.push(fragment.start(), false, fragment.bytes());
        segmenter.advance();
        count += 1;
        if segmenter.is_done() {
            assert_eq!(joined.unwrap().payload, payload);
        } else {
            assert!(segmenter.is_mid_pdu());
            assert_eq!(joined, None);
        }
    }
    assert_eq!(lengths, [27, 27, 15]);
    assert!(segmenter.is_done());
    assert!(!segmenter.is_mid_pdu());
    assert_eq!(segmenter.fragment(payload), None);
    let mut first = Segmenter::new(Channel::SecurityManager, payload.len()).unwrap();
    assert_eq!(first.fragment(payload).unwrap().bytes(), &frame[..27]);
    first.advance();
    assert_eq!(first.fragment(payload).unwrap().bytes(), &frame[27..54]);
    first.advance();
    assert_eq!(first.fragment(payload).unwrap().bytes(), &frame[54..]);
}

#[test]
fn an_att_pdu_fits_one_fragment() {
    let payload = [0x0B; 23];
    let mut segmenter = Segmenter::new(Channel::Att, payload.len()).unwrap();
    let fragment = segmenter.fragment(&payload).unwrap();
    assert!(fragment.start());
    assert_eq!(&fragment.bytes()[..4], &[23, 0, 4, 0]);
    assert_eq!(&fragment.bytes()[4..], &payload);
    segmenter.advance();
    assert!(segmenter.is_done());
    assert_eq!(segmenter.channel(), Channel::Att);
}

#[test]
fn a_payload_of_another_length_renders_nothing() {
    let segmenter = Segmenter::new(Channel::Signalling, 12).unwrap();
    assert_eq!(segmenter.fragment(&[0; 11]), None);
    assert_eq!(segmenter.fragment(&[0; 13]), None);
    assert!(segmenter.fragment(&[0; 12]).is_some());
    assert!(Segmenter::new(Channel::Att, usize::from(u16::MAX) - 4).is_some());
    assert!(Segmenter::new(Channel::Att, usize::from(u16::MAX) - 3).is_none());
}
