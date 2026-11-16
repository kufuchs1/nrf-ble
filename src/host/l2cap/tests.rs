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
    #[cfg(not(feature = "eatt"))]
    assert_eq!(reassembly.push(true, false, &[1, 0, 0x40, 0, 0x00]), None);
    #[cfg(feature = "eatt")]
    {
        use crate::host::ecfc::BEARERS;
        for bearer in 0..BEARERS as u8 {
            let pdu = reassembly.push(true, false, &[1, 0, 0x40 + bearer, 0, 0x00]).unwrap();
            assert_eq!(pdu.channel, Channel::Eatt(bearer));
            assert_eq!(Channel::Eatt(bearer).cid(), 0x0040 + u16::from(bearer));
            assert_eq!(Channel::from_cid(0x0040 + u16::from(bearer)), Some(Channel::Eatt(bearer)));
        }
        assert_eq!(reassembly.push(true, false, &[1, 0, 0x40 + BEARERS as u8, 0, 0x00]), None);
        assert_eq!(reassembly.push(true, false, &[1, 0, 0x3F, 0, 0x00]), None);
    }
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

/// Tests of the K-frames of the enhanced bearers.
#[cfg(feature = "eatt")]
mod kframes {
    extern crate std;

    use super::*;

    /// An SDU of 65 octets.
    fn sdu() -> [u8; 65] { core::array::from_fn(|index| index as u8) }

    /// The K-frames of `sdu` at the peer's `mps`, each with its fragments.
    fn send(sdu: &[u8], mps: u16) -> [([u8; 80], usize, [usize; 4]); 3] {
        let mut frames = [([0_u8; 80], 0, [0; 4]); 3];
        let mut sent = 0;
        for (frame, len, fragments) in &mut frames {
            let Some(mut segmenter) = Segmenter::kframe(Channel::Eatt(1), 0x0050, sdu.len(), sent, mps) else { break };
            let mut count = 0;
            while let Some(fragment) = segmenter.fragment(sdu) {
                // Rendering again without queueing gives the same fragment.
                assert_eq!(segmenter.fragment(sdu), Some(fragment));
                assert_eq!(fragment.start(), *len == 0);
                frame[*len..*len + fragment.bytes().len()].copy_from_slice(fragment.bytes());
                *len += fragment.bytes().len();
                fragments[count] = fragment.bytes().len();
                count += 1;
                segmenter.advance();
                assert_eq!(segmenter.is_mid_pdu(), !segmenter.is_done());
            }
            let (end, total) = segmenter.kframe_end().unwrap();
            assert_eq!(total, sdu.len());
            sent = end;
        }
        frames
    }

    #[test]
    fn an_sdu_of_65_at_mps_64_is_two_k_frames_of_62_and_3() {
        let sdu = sdu();
        let [(first, first_len, first_fragments), (second, second_len, second_fragments), (_, third_len, _)] =
            send(&sdu, 64);
        assert_eq!(first_len, 4 + 64);
        assert_eq!(first[..6], [64, 0, 0x50, 0x00, 65, 0]);
        assert_eq!(first[6..68], sdu[..62]);
        assert_eq!(first_fragments, [27, 27, 14, 0]);
        assert_eq!(second_len, 4 + 3);
        assert_eq!(second[..7], [3, 0, 0x50, 0x00, 62, 63, 64]);
        assert_eq!(second_fragments, [7, 0, 0, 0]);
        assert_eq!(third_len, 0);
    }

    #[test]
    fn an_sdu_of_65_at_mps_67_or_247_is_one_k_frame_of_71_in_27_27_and_17() {
        let sdu = sdu();
        for mps in [67, 247] {
            let [(frame, len, fragments), (_, next, _), _] = send(&sdu, mps);
            assert_eq!(len, 71);
            assert_eq!(frame[..6], [67, 0, 0x50, 0x00, 65, 0]);
            assert_eq!(frame[6..71], sdu);
            assert_eq!(fragments, [27, 27, 17, 0]);
            assert_eq!(next, 0);
        }
    }

    #[test]
    fn a_k_frame_renders_nothing_for_an_sdu_of_another_length_or_after_the_last() {
        let sdu = sdu();
        let segmenter = Segmenter::kframe(Channel::Eatt(0), 0x0050, 65, 0, 67).unwrap();
        assert_eq!(segmenter.fragment(&sdu[..64]), None);
        assert!(segmenter.fragment(&sdu).is_some());
        // The whole SDU went: no further K-frame.
        assert_eq!(Segmenter::kframe(Channel::Eatt(0), 0x0050, 65, 65, 67), None);
        assert_eq!(Segmenter::kframe(Channel::Eatt(0), 0x0050, 65, 66, 67), None);
        // No room for an octet of the SDU, or an SDU too long.
        assert_eq!(Segmenter::kframe(Channel::Eatt(0), 0x0050, 65, 0, 2), None);
        assert_eq!(Segmenter::kframe(Channel::Eatt(0), 0x0050, 65, 3, 0), None);
        assert_eq!(Segmenter::kframe(Channel::Eatt(0), 0x0050, 256, 0, 67), None);
        // An empty SDU is its length field alone.
        let empty = Segmenter::kframe(Channel::Eatt(0), 0x0050, 0, 0, 67).unwrap();
        assert_eq!(empty.fragment(&[]).unwrap().bytes(), [2, 0, 0x50, 0x00, 0, 0]);
        // A basic frame is no K-frame.
        assert_eq!(Segmenter::new(Channel::Att, 3).unwrap().kframe_end(), None);
    }

    #[test]
    fn a_split_sdu_of_30_and_35_is_joined_and_encrypted_only_if_both_were() {
        let sdu = sdu();
        let first = [&[65, 0][..], &sdu[..30]].concat();
        let mut rx = SduRx::new();
        for (one, two) in [(true, true), (true, false), (false, true)] {
            assert_eq!(rx.push(0, &first, one), Ok(None));
            assert_eq!(rx.push(0, &sdu[30..], two), Ok(Some((&sdu[..], one && two))));
        }
        // A whole SDU is handed on in place, while another bearer's split SDU
        // waits, and empty continuations are taken.
        assert_eq!(rx.push(0, &first, true), Ok(None));
        assert_eq!(rx.push(1, &[1, 0, 0x0A], false), Ok(Some((&[0x0A][..], false))));
        assert_eq!(rx.push(0, &[], true), Ok(None));
        assert_eq!(rx.push(0, &sdu[30..], true), Ok(Some((&sdu[..], true))));
        // The longest K-frame: our MPS of 67.
        let whole = [&[65, 0][..], &sdu[..]].concat();
        assert_eq!(rx.push(0, &whole, true), Ok(Some((&sdu[..], true))));
    }

    #[test]
    fn k_frames_that_break_the_rules_are_violations() {
        let sdu = sdu();
        let first = [&[65, 0][..], &sdu[..30]].concat();
        let mut rx = SduRx::new();
        // Longer than our MPS, shorter than the SDU length field, an SDU
        // longer than our MTU, more octets than its length.
        assert_eq!(rx.push(0, &[0; 68], true), Err(Violation));
        assert_eq!(rx.push(0, &[], true), Err(Violation));
        assert_eq!(rx.push(0, &[1], true), Err(Violation));
        assert_eq!(rx.push(0, &[66, 0, 0x0A], true), Err(Violation));
        assert_eq!(rx.push(0, &[1, 0, 0x0A, 0x0B], true), Err(Violation));
        // A continuation beyond the SDU length drops the SDU.
        assert_eq!(rx.push(0, &first, true), Ok(None));
        assert_eq!(rx.push(0, &sdu[29..], true), Err(Violation));
        assert_eq!(rx.push(0, &sdu[30..], true), Err(Violation), "a first K-frame again");
        // A second split SDU while another bearer's fills the buffer; the
        // first one goes on.
        assert_eq!(rx.push(0, &first, true), Ok(None));
        assert_eq!(rx.push(1, &first, true), Err(Violation));
        assert_eq!(rx.push(0, &sdu[30..], true), Ok(Some((&sdu[..], true))));
        // A continuation longer than our MPS drops the SDU.
        assert_eq!(rx.push(0, &first, true), Ok(None));
        assert_eq!(rx.push(0, &[0; 68], true), Err(Violation));
        assert_eq!(rx.push(1, &first, true), Ok(None), "the buffer is free");
    }

    #[test]
    fn a_closed_bearer_s_split_sdu_is_dropped() {
        let sdu = sdu();
        let first = [&[65, 0][..], &sdu[..30]].concat();
        let mut rx = SduRx::new();
        assert_eq!(rx.push(0, &first, true), Ok(None));
        rx.release(1);
        assert_eq!(rx.push(1, &first, true), Err(Violation));
        rx.release(0);
        assert_eq!(rx.push(1, &first, true), Ok(None));
        assert_eq!(rx.push(1, &sdu[30..], true), Ok(Some((&sdu[..], true))));
    }

    #[test]
    fn a_pdu_too_long_for_the_buffer_on_a_bearer_s_cid_is_reported_once() {
        let mut reassembly = Reassembly::new();
        // A K-frame of 68 octets fits the buffer, for the bearer to refuse.
        let mut frame = [0_u8; 73];
        frame[..4].copy_from_slice(&[68, 0, 0x40, 0]);
        assert_eq!(reassembly.push(true, false, &frame[..27]), None);
        assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
        assert_eq!(reassembly.push(false, false, &frame[54..72]).unwrap().payload.len(), 68);
        assert_eq!(reassembly.take_overlong(), None);
        // One of 69 does not.
        frame[0] = 69;
        assert_eq!(reassembly.push(true, false, &frame[..27]), None);
        assert_eq!(reassembly.take_overlong(), Some(0));
        assert_eq!(reassembly.take_overlong(), None);
        assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
        assert_eq!(reassembly.push(false, false, &frame[54..]), None);
        assert_eq!(reassembly.take_overlong(), None);
        // Nor on the fixed channels or a CID that is not ours.
        for cid in [0x04, 0x06, 0x3F, 0x40 + crate::host::ecfc::BEARERS as u8] {
            frame[..4].copy_from_slice(&[69, 0, cid, 0]);
            assert_eq!(reassembly.push(true, false, &frame[..27]), None);
            assert_eq!(reassembly.take_overlong(), None);
        }
    }
}
