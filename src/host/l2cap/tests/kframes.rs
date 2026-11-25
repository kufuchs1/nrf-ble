//! Tests of the K-frames of the enhanced bearers.

use super::*;
use crate::host::ecfc::BEARERS;
use core::array::from_fn;

/// Bearer 0.
const ZERO: BearerId = BearerId::FIRST;

/// Bearer 1, for the parts that take two bearers, which run with two or
/// more.
const fn one() -> BearerId { BearerId::valid(1) }

/// An SDU of 65 octets.
fn sdu() -> [u8; 65] { from_fn(usize::truncate::<u8>) }

/// The K-frames of `sdu` at the peer's `mps`, each with its fragments.
fn send(sdu: &[u8], mps: u16) -> [([u8; 80], usize, [usize; 4]); 3] {
    let mut frames = [([0_u8; 80], 0_usize, [0_usize; 4]); 3];
    let mut sent = 0;
    for (frame, len, fragments) in frames.iter_mut().map(|entry| (&mut entry.0, &mut entry.1, &mut entry.2)) {
        let Some(mut segmenter) = Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, sdu.len(), sent, mps) else {
            break;
        };
        let mut count = 0;
        while let Some(fragment) = segmenter.fragment(sdu) {
            // Rendering again without queueing gives the same fragment.
            assert_eq!(segmenter.fragment(sdu), Some(fragment));
            assert_eq!(fragment.start(), *len == 0);
            let end = len.strict_add(fragment.bytes().len());
            frame.get_mut(*len..end).unwrap_or_default().copy_from_slice(fragment.bytes());
            *len = end;
            let slot = fragments.get_mut(count);
            assert!(slot.is_some(), "at most four fragments");
            if let Some(fragment_len) = slot {
                *fragment_len = fragment.bytes().len();
            }
            count = count.strict_add(1);
            segmenter.advance();
            assert_eq!(segmenter.is_mid_pdu(), !segmenter.is_done());
        }
        let frame_end = segmenter.kframe_end();
        assert!(frame_end.is_some(), "the K-frame ends");
        let Some((end, total)) = frame_end else { break };
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
    let segmenter = assert_some!(Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, 65, 0, 67));
    assert_eq!(segmenter.fragment(&sdu[..64]), None);
    assert!(segmenter.fragment(&sdu).is_some());
    // The whole SDU went: no further K-frame.
    assert_eq!(Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, 65, 65, 67), None);
    assert_eq!(Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, 65, 66, 67), None);
    // No room for an octet of the SDU, or an SDU too long.
    assert_eq!(Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, 65, 0, 2), None);
    assert_eq!(Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, 65, 3, 0), None);
    assert_eq!(Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, 256, 0, 67), None);
    // An empty SDU is its length field alone.
    let empty = assert_some!(Segmenter::kframe(Channel::Eatt(ZERO), 0x0050, 0, 0, 67));
    assert_eq!(assert_some!(empty.fragment(&[])).bytes(), [2, 0, 0x50, 0x00, 0, 0]);
    // A basic frame is no K-frame.
    assert_eq!(assert_some!(Segmenter::new(Channel::Att, 3)).kframe_end(), None);
}

#[test]
fn a_split_sdu_of_30_and_35_is_joined_and_encrypted_only_if_both_were() {
    let sdu = sdu();
    let first = [&[65, 0][..], &sdu[..30]].concat();
    let mut rx = SduRx::new();
    for (one, two) in [(true, true), (true, false), (false, true)] {
        assert_eq!(rx.push(ZERO, &first, one), Ok(None));
        assert_eq!(rx.push(ZERO, &sdu[30..], two), Ok(Some((&sdu[..], one && two))));
    }
    // A whole SDU is handed on in place, while another bearer's split SDU
    // waits, and empty continuations are taken.
    assert_eq!(rx.push(ZERO, &first, true), Ok(None));
    if BEARERS >= 2 {
        assert_eq!(rx.push(one(), &[1, 0, 0x0A], false), Ok(Some((&[0x0A][..], false))));
    }
    assert_eq!(rx.push(ZERO, &[], true), Ok(None));
    assert_eq!(rx.push(ZERO, &sdu[30..], true), Ok(Some((&sdu[..], true))));
    // The longest K-frame: our MPS of 67.
    let whole = [&[65, 0][..], &sdu[..]].concat();
    assert_eq!(rx.push(ZERO, &whole, true), Ok(Some((&sdu[..], true))));
}

#[test]
fn k_frames_that_break_the_rules_are_violations() {
    let sdu = sdu();
    let first = [&[65, 0][..], &sdu[..30]].concat();
    let mut rx = SduRx::new();
    // Longer than our MPS, shorter than the SDU length field, an SDU
    // longer than our MTU, more octets than its length.
    assert_eq!(rx.push(ZERO, &[0; 68], true), Err(Violation));
    assert_eq!(rx.push(ZERO, &[], true), Err(Violation));
    assert_eq!(rx.push(ZERO, &[1], true), Err(Violation));
    assert_eq!(rx.push(ZERO, &[66, 0, 0x0A], true), Err(Violation));
    assert_eq!(rx.push(ZERO, &[1, 0, 0x0A, 0x0B], true), Err(Violation));
    // A continuation beyond the SDU length drops the SDU.
    assert_eq!(rx.push(ZERO, &first, true), Ok(None));
    assert_eq!(rx.push(ZERO, &sdu[29..], true), Err(Violation));
    assert_eq!(rx.push(ZERO, &sdu[30..], true), Err(Violation), "a first K-frame again");
    // A second split SDU while another bearer's fills the buffer; the
    // first one goes on.
    assert_eq!(rx.push(ZERO, &first, true), Ok(None));
    if BEARERS >= 2 {
        assert_eq!(rx.push(one(), &first, true), Err(Violation));
    }
    assert_eq!(rx.push(ZERO, &sdu[30..], true), Ok(Some((&sdu[..], true))));
    // A continuation longer than our MPS drops the SDU.
    assert_eq!(rx.push(ZERO, &first, true), Ok(None));
    assert_eq!(rx.push(ZERO, &[0; 68], true), Err(Violation));
    if BEARERS >= 2 {
        assert_eq!(rx.push(one(), &first, true), Ok(None), "the buffer is free");
    }
}

#[test]
fn a_closed_bearer_s_split_sdu_is_dropped() {
    if BEARERS < 2 {
        return;
    }
    let sdu = sdu();
    let first = [&[65, 0][..], &sdu[..30]].concat();
    let mut rx = SduRx::new();
    assert_eq!(rx.push(ZERO, &first, true), Ok(None));
    rx.release(one());
    assert_eq!(rx.push(one(), &first, true), Err(Violation));
    rx.release(ZERO);
    assert_eq!(rx.push(one(), &first, true), Ok(None));
    assert_eq!(rx.push(one(), &sdu[30..], true), Ok(Some((&sdu[..], true))));
}

#[test]
fn a_pdu_too_long_for_the_buffer_on_a_bearer_s_cid_is_reported_once() {
    let mut reassembly = Reassembly::new();
    // A K-frame of 68 octets fits the buffer, for the bearer to refuse.
    let mut frame = [0_u8; 73];
    frame[..4].copy_from_slice(&[68, 0, 0x40, 0]);
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
    assert_eq!(assert_some!(reassembly.push(false, false, &frame[54..72])).payload.len(), 68);
    assert_eq!(reassembly.take_overlong(), None);
    // One of 69 does not.
    frame[0] = 69;
    assert_eq!(reassembly.push(true, false, &frame[..27]), None);
    assert_eq!(reassembly.take_overlong(), Some(ZERO));
    assert_eq!(reassembly.take_overlong(), None);
    assert_eq!(reassembly.push(false, false, &frame[27..54]), None);
    assert_eq!(reassembly.push(false, false, &frame[54..]), None);
    assert_eq!(reassembly.take_overlong(), None);
    // Nor on the fixed channels or a CID that is not ours.
    for cid in [0x04, 0x06, 0x3F, 0x40 + BEARERS.truncate::<u8>()] {
        frame[..4].copy_from_slice(&[69, 0, cid, 0]);
        assert_eq!(reassembly.push(true, false, &frame[..27]), None);
        assert_eq!(reassembly.take_overlong(), None);
    }
}
