//! Tests of the typed link API: the behaviour the byte level HCI module
//! checked, expressed with typed calls, and the additions of the typed API.

use super::*;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

/// Starts a link and returns its epoch.
fn connect(shared: &Shared) -> Epoch {
    shared.set_connected(true);
    shared.set_info(
        (Peer::new([1, 2, 3, 4, 5, 0x40], true), None, Peer::new([9; 6], true)),
        ConnectionParams::new(12, 0, 600),
        0,
    )
}

/// Polls `future` once; it must not block.
fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("operation unexpectedly blocked"),
    }
}

#[test]
fn events_are_small_and_the_queue_holds_six() {
    assert!(size_of::<Event>() <= 12);
    let shared = Shared::new();
    for _ in 0..EVENT_QUEUE {
        assert!(shared.try_push_event(Event::PayloadTimeout));
    }
    assert!(!shared.try_push_event(Event::PayloadTimeout));
    assert_eq!(EVENT_QUEUE, 6);
}

#[test]
fn reset_waits_for_radio_shutdown_and_clears_old_queues() {
    let shared = Shared::new();
    connect(&shared);
    assert!(shared.try_push_event(Event::PayloadTimeout));
    assert!(shared.push_acl_in(Llid::Start, &[1], false));
    let link = Link::new(&shared);
    let mut reset = pin!(link.reset());
    let mut context = Context::from_waker(Waker::noop());
    assert!(reset.as_mut().poll(&mut context).is_pending());
    assert!(shared.state.lock(|cell| cell.borrow().connected));
    assert!(shared.take_reset());
    shared.complete_reset();
    assert!(reset.as_mut().poll(&mut context).is_ready());
    assert!(link.try_next().is_none());
    assert!(!shared.state.lock(|cell| cell.borrow().connected));
}

#[test]
fn a_second_connection_update_waits_for_the_first_to_complete() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    shared.set_remote_features(0x02);
    let range = ParamRange::new(6, 12, 0, 100);
    assert_eq!(link.request_params(epoch, range), Ok(()));
    assert_eq!(link.request_params(epoch, range), Err(Error::Disallowed));
    assert_eq!(shared.take_param_request(), Some([6, 12, 0, 100]));
    shared.finish_param_request();
    assert_eq!(link.request_params(epoch, range), Ok(()));
    assert_eq!(link.request_params(epoch, ParamRange::new(12, 6, 0, 100)), Err(Error::Invalid));
    // A link that ends forgets the request, and refuses the old epoch.
    shared.set_connected(false);
    let next = connect(&shared);
    shared.set_remote_features(0x02);
    assert_eq!(link.request_params(epoch, range), Err(Error::Gone));
    assert_eq!(link.request_params(next, range), Ok(()));
}

#[test]
fn rssi_reports_the_link_average_or_nothing() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    assert_eq!(link.rssi(Epoch(1)), None);
    let epoch = connect(&shared);
    assert_eq!(link.rssi(epoch), None);
    shared.set_rssi(Some(-61));
    assert_eq!(link.rssi(epoch), Some(-61));
    shared.set_connected(false);
    let next = connect(&shared);
    assert_eq!(link.rssi(epoch), None);
    assert_eq!(link.rssi(next), None);
}

#[test]
fn privacy_enable_mode_and_list_changes_are_enforced() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let peer = Peer::new([1; 6], true);
    assert_eq!(link.add_peer(peer, [0; 16], [0; 16]), Ok(()));
    assert_eq!(link.set_privacy_mode(peer, true), Ok(()));
    assert_eq!(link.set_privacy_mode(Peer::new([2; 6], true), true), Err(Error::Invalid));
    assert_eq!(link.set_address_resolution(true), Ok(()));
    shared.state.lock(|cell| cell.borrow_mut().legacy_enabled = true);
    assert_eq!(link.clear_peers(), Err(Error::Disallowed));
    assert_eq!(link.set_address_resolution(false), Err(Error::Disallowed));
    shared.state.lock(|cell| cell.borrow_mut().legacy_enabled = false);
    assert_eq!(link.set_address_resolution(false), Ok(()));
    assert!(!shared.state.lock(|cell| cell.borrow().legacy.resolution_enabled));
    for slot in 2..=u8::try_from(crate::advertiser::legacy::RESOLVING_LIST_SIZE).unwrap() {
        assert_eq!(link.add_peer(Peer::new([slot; 6], true), [0; 16], [0; 16]), Ok(()));
    }
    assert_eq!(link.add_peer(Peer::new([0xEE; 6], true), [0; 16], [0; 16]), Err(Error::Full));
}

#[test]
fn info_keeps_the_addresses_on_the_air_and_the_identity_apart() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    assert!(link.info().is_none());
    shared.set_connected(true);
    let on_air = Peer::new([1, 2, 3, 4, 5, 0x40], true);
    let identity = Peer::new([6; 6], false);
    let local = Peer::new([0xAA, 0xFB, 0x0D, 0x94, 0x81, 0x70], true);
    let epoch = shared.set_info((on_air, Some(identity), local), ConnectionParams::new(12, 0, 600), 5);
    let info = link.info().unwrap();
    assert_eq!(info.epoch, epoch);
    assert!(info.peer == on_air && info.identity == Some(identity) && info.local == local);
    assert_eq!(info.params, ConnectionParams::new(12, 0, 600));
    assert_eq!(info.central_accuracy, 5);
    shared.set_connected(false);
    assert!(link.info().is_none());
}

#[cfg(feature = "nrf52832")]
#[test]
fn phy_requests_are_validated_and_one_runs_at_a_time() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert_eq!(link.set_phy(epoch, Some(1), Some(2)), Ok(()));
    assert_eq!(shared.take_phy_request(), Some([1, 2]));
    assert_eq!(link.set_phy(epoch, Some(1), Some(2)), Err(Error::Disallowed));
    shared.complete_query(QUERY_PHY);
    assert_eq!(link.set_phy(epoch, Some(4), Some(2)), Err(Error::Invalid));
    assert_eq!(link.set_phy(epoch, Some(0), None), Err(Error::Invalid));
    assert_eq!(link.set_default_phy(None, None), Ok(()));
    assert_eq!(shared.preferred_phys(), [3, 3]);
    assert_eq!(link.phy(epoch), Ok([1, 1]));
    assert_eq!(link.phy(Epoch(0)), Err(Error::Gone));
}

#[cfg(feature = "nrf51")]
#[test]
fn without_2m_phy_requests_naming_2m_or_coded_are_unsupported() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    let preferred = shared.preferred_phys();
    for [tx, rx] in [[2, 1], [1, 2], [3, 1], [1, 3], [4, 1], [1, 4], [5, 5], [6, 6]] {
        assert_eq!(link.set_phy(epoch, Some(tx), Some(rx)), Err(Error::Unsupported));
        assert_eq!(link.set_default_phy(Some(tx), Some(rx)), Err(Error::Unsupported));
    }
    assert_eq!(link.set_default_phy(None, Some(2)), Err(Error::Unsupported));
    assert_eq!(shared.preferred_phys(), preferred);
    // Reserved bits stay invalid.
    assert_eq!(link.set_phy(epoch, Some(8), Some(1)), Err(Error::Invalid));
    assert_eq!(shared.take_phy_request(), None);
    // LE 1M alone, or no preference, is taken.
    assert_eq!(link.set_phy(epoch, Some(1), Some(1)), Ok(()));
    assert_eq!(shared.take_phy_request(), Some([1, 1]));
    assert_eq!(link.set_default_phy(Some(1), Some(1)), Ok(()));
    assert_eq!(shared.preferred_phys(), [1, 1]);
    assert_eq!(link.set_default_phy(None, Some(1)), Ok(()));
    assert_eq!(shared.preferred_phys(), [3, 1]);
}

#[test]
fn the_payload_timeout_belongs_to_a_live_link() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    assert_eq!(link.set_payload_timeout(Epoch(1), 100), Err(Error::Gone));
    assert_eq!(shared.payload_timeout(), u32::from(DEFAULT_PAYLOAD_TIMEOUT) * 10_000);
    let epoch = connect(&shared);
    assert_eq!(link.set_payload_timeout(epoch, 0), Err(Error::Invalid));
    assert_eq!(link.set_payload_timeout(epoch, 100), Ok(()));
    assert_eq!(shared.payload_timeout(), 1_000_000);
    assert_eq!(link.payload_timeout(epoch), Ok(100));
}

#[test]
fn cached_private_address_survives_restarts_but_not_expiry_or_key_changes() {
    let shared = Shared::new();
    let address = Peer::new([1, 2, 3, 4, 5, 0x40], true);
    shared.state.lock(|cell| {
        let mut state = cell.borrow_mut();
        state.private_address = Some((address, [7; 16], Instant::from_secs(900)));
        assert!(state.cached_address([7; 16], Instant::from_secs(3)) == Some(address));
        assert!(state.cached_address([7; 16], Instant::from_secs(899)) == Some(address));
        assert!(state.cached_address([7; 16], Instant::from_secs(900)).is_none());
        assert!(state.cached_address([8; 16], Instant::from_secs(15)).is_none());
    });
}

#[test]
fn a_fragment_for_a_link_that_ended_cannot_enter_the_next_one() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    for _ in 0..ACL_OUT_BUFFERS {
        assert_eq!(link.try_send(epoch, true, &[42]), Ok(()));
    }
    assert_eq!(link.tx_room(), 0);
    assert_eq!(link.try_send(epoch, true, &[42]), Err(Error::Full));
    let mut pending = pin!(link.send(epoch, true, &[42]));
    let mut context = Context::from_waker(Waker::noop());
    assert!(pending.as_mut().poll(&mut context).is_pending());
    shared.set_connected(false);
    let next = connect(&shared);
    assert!(matches!(pending.as_mut().poll(&mut context), Poll::Ready(Err(Error::Gone))));
    assert!(shared.next_acl_out().is_none());
    assert_eq!(link.try_send(epoch, true, &[99]), Err(Error::Gone));
    run(link.send(next, true, &[99])).unwrap();
    assert_eq!(shared.next_acl_out().unwrap().data[0], 99);
}

#[test]
fn oversized_fragments_are_refused_and_an_empty_one_continues() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert_eq!(link.try_send(epoch, true, &[0; ACL_MAX + 1]), Err(Error::Invalid));
    assert!(!shared.has_acl_out());
    assert_eq!(link.try_send(epoch, true, &[]), Ok(()));
    assert!(shared.next_acl_out().unwrap().llid == Llid::Continuation);
    assert_eq!(link.try_send(epoch, false, &[1]), Ok(()));
    assert!(shared.next_acl_out().unwrap().llid == Llid::Continuation);
    assert_eq!(link.try_send(epoch, true, &[1]), Ok(()));
    assert!(shared.next_acl_out().unwrap().llid == Llid::Start);
}

#[test]
fn in_flight_counts_queued_fragments_until_the_central_acknowledges_them() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert_eq!(link.in_flight(epoch), 0);
    link.try_send(epoch, true, &[1]).unwrap();
    link.try_send(epoch, true, &[2]).unwrap();
    assert_eq!(link.in_flight(epoch), 2);
    // Taken for the air, not yet acknowledged.
    assert!(shared.next_acl_out().is_some());
    assert_eq!(link.in_flight(epoch), 2);
    shared.acknowledged(1);
    assert_eq!(link.in_flight(epoch), 1);
    assert_eq!(link.acked(), 1);
    // A new link starts from nothing.
    shared.set_connected(false);
    assert_eq!(link.in_flight(epoch), 0);
    let next = connect(&shared);
    assert_eq!(link.in_flight(next), 0);
    assert_eq!(link.acked(), 0);
}

#[test]
fn taking_a_fragment_for_the_air_signals_room() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    let mut context = Context::from_waker(Waker::noop());
    let mut room = pin!(link.tx_room_changed());
    assert!(room.as_mut().poll(&mut context).is_pending());
    link.try_send(epoch, true, &[1]).unwrap();
    assert!(room.as_mut().poll(&mut context).is_pending());
    assert!(shared.next_acl_out().is_some());
    assert!(room.as_mut().poll(&mut context).is_ready());
    // The end of the link frees the queue too.
    let mut room = pin!(link.tx_room_changed());
    assert!(room.as_mut().poll(&mut context).is_pending());
    shared.set_connected(false);
    assert!(room.as_mut().poll(&mut context).is_ready());
}

#[test]
fn an_acknowledgement_signals_room() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    let mut context = Context::from_waker(Waker::noop());
    link.try_send(epoch, true, &[1]).unwrap();
    assert!(shared.next_acl_out().is_some());
    let mut room = pin!(link.tx_room_changed());
    assert!(room.as_mut().poll(&mut context).is_ready());
    // Fewer fragments in flight is room for the host's pacing too.
    let mut room = pin!(link.tx_room_changed());
    assert!(room.as_mut().poll(&mut context).is_pending());
    shared.acknowledged(0);
    assert!(room.as_mut().poll(&mut context).is_pending());
    shared.acknowledged(1);
    assert!(room.as_mut().poll(&mut context).is_ready());
    assert_eq!(link.in_flight(epoch), 0);
}

#[test]
fn a_key_reply_needs_its_link_and_a_pending_request() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert_eq!(link.ltk_reply(epoch, Some([0xAA; 16])), Err(Error::Disallowed));
    assert!(shared.request_ltk([3; 8], [0x34, 0x12]));
    assert_eq!(shared.take_event(), Some(Event::LtkRequest { ediv: 0x1234, rand: [3; 8] }));
    assert_eq!(link.ltk_reply(Epoch(0), Some([0xAA; 16])), Err(Error::Gone));
    assert!(shared.take_ltk().is_none());
    assert_eq!(link.ltk_reply(epoch, Some([0xAA; 16])), Ok(()));
    assert_eq!(shared.take_ltk(), Some(Some([0xAA; 16])));
    assert_eq!(link.ltk_reply(epoch, None), Err(Error::Disallowed));
    assert!(shared.request_ltk([0; 8], [0; 2]));
    assert_eq!(link.ltk_reply(epoch, None), Ok(()));
    assert_eq!(shared.take_ltk(), Some(None));
}

#[test]
fn a_key_reply_for_a_link_that_ended_has_no_effect_on_the_next() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let old = connect(&shared);
    // The central asks for encryption and leaves before the host answers.
    assert!(shared.request_ltk([0; 8], [0; 2]));
    shared.set_connected(false);
    assert_eq!(link.ltk_reply(old, Some([0xAA; 16])), Err(Error::Gone));
    // A new link asks for its own key: the old link's late answer goes
    // nowhere, the new link's answer is its key.
    let next = connect(&shared);
    assert!(shared.request_ltk([1; 8], [1; 2]));
    assert_eq!(link.ltk_reply(old, None), Err(Error::Gone));
    assert!(shared.take_ltk().is_none());
    assert_eq!(link.ltk_reply(next, Some([0xBB; 16])), Ok(()));
    assert_eq!(shared.take_ltk(), Some(Some([0xBB; 16])));
}

#[test]
fn a_full_event_queue_does_not_authorize_an_unsolicited_key_reply() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    while shared.try_push_event(Event::PayloadTimeout) {}
    assert!(!shared.request_ltk([0; 8], [0; 2]));
    assert_eq!(link.ltk_reply(epoch, None), Err(Error::Disallowed));
}

#[test]
fn disconnect_reasons_and_links_are_checked() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    assert_eq!(link.disconnect(Epoch(1), 0x13), Err(Error::Gone));
    let epoch = connect(&shared);
    assert_eq!(link.disconnect(Epoch(0), 0x13), Err(Error::Gone));
    assert_eq!(link.disconnect(epoch, 0x16), Err(Error::Invalid));
    assert!(shared.take_disconnect().is_none());
    assert_eq!(link.disconnect(epoch, 0x13), Ok(()));
    assert_eq!(shared.take_disconnect(), Some(0x13));
}

#[test]
fn reset_forgets_keys_settings_and_the_link() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert_eq!(link.add_peer(Peer::new([1, 2, 3, 4, 5, 0xC6], true), [0x11; 16], [0x22; 16]), Ok(()));
    assert_eq!(link.set_payload_timeout(epoch, 100), Ok(()));
    assert_eq!(link.set_rpa_timeout(60), Ok(()));
    link.set_host_decides_params(true);
    link.hold_latency(true);
    shared.complete_reset();
    shared.state.lock(|cell| {
        let state = cell.borrow();
        assert!(state.legacy.resolving.is_empty());
        assert_eq!(state.payload_timeout, DEFAULT_PAYLOAD_TIMEOUT);
        assert_eq!(state.private_timeout, PRIVATE_ADDRESS_TIMEOUT);
        assert!(!state.connected);
        assert_ne!(state.epoch, epoch.0);
    });
    assert!(!shared.host_decides_parameters());
    assert!(!shared.latency_held());
}

#[test]
fn the_private_address_timeout_is_checked_and_kept() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    for seconds in [0, 0x0E11] {
        assert_eq!(link.set_rpa_timeout(seconds), Err(Error::Invalid));
    }
    assert_eq!(link.set_rpa_timeout(0x0E10), Ok(()));
    assert_eq!(shared.state.lock(|cell| cell.borrow().private_timeout), Duration::from_secs(3600));
}

#[test]
fn disconnect_drops_outgoing_data_and_requests_but_keeps_received_data() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert!(shared.push_acl_in(Llid::Start, &[1, 2, 3], true));
    link.try_send(epoch, true, &[0]).unwrap();
    shared.ltk.signal(Some([0xAA; 16]));
    shared.disconnect.signal(0x13);
    shared.data_length.signal([251, 2120]);
    shared.state.lock(|cell| cell.borrow_mut().payload_timeout = 100);
    shared.set_connected(false);
    // Acknowledged data reaches the host before the disconnection, with its
    // encryption.
    let Some(Rx::Acl(acl)) = link.try_next() else { panic!("the received fragment is kept") };
    assert!(acl.start() && acl.encrypted() && acl.payload() == [1, 2, 3]);
    assert!(shared.next_acl_out().is_none());
    assert!(shared.take_ltk().is_none());
    assert!(shared.take_disconnect().is_none());
    assert!(shared.take_data_length().is_none());
    assert_eq!(shared.state.lock(|cell| cell.borrow().payload_timeout), DEFAULT_PAYLOAD_TIMEOUT);
    // A reset drops it.
    assert!(shared.push_acl_in(Llid::Start, &[1], false));
    shared.complete_reset();
    assert!(link.try_next().is_none());
}

#[test]
fn a_connection_update_while_the_host_answers_a_central_request_is_part_of_the_answer() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    let range = ParamRange::new(6, 12, 0, 100);
    // Before the feature exchange a request is refused: the host uses the
    // L2CAP request.
    assert_eq!(link.request_params(epoch, range), Err(Error::UnsupportedRemote));
    // While the host answers a central's request it is part of the answer,
    // owed a completion when the central's procedure ends, also while an own
    // request of the host runs.
    shared.ask_parameters();
    assert_eq!(link.request_params(epoch, range), Ok(()));
    assert_eq!(link.request_params(epoch, range), Ok(()));
    assert!(shared.take_param_request().is_none());
    assert_eq!(shared.take_merged_updates(), 2);
    assert_eq!(shared.take_merged_updates(), 0);
    // Without a central's request a plain request needs the feature.
    assert_eq!(link.reply_params(epoch, Ok(range)), Ok(()));
    assert_eq!(link.reply_params(epoch, Ok(range)), Err(Error::Disallowed));
    assert_eq!(link.request_params(epoch, range), Err(Error::UnsupportedRemote));
}

#[test]
fn data_lengths_are_checked_and_limited_to_this_side() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    assert_eq!(link.set_suggested_length(26, 328), Err(Error::Invalid));
    assert_eq!(link.set_suggested_length(27, 327), Err(Error::Invalid));
    assert_eq!(link.set_suggested_length(27, 0x4291), Err(Error::Invalid));
    assert_eq!(link.set_suggested_length(27, 0x4290), Ok(()));
    assert_eq!(shared.suggested_length(), [27, LENGTH_MAX[1]]);
    assert_eq!(link.set_data_length(Epoch(1), 27, 328), Err(Error::Gone));
    let epoch = connect(&shared);
    assert_eq!(link.set_data_length(epoch, LENGTH_MAX[0] + 1, 328), Err(Error::Invalid));
    assert_eq!(link.set_data_length(epoch, LENGTH_MAX[0], 328), Ok(()));
    assert_eq!(shared.take_data_length(), Some([LENGTH_MAX[0], 328]));
}

#[test]
fn queries_run_one_at_a_time_per_kind() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    assert_eq!(link.read_remote_features(Epoch(1)), Err(Error::Gone));
    let epoch = connect(&shared);
    assert_eq!(link.read_remote_features(epoch), Ok(()));
    assert_eq!(link.read_remote_features(epoch), Err(Error::Disallowed));
    assert_eq!(link.read_remote_version(epoch), Ok(()));
    assert_eq!(shared.take_queries(), QUERY_FEATURES | QUERY_VERSION);
    shared.complete_query(QUERY_FEATURES);
    assert_eq!(link.read_remote_features(epoch), Ok(()));
}

#[test]
fn advertising_needs_an_identity_valid_parameters_and_no_link() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let params = AdvParams::new(Kind::ConnectableUndirected).interval(0x0030);
    assert_eq!(link.advertise(&params, &[2, 1, 6], &[]), Err(Error::Invalid));
    assert_eq!(link.set_identity([1, 2, 3, 4, 5, 0xC6]), Ok(()));
    assert_eq!(link.advertise(&params.interval(0x001F), &[], &[]), Err(Error::Invalid));
    assert_eq!(link.advertise(&params.channel_map(0), &[], &[]), Err(Error::Invalid));
    assert_eq!(link.advertise(&params, &[0; 32], &[]), Err(Error::Invalid));
    assert_eq!(link.advertise(&params, &[2, 1, 6], &[3, 9, 0x41, 0x42]), Ok(()));
    let settings = shared.advertising().unwrap();
    assert_eq!(settings.own.address, [1, 2, 3, 4, 5, 0xC6]);
    assert_eq!(settings.interval, 0x30 * 625);
    assert_eq!(&settings.data[..usize::from(settings.len)], &[2, 1, 6]);
    assert_eq!(&settings.scan_data[..usize::from(settings.scan_len)], &[3, 9, 0x41, 0x42]);
    assert_eq!(link.set_identity([7; 6]), Err(Error::Disallowed));
    // Advertising again replaces the data.
    assert_eq!(link.advertise(&params, &[2, 1, 4], &[]), Ok(()));
    assert_eq!(shared.advertising().unwrap().scan_len, 0);
    link.stop_advertising();
    assert!(shared.advertising().is_none());
    connect(&shared);
    assert_eq!(link.advertise(&params, &[], &[]), Err(Error::Disallowed));
}

#[test]
fn the_accept_list_is_locked_while_advertising_filters_on_it() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    for slot in 0..u8::try_from(ACCEPT_LIST_SIZE).unwrap() {
        assert_eq!(link.accept_list_add(Peer::new([slot; 6], false)), Ok(()));
    }
    assert_eq!(link.accept_list_add(Peer::new([0xEE; 6], false)), Err(Error::Full));
    assert_eq!(link.accept_list_remove(Peer::new([0; 6], false)), Ok(()));
    assert_eq!(link.set_identity([1, 2, 3, 4, 5, 0xC6]), Ok(()));
    let filtered = AdvParams::new(Kind::ConnectableUndirected).filter_policy(2);
    assert_eq!(link.advertise(&filtered, &[], &[]), Ok(()));
    assert_eq!(link.accept_list_clear(), Err(Error::Disallowed));
    link.stop_advertising();
    assert_eq!(link.accept_list_clear(), Ok(()));
}

#[test]
fn the_host_decides_on_parameter_requests_only_when_it_asks_to() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    assert!(!shared.host_decides_parameters());
    link.set_host_decides_params(true);
    assert!(shared.host_decides_parameters());
    let epoch = connect(&shared);
    assert_eq!(link.reply_params(epoch, Ok(ParamRange::new(6, 12, 0, 100))), Err(Error::Disallowed));
    shared.ask_parameters();
    assert_eq!(link.reply_params(epoch, Ok(ParamRange::new(12, 6, 0, 100))), Err(Error::Invalid));
    assert_eq!(link.reply_params(epoch, Err(0x3B)), Ok(()));
    assert_eq!(shared.take_parameter_reply(), Some(Err(0x3B)));
}

#[test]
fn next_returns_events_before_fragments_and_marks_the_fragment_read() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert!(shared.push_acl_in(Llid::Start, &[1], false));
    assert!(shared.try_push_event(Event::Connected(epoch)));
    assert!(matches!(run(link.next()), Rx::Event(Event::Connected(e)) if e == epoch));
    let mut drained = pin!(shared.acl_in_drained());
    let mut context = Context::from_waker(Waker::noop());
    assert!(drained.as_mut().poll(&mut context).is_pending());
    assert!(matches!(run(link.next()), Rx::Acl(acl) if acl.payload() == [1] && !acl.encrypted()));
    assert!(drained.as_mut().poll(&mut context).is_ready());
}

#[cfg(feature = "event-timing")]
#[test]
fn the_next_connection_event_is_known_only_for_its_link_once_planned() {
    let shared = Shared::new();
    let link = Link::new(&shared);
    let epoch = connect(&shared);
    assert_eq!(link.next_connection_event(epoch), None);
    let at = Instant::from_secs(10);
    // The radio starts 5 ms after `at`; data is due 331 us before it.
    shared.set_next_event(at, 5000, 331, 15_000);
    let next = link.next_connection_event(epoch).unwrap();
    assert_eq!(next.start, at + Duration::from_micros(5000));
    assert_eq!(next.queue_by, next.start - Duration::from_micros(331));
    assert_eq!(next.interval, Duration::from_micros(15_000));
    // Another link's epoch learns nothing.
    assert_eq!(link.next_connection_event(Epoch(epoch.0.wrapping_add(1))), None);
    // Nor does anyone once the link ended, or the next link before its first
    // event is planned.
    shared.set_connected(false);
    assert_eq!(link.next_connection_event(epoch), None);
    let next_link = connect(&shared);
    assert_eq!(link.next_connection_event(next_link), None);
}

#[cfg(feature = "event-timing")]
#[test]
fn a_planned_event_converts_to_the_host_time_both_ways() {
    let at = Instant::from_secs(10);
    let ahead = Planned { ahead: 2000, at, epoch: 0, interval: 7500, lead: 2000 }.resolve();
    assert_eq!(ahead.start, at + Duration::from_micros(2000));
    assert_eq!(ahead.queue_by, at);
    // An event planned late: its start passed already.
    let behind = Planned { ahead: 0_u32.wrapping_sub(2000), at, epoch: 0, interval: 7500, lead: 300 }.resolve();
    assert_eq!(behind.start, at - Duration::from_micros(2000));
    assert!(behind.queue_by < behind.start);
    // Near the start of the host's time the times stop at it instead of
    // wrapping.
    let early = Planned {
        ahead:    0_u32.wrapping_sub(2000),
        at:       Instant::from_ticks(0),
        epoch:    0,
        interval: 7500,
        lead:     300,
    };
    assert_eq!(early.resolve().start, Instant::from_ticks(0));
    assert_eq!(early.resolve().queue_by, Instant::from_ticks(0));
}
