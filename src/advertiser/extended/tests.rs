//! Tests of extended advertising: the timing plan, the data limits, the
//! renewal of the advertising set and the PDUs of the settings.

use super::*;
#[cfg(feature = "directed-advertising")]
use crate::advertiser::tests::{SAMPLE_IRK, SAMPLE_PRAND, SAMPLE_RPA, rpa};
use crate::{
    advertiser::tests::{CENTRAL, directed},
    chip::ADV_MAXLEN,
    pdu::Adi,
};

/// Our address: a static random one.
const OWN: Peer = Peer::new([1, 2, 3, 4, 5, 0xC6], true);

/// Undirected advertising from [`OWN`] with the data `[2, 1, 6]` and the
/// ADI's DID 0x0ABC.
fn undirected() -> Settings {
    let mut settings = Settings::new();
    settings.own = OWN;
    assert!(settings.set_data(&[2, 1, 6], &[]));
    settings.adi = Adi::new(0, 0x0ABC);
    settings
}

#[test]
fn the_primaries_point_to_the_same_auxiliary_packet_12_us_into_its_unit() {
    // The design's offsets, in units of 30 us, for three, two and one
    // channels.
    let expected: [&[u16]; 3] =
        if cfg!(feature = "nrf51") { [&[15], &[28, 15], &[41, 28, 15]] } else { [&[15], &[24, 15], &[33, 24, 15]] };
    for (channels, offsets) in (1..=3).zip(expected) {
        for (index, &offset) in offsets.iter().enumerate() {
            assert_eq!(aux_offset(channels, index), offset);
            // The auxiliary packet starts 12 us into the unit, seen from
            // every primary; on every secondary PHY, whose ramp-up only
            // moves its TXEN.
            assert_eq!(aux_start_us(channels, index) - u32::from(offset) * UNIT_US, 12);
            for phy in SECONDARY_PHYS {
                let txen = aux_start_us(channels, index) - tx_ready_us(phy);
                assert_eq!(txen + tx_ready_us(phy) - u32::from(offset) * UNIT_US, aux_residue_us());
            }
        }
    }
    // The first primary to the auxiliary packet with three channels: 1002 us
    // on the nRF52 chips, 1242 us on the nRF51.
    assert_eq!(aux_start_us(3, 0), if cfg!(feature = "nrf51") { 1242 } else { 1002 });
}

#[test]
fn the_auxiliary_packet_keeps_the_minimum_aux_frame_space() {
    // An ADV_EXT_IND takes 136 us on LE 1M.
    assert_eq!(PRIMARY_US, 136);
    // The Aux Offset of the last primary covers its packet and T_MAFS
    // (Core, Vol 6, Part B, 2.3.4.5): 15 units, 450 us >= 436 us; and the
    // packet itself starts 326 us after the primary's end.
    for channels in 1..=3 {
        let last = channels - 1;
        assert!(u32::from(aux_offset(channels, last)) * UNIT_US >= PRIMARY_US + T_MAFS_US);
        assert_eq!(aux_start_us(channels, last) - PRIMARY_US, 326);
    }
    assert_eq!(AUX_GAP_US - PRIMARY_US, 326);
    // Primaries at most 10 ms apart, all within 2 x the spacing.
    assert!(aux_start_us(3, 0) - aux_start_us(3, 2) <= 10_000);
}

#[test]
fn airtimes_and_the_longest_event_fit_the_shortest_interval() {
    // Reconnection data (13 octets) in an undirected AUX_ADV_IND: 23 octets
    // of payload; the longest one the chip sends: 255 octets on the
    // nRF52 chips, 252 on the nRF51.
    assert_eq!(airtime_us(Phy::M1, AUX_HEADER_LEN + 13), 264);
    assert_eq!(airtime_us(Phy::M2, AUX_HEADER_LEN + 13), 136);
    assert_eq!(airtime_us(Phy::M1, 255), 2120);
    assert_eq!(airtime_us(Phy::M2, 255), 1064);
    assert_eq!(airtime_us(Phy::M1, AUX_PAYLOAD_MAX), if cfg!(feature = "nrf51") { 2096 } else { 2120 });
    // AUX_CONNECT_REQ and AUX_CONNECT_RSP.
    assert_eq!(airtime_us(Phy::M1, 34), 352);
    assert_eq!(airtime_us(Phy::M1, 14), 192);
    for phy in SECONDARY_PHYS {
        assert!(event_us(3, phy, AUX_PAYLOAD_MAX) < ADV_INTERVAL_MIN_US);
    }
    // Reconnection data on LE 1M: 60 + 41 + 540 + 462 + 264 + 150 + 352 +
    // 150 + 192 on the nRF52832; the nRF52833's LE 1M ramp-up rounds to
    // 40 us, one less.
    if cfg!(feature = "nrf52832") {
        assert_eq!(event_us(3, Phy::M1, AUX_HEADER_LEN + 13), 2211);
    }
    if cfg!(feature = "nrf52833") {
        assert_eq!(event_us(3, Phy::M1, AUX_HEADER_LEN + 13), 2210);
    }
    // The CPU gets time between two packets: 87 us on the nRF52832, 88 on
    // the nRF52833, 108 on the nRF51.
    let between = PRIMARY_SPACING_US - PRIMARY_US - DISABLE_US - tx_ready_us(Phy::M1);
    let expected = if cfg!(feature = "nrf51") {
        108
    } else if cfg!(feature = "nrf52833") {
        88
    } else {
        87
    };
    assert_eq!(between, expected);
}

#[test]
fn the_enabled_primary_channels_are_listed_in_order() {
    assert_eq!(primary_channels(0x07), ([37, 38, 39], 3));
    assert_eq!(primary_channels(0x05), ([37, 39, 0], 2));
    assert_eq!(primary_channels(0x02), ([38, 0, 0], 1));
    assert_eq!(primary_channels(0x00), ([0, 0, 0], 0));
}

#[test]
fn the_auxiliary_channel_covers_all_37_secondary_channels() {
    let mut seen = [false; 37];
    for counter in 0..=u16::MAX {
        let channel = aux_channel(0x1234, counter);
        *assert_some!(seen.get_mut(usize::from(channel))) = true;
    }
    assert!(seen.iter().all(|&visited| visited));
    // The same identifier and counter give the same channel; another
    // identifier a sequence of its own.
    assert_eq!(aux_channel(0x1234, 7), aux_channel(0x1234, 7));
    assert!((0..16).any(|counter| aux_channel(0x1234, counter) != aux_channel(0x4321, counter)));
}

#[test]
fn the_data_takes_what_the_chip_sends_and_no_scan_response() {
    // The nRF52 chips send the largest payload, 255 octets; the nRF51 252, as
    // its radio takes at most 254 octets of a packet from RAM.
    let (undirected, directed) = if cfg!(feature = "nrf51") { (242, 236) } else { (245, 239) };
    assert_eq!(AUX_PAYLOAD_MAX, if cfg!(feature = "nrf51") { 252 } else { 255 });
    assert_eq!((DATA_MAX, DIRECTED_DATA_MAX, SCAN_DATA_MAX), (undirected, directed, 0));
    assert_eq!(Kind::ConnectableUndirected.data_max(), undirected);
    assert_eq!(Kind::DirectedLowDuty.data_max(), directed);
    assert!(!Kind::ConnectableUndirected.is_high_duty() && !Kind::DirectedLowDuty.is_high_duty());
    assert!(Kind::DirectedLowDuty.is_directed() && Kind::DirectedLowDuty.is_connectable());
    let mut settings = Settings::new();
    let full = [0xA5; DATA_MAX];
    assert!(settings.set_data(&full, &[]));
    assert_eq!((settings.data, settings.len), (full, assert_ok!(undirected.try_into())));
    settings.stale = false;
    // Longer data, or any scan response, changes nothing.
    for (adv, scan) in [(&[1; DATA_MAX + 1][..], &[][..]), (&[1; 3][..], &[2][..])] {
        assert!(!settings.set_data(adv, scan));
        assert_eq!((settings.data, settings.len), (full, assert_ok!(undirected.try_into())));
        assert!(!settings.stale);
    }
    // Shorter data replaces it, with zeros after it.
    assert!(settings.set_data(&[2, 1, 6], &[]));
    assert_eq!((&settings.data[..4], settings.len), (&[2, 1, 6, 0][..], 3));
}

#[test]
fn new_data_or_a_new_address_waits_for_a_new_random_adi_and_channel_identifier() {
    let mut settings = Settings::new();
    // A new advertising set is renewed before it first goes out.
    assert!(settings.stale);
    settings.renew([0xBC, 0x0A, 0x34, 0x12]);
    assert!(!settings.stale);
    assert_eq!((settings.adi.did(), settings.adi.sid(), settings.aux_id), (0x0ABC, 0, 0x1234));
    // Each data change, even to the same data, asks for a new DID.
    assert!(settings.set_data(&[2, 1, 6], &[]));
    assert!(settings.stale);
    // The DID comes from the random octets, but never stays the same.
    settings.renew([0xBC, 0x0A, 0x78, 0x56]);
    assert_eq!((settings.adi.did(), settings.aux_id), (0x0ABD, 0x5678));
    settings.renew([0x21, 0xF3, 0x00, 0x00]);
    assert_eq!(settings.adi.did(), 0x0321);
    // An event takes DID 0x0321; the data changes twice before the next
    // one. The second renewal avoids the DID the first gave, which never
    // went on air, and the one scanners last received.
    settings.last_used = settings.adi;
    settings.renew([0x45, 0x04, 0x00, 0x00]);
    assert_eq!(settings.adi.did(), 0x0445);
    settings.renew([0x21, 0x03, 0x00, 0x00]);
    assert_eq!(settings.adi.did(), 0x0322);
    // Past both, when the next value is the current one.
    settings.renew([0x21, 0x03, 0x00, 0x00]);
    assert_eq!(settings.adi.did(), 0x0323);
    // Our own address: only a new one asks for a renewal.
    settings.set_own(settings.own);
    assert!(!settings.stale);
    settings.set_own(OWN);
    assert!(settings.stale && settings.own == OWN);
}

#[test]
fn the_settings_give_the_primary_and_the_auxiliary_pdu() {
    let settings = undirected();
    // The design's sample: ADI 0x0ABC, channel 36, 33 units, LE 1M.
    let primary = primary(&settings, AuxPtr::new(36, 33, Phy::M1));
    assert_eq!(primary.as_bytes(), [0x07, 0x07, 0x46, 0x18, 0xBC, 0x0A, 0x24, 0x21, 0x00]);
    let auxiliary = auxiliary(&settings);
    assert_eq!(auxiliary.as_bytes(), [0x47, 13, 0x49, 0x09, 1, 2, 3, 4, 5, 0xC6, 0xBC, 0x0A, 2, 1, 6]);
}

/// `settings` with the central's identity as the target on air, which
/// settings only hold with the feature `directed-advertising`.
#[cfg(feature = "directed-advertising")]
const fn to_central(settings: &Settings) -> Settings { Settings { target: CENTRAL, ..*settings } }

/// `settings`, whose target on air is the peer's identity without the
/// feature `directed-advertising`.
#[cfg(not(feature = "directed-advertising"))]
const fn to_central(settings: &Settings) -> Settings { *settings }

#[test]
fn directed_advertising_targets_the_central_in_the_auxiliary_pdu() {
    let mut base = directed();
    assert!(base.set_data(&[2, 1, 4], &[]));
    base.adi = Adi::new(0, 0x0ABC);
    // Without a key on air, or without the feature, the target is the
    // central's identity, public: no RxAdd.
    let mut settings = to_central(&base);
    let pdu = auxiliary(&settings);
    let bytes = pdu.as_bytes();
    assert_eq!(bytes.get(..4), Some(&[0x47, 19, 0x4F, 0x0B][..]));
    assert_eq!(bytes.get(4..10), Some(&settings.own.address[..]));
    assert_eq!(bytes.get(10..16), Some(&CENTRAL.address[..]));
    assert_eq!(bytes.get(16..), Some(&[0xBC, 0x0A, 2, 1, 4][..]));
    // With the feature and the central's key, a resolvable private address
    // made with it: RxAdd.
    #[cfg(feature = "directed-advertising")]
    let to_private = auxiliary(&Settings { target: rpa(SAMPLE_IRK, SAMPLE_PRAND), ..settings });
    #[cfg(feature = "directed-advertising")]
    assert_eq!(to_private.as_bytes().get(..4), Some(&[0xC7, 19, 0x4F, 0x0B][..]));
    #[cfg(feature = "directed-advertising")]
    assert_eq!(to_private.as_bytes().get(10..16), Some(&SAMPLE_RPA[..]));
    // Data that only fits undirected advertising is cut off; the link layer
    // refuses it before (`Kind::data_max`).
    assert!(settings.set_data(&[7; DATA_MAX], &[]));
    assert_eq!(auxiliary(&settings).as_bytes().len(), 2 + AUX_PAYLOAD_MAX);
    assert_eq!(auxiliary(&settings).as_bytes().get(1), Some(&if cfg!(feature = "nrf51") { 252 } else { 255 }));
}

#[test]
fn an_aux_connect_req_is_accepted_as_the_filter_policy_says() {
    /// An `AUX_CONNECT_REQ` from `central` to `advertiser`, with valid
    /// parameters and `ChSel` 0, as it is reserved.
    fn request(central: Peer, advertiser: Peer) -> [u8; 36] {
        let mut bytes = [0; 36];
        bytes[0] = 0x05 | if central.random { 0x40 } else { 0 } | if advertiser.random { 0x80 } else { 0 };
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
    // Undirected without a filter: anyone, with channel selection
    // algorithm 2.
    let settings = undirected();
    let accepted = assert_some!(accepted_request(&settings, &request(CENTRAL, OWN)));
    assert!(accepted.csa2 && accepted.central() == CENTRAL);
    // Not to another advertiser.
    assert!(accepted_request(&settings, &request(CENTRAL, Peer::new(OWN.address, false))).is_none());
    // With the filter accept list: only the listed central.
    let mut filtered = settings;
    assert!(filtered.filter.add(CENTRAL));
    filtered.filter_policy = 0x02;
    assert!(accepted_request(&filtered, &request(CENTRAL, OWN)).is_some());
    assert!(accepted_request(&filtered, &request(Peer::new([9; 6], false), OWN)).is_none());
    // Directed: the central's identity, not another public address.
    let directed = directed();
    assert!(accepted_request(&directed, &request(CENTRAL, directed.own)).is_some());
    assert!(accepted_request(&directed, &request(Peer::new([9; 6], false), directed.own)).is_none());
}

#[test]
fn an_event_s_pdus_point_to_the_auxiliary_packet_on_its_channel_and_phy() {
    let mut settings = undirected();
    settings.channel_map = 0x05;
    settings.aux_id = 0x1234;
    settings.secondary_phy = Phy::M2;
    let pdus = Pdus::new(&settings, 7);
    // Channels 37 and 39; the secondary channel of event 7.
    assert_eq!((pdus.channels, pdus.count), ([37, 39, 0], 2));
    assert_eq!(pdus.aux_channel, aux_channel(0x1234, 7));
    // LE 2M where the chip has it; the nRF51 stays on LE 1M whatever the
    // settings hold.
    let phy = if cfg!(feature = "nrf51") { Phy::M1 } else { Phy::M2 };
    assert!(pdus.phy == phy && secondary_phy(&settings) == phy);
    // Each primary points with its own offset to the one auxiliary packet:
    // channel, offset and PHY in its AuxPtr.
    for (index, pdu) in pdus.primaries.iter().take(2).enumerate() {
        let expected = primary(&settings, AuxPtr::new(pdus.aux_channel, aux_offset(2, index), phy));
        assert_eq!(pdu.as_bytes(), expected.as_bytes());
        let Some(&[channel, offset0, offset1]) = ({
            let value = pdu.as_bytes().get(6..9);
            assert!(matches!(value, Some(&[_, _, _])), "an AuxPtr");
            value
        }) else {
            return;
        };
        assert_eq!(channel, pdus.aux_channel);
        let field = u16::from_le_bytes([offset0, offset1]);
        assert_eq!(field & 0x1FFF, aux_offset(2, index));
        assert_eq!(field >> 13_i32, u16::from(phy == Phy::M2));
    }
    // The auxiliary packet in its buffer, which also takes the request.
    let auxiliary = auxiliary(&settings);
    assert_eq!(pdus.auxiliary.0.get(..auxiliary.as_bytes().len()), Some(auxiliary.as_bytes()));
    assert_eq!(pdus.auxiliary.0.len(), 2 + usize::from(ADV_MAXLEN));
    // Another event, another channel in time: CSA #2 over the 37 channels.
    assert!((0..8).any(|counter| Pdus::new(&settings, counter).aux_channel != pdus.aux_channel));
}

#[test]
fn the_event_plan_keeps_its_times_and_budgets_on_every_secondary_phy() {
    // The first primary on air at 1000 us of the clock.
    let first = 1000;
    for phy in SECONDARY_PHYS {
        for channels in 1..=3 {
            // The primaries are a spacing apart on air, each TXEN its LE 1M
            // ramp-up before.
            for index in 0..channels {
                let on_air = primary_txen(At(first), Phy::M1, index).0 + tx_ready_us(Phy::M1);
                assert_eq!(on_air, first + assert_ok!(u32::try_from(index)) * PRIMARY_SPACING_US);
                // Seen from each primary, the auxiliary packet starts 12 us
                // into the unit its Aux Offset names, on either PHY.
                let aux_on_air = aux_txen(At(first), Phy::M1, channels, phy).0 + tx_ready_us(phy);
                assert_eq!(aux_on_air - on_air - u32::from(aux_offset(channels, index)) * UNIT_US, 12);
            }
            // The CPU's time from the last primary's DISABLED to the
            // auxiliary packet's TXEN.
            let last_end = primary_txen(At(first), Phy::M1, channels - 1).0 + tx_ready_us(Phy::M1) + PRIMARY_US;
            let budget = aux_txen(At(first), Phy::M1, channels, phy).0 - last_end - DISABLE_US;
            assert!(budget >= CPU_SLACK_MIN_US);
            // The nRF52833's LE 1M ramp-up rounds to 40 us like its LE 2M
            // one, so its two budgets are the same.
            assert_eq!(budget, match (cfg!(feature = "nrf51"), cfg!(feature = "nrf52833"), phy) {
                (true, ..) => 180,
                (false, false, Phy::M1) => 279,
                (false, true, Phy::M1) | (false, _, Phy::M2) => 280,
                // Not among the secondary PHYs of LE 1M primaries this loop
                // takes; `the_event_plan_on_le_coded_keeps_its_times` checks
                // LE Coded.
                #[cfg(feature = "coded-phy")]
                (_, _, Phy::CodedS8 | Phy::CodedS2) => 0,
            });
        }
        // The request's access address comes before the listen ends: T_IFS
        // and the preamble and access address on the PHY.
        let address = T_IFS_US + phy.address_offset_us();
        assert_eq!(address, if phy == Phy::M2 { 174 } else { 190 });
        assert!(address < LISTEN_US);
        // The answer after a request: 2.5 ms to the transmit window, on
        // the secondary channel's PHY.
        let setup = Setup::aux(phy);
        assert!(setup.phy == phy && setup.window_delay_us == 2500);
    }
    // Between two primaries, on LE 1M alone.
    let between = PRIMARY_SPACING_US - PRIMARY_US - DISABLE_US - tx_ready_us(Phy::M1);
    assert!(between >= CPU_SLACK_MIN_US);
    // A whole event with the reconnection data, three channels, request and
    // answer: on the nRF52832 2211 us on LE 1M and on LE 2M 60 + 41 + 540 +
    // 462 + 136 + 150 + 180 + 150 + 100 = 1819 us, on the nRF52833 1 us
    // less on either, as the LE 1M ramp-up of its primaries rounds to 40 us;
    // on the nRF51 its longer spacing and ramp-up.
    let reconnect = AUX_HEADER_LEN + 13;
    if cfg!(feature = "nrf51") {
        assert_eq!(event_us(3, Phy::M1, reconnect), 120 + 140 + 780 + 462 + 264 + 150 + 352 + 150 + 192);
    } else {
        assert_eq!(event_us(3, Phy::M1, reconnect), if cfg!(feature = "nrf52833") { 2210 } else { 2211 });
        assert_eq!(event_us(3, Phy::M2, reconnect), if cfg!(feature = "nrf52833") { 1818 } else { 1819 });
    }
    // The longest, 20 ms at the shortest interval, on every PHY.
    for phy in SECONDARY_PHYS {
        assert!(event_us(3, phy, AUX_PAYLOAD_MAX) < ADV_INTERVAL_MIN_US);
    }
}

#[test]
fn a_connection_request_is_decided_before_its_answer_ends() {
    // One interframe space and the 14-octet AUX_CONNECT_RSP: 192 us on
    // LE 1M, 100 us on LE 2M.
    assert_eq!(decision_budget_us(Phy::M1), 342);
    assert_eq!(decision_budget_us(Phy::M2), 250);
    // Less the receive chain delay before the END event and the TIMER1
    // turnaround, the answer ends about 245 us after the END on LE 2M, and
    // 333 us on LE 1M on the nRF52832, 332 us on the nRF52833.
    #[cfg(feature = "_nrf52")]
    for (phy, from_end) in [(Phy::M1, if cfg!(feature = "nrf52833") { 332 } else { 333 }), (Phy::M2, 245)] {
        let ends = phy.response_offset_us(phy) + tx_ready_us(phy) + airtime_us(phy, AUX_CONNECT_RSP_LEN);
        assert_eq!(ends, from_end);
        assert!(decision_budget_us(phy) - ends <= 10);
    }
}

#[test]
fn no_channel_no_primary() {
    // Not a valid map (the link layer refuses it), but no offset is
    // computed for a channel that is not there.
    let mut settings = undirected();
    settings.channel_map = 0;
    let pdus = Pdus::new(&settings, 0);
    assert_eq!(pdus.count, 0);
}

#[test]
fn nothing_is_late_before_the_first_event() {
    let mut counters = Counters::new();
    assert_eq!((late_starts(), late_connect_decisions()), (0, 0));
    counters.log();
    assert!(counters.sent.is_none() && counters.shown.is_none());
}

/// The timing functions without a primary PHY are those of primaries on LE
/// 1M.
#[test]
fn the_timing_without_a_primary_phy_is_that_of_le_1m() {
    for channels in 1..=3 {
        for index in 0..channels {
            assert_eq!(aux_offset(channels, index), aux_offset_on(Phy::M1, channels, index));
            assert_eq!(aux_start_us(channels, index), aux_start_us_on(Phy::M1, channels, index));
        }
        for phy in SECONDARY_PHYS {
            assert_eq!(event_us(channels, phy, AUX_PAYLOAD_MAX), event_us_on(channels, Phy::M1, phy, AUX_PAYLOAD_MAX));
        }
    }
}

/// The plan on LE Coded primaries: their airtime, 1168 us with S=8 and
/// 574 us with S=2, the spacing in whole units with the CPU's time after
/// each, and the auxiliary packet `T_MAFS` after the last, 12 us into its
/// unit from every primary.
#[cfg(feature = "coded-phy")]
#[test]
fn the_event_plan_on_le_coded_keeps_its_times() {
    assert_eq!([primary_us(Phy::CodedS8), primary_us(Phy::CodedS2)], [1168, 574]);
    assert_eq!([primary_spacing_us(Phy::CodedS8), primary_spacing_us(Phy::CodedS2)], [1290, 690]);
    assert_eq!([aux_gap_us(Phy::CodedS8), aux_gap_us(Phy::CodedS2)], [1482, 912]);
    assert_eq!([primary_spacing_us(Phy::M1), aux_gap_us(Phy::M1)], [PRIMARY_SPACING_US, AUX_GAP_US]);
    let first: u32 = 1000;
    for primary in [Phy::CodedS8, Phy::CodedS2] {
        for secondary in [Phy::M1, Phy::M2, Phy::CodedS8, Phy::CodedS2] {
            for channels in 1..=3 {
                for index in 0..channels {
                    let on_air = primary_txen(At(first), primary, index).0 + tx_ready_us(primary);
                    let spacings = assert_ok!(u32::try_from(index));
                    assert_eq!(on_air, first + spacings * primary_spacing_us(primary));
                    let aux_on_air = aux_txen(At(first), primary, channels, secondary).0 + tx_ready_us(secondary);
                    let offset = u32::from(aux_offset_on(primary, channels, index)) * UNIT_US;
                    assert_eq!(aux_on_air - on_air - offset, 12);
                    assert!(offset >= primary_us(primary) + T_MAFS_US);
                }
            }
        }
    }
}

/// An event on LE Coded with S=8 on both channels and 245 octets of data,
/// 255 octets of payload, takes 26016 us, more than the shortest interval,
/// which grows to it, rounded up to 26250 us, 42 units of 0.625 ms; on LE
/// 1M the interval stays.
#[cfg(feature = "coded-phy")]
#[test]
fn an_event_on_le_coded_sets_the_least_interval() {
    let longest = 60 + 42 + 2 * 1290 + 1482 + 17_040 + 150 + 2896 + 150 + 1616;
    assert_eq!(event_us_on(3, Phy::CodedS8, Phy::CodedS8, AUX_PAYLOAD_MAX), longest);
    assert_eq!(longest, 26_016);
    let mut settings = undirected();
    settings.interval = 20_000;
    assert!(settings.set_data(&[0; DATA_MAX], &[]));
    fit_interval(&mut settings);
    assert_eq!(settings.interval, 20_000);
    settings.primary_phy = Phy::CodedS8;
    settings.secondary_phy = Phy::CodedS8;
    fit_interval(&mut settings);
    assert_eq!(event_us_on(3, Phy::CodedS8, Phy::CodedS8, AUX_HEADER_LEN + DATA_MAX), longest);
    assert_eq!(settings.interval, 26_250);
    assert_eq!(settings.interval.strict_rem(625), 0);
    // A longer interval stays.
    settings.interval = 100_000;
    fit_interval(&mut settings);
    assert_eq!(settings.interval, 100_000);
}

/// With S=2 on the secondary channel the central may still send its
/// `AUX_CONNECT_REQ` with S=8, 2896 us against 1006 us with S=2, which the
/// event counts; the `AUX_ADV_IND` and the `AUX_CONNECT_RSP` go out with
/// S=2.
#[cfg(feature = "coded-phy")]
#[test]
fn an_event_on_le_coded_with_s2_counts_the_request_with_s8() {
    assert_eq!(airtime_us(Phy::CodedS8, usize::from(CONNECT_IND_LEN)), 2896);
    assert_eq!(airtime_us(Phy::CodedS2, usize::from(CONNECT_IND_LEN)), 1006);
    assert_eq!(airtime_us(Phy::CodedS2, AUX_PAYLOAD_MAX), 4542);
    assert_eq!(airtime_us(Phy::CodedS2, AUX_CONNECT_RSP_LEN), 686);
    let longest = 60 + 42 + 2 * 1290 + 1482 + 4542 + 150 + 2896 + 150 + 686;
    assert_eq!(event_us_on(3, Phy::CodedS8, Phy::CodedS2, AUX_PAYLOAD_MAX), longest);
    assert_eq!(longest, 12_588);
}

/// The PDUs of advertising on LE Coded: each primary's `AuxPtr` names LE
/// Coded, PHY 2, with the offset of the coded plan; a request is listened
/// for until its access address event on LE Coded may come; its answer
/// leaves the CPU the coded budget; and the link's transmit window comes
/// 3.75 ms after the request.
#[cfg(feature = "coded-phy")]
#[test]
fn an_event_on_le_coded_points_to_the_auxiliary_packet_on_le_coded() {
    let mut settings = undirected();
    settings.primary_phy = Phy::CodedS8;
    settings.secondary_phy = Phy::CodedS2;
    let pdus = Pdus::new(&settings, 3);
    assert!(pdus.phy == Phy::CodedS2 && primary_phy(&settings) == Phy::CodedS8);
    for (index, pdu) in pdus.primaries.iter().take(3).enumerate() {
        let offset = aux_offset_on(Phy::CodedS8, 3, index);
        let expected = primary(&settings, AuxPtr::new(pdus.aux_channel, offset, Phy::CodedS2));
        assert_eq!(pdu.as_bytes(), expected.as_bytes());
        let [offset0, offset1] = (offset | (2 << 13)).to_le_bytes();
        assert_eq!(pdu.as_bytes().get(6..9), Some([pdus.aux_channel, offset0, offset1].as_slice()));
    }
    assert_eq!(AuxPtr::new(5, 100, Phy::CodedS8).to_bytes(), [5, 100, 0x40]);
    for phy in [Phy::CodedS8, Phy::CodedS2] {
        assert_eq!(listen_us(phy), 636);
        assert!(T_IFS_US + phy.address_offset_us() < listen_us(phy));
        assert_eq!(Setup::aux(phy).window_delay_us, 3750);
        assert!(Setup::aux(phy).phy == phy);
    }
    assert_eq!([listen_us(Phy::M1), Setup::aux(Phy::M2).window_delay_us], [LISTEN_US, 2500]);
    // The answer's end, one interframe space after the request, bounds its
    // check: 150 us and an AUX_CONNECT_RSP of 1616 us with S=8, 686 us
    // with S=2.
    assert_eq!([decision_budget_us(Phy::CodedS8), decision_budget_us(Phy::CodedS2)], [1766, 836]);
}
