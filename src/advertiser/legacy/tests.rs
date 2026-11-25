//! Tests of legacy advertising: the target of directed advertising on air
//! and the limits of the advertising and scan response data.

use super::*;
#[cfg(feature = "directed-advertising")]
use crate::advertiser::tests::{CENTRAL, LOCAL_IRK, SAMPLE_IRK, SAMPLE_PRAND, SAMPLE_RPA, directed, resolves, rpa};

#[cfg(feature = "directed-advertising")]
#[test]
fn directed_advertising_targets_a_private_address_of_the_central_s_key() {
    let mut settings = directed();
    settings.kind = Kind::DirectedHighDuty;
    // It puts a resolvable private address made with the central's key on
    // air: the sample's for the sample's prand.
    settings.target = rpa(SAMPLE_IRK, SAMPLE_PRAND);
    let (primary, _) = pdus(&settings);
    let bytes = primary.as_bytes();
    // ADV_DIRECT_IND with ChSel, TxAdd and RxAdd: both addresses random.
    assert_eq!(bytes.get(..2), Some(&[0x01 | 0x20 | 0x40 | 0x80, 12][..]));
    assert_eq!(bytes.get(2..8), Some(&settings.own.address[..]));
    assert_eq!(bytes.get(8..14), Some(&SAMPLE_RPA[..]));
    assert!(resolves(SAMPLE_IRK, assert_some!(bytes.get(8..14).and_then(|target| target.try_into().ok()))));
    // The central's identity is not on air, nor our address made with its
    // key.
    assert!(!resolves(LOCAL_IRK, assert_some!(bytes.get(8..14).and_then(|target| target.try_into().ok()))));
    assert_ne!(bytes.get(8..14), Some(&CENTRAL.address[..]));
}

#[test]
fn the_data_takes_31_octets_each_and_a_longer_one_changes_neither() {
    let mut settings = Settings::new();
    let full = [0xA5; DATA_MAX];
    let scan_full = [0x5A; SCAN_DATA_MAX];
    assert!(settings.set_data(&full, &scan_full));
    assert_eq!((settings.data, settings.len), (full, 31));
    assert_eq!((settings.scan_data, settings.scan_len), (scan_full, 31));
    // Either too long refuses both, the other one fitting or not.
    for (adv, scan) in [
        (&[1; DATA_MAX + 1][..], &[2; 3][..]),
        (&[1; 3][..], &[2; SCAN_DATA_MAX + 1][..]),
        (&[1; 32][..], &[2; 32][..]),
    ] {
        assert!(!settings.set_data(adv, scan));
        assert_eq!((settings.data, settings.len), (full, 31));
        assert_eq!((settings.scan_data, settings.scan_len), (scan_full, 31));
    }
    // Shorter data replaces both, with zeros after it.
    assert!(settings.set_data(&[2, 1, 6], &[]));
    assert_eq!((&settings.data[..4], settings.len), (&[2, 1, 6, 0][..], 3));
    assert_eq!((settings.scan_data, settings.scan_len), ([0; SCAN_DATA_MAX], 0));
}
