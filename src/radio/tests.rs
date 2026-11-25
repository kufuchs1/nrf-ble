//! The PHYs' values in the link layer's fields and their times on air.

use super::Phy;
#[cfg(feature = "coded-phy")]
use super::{CODED_ADDRESS_US, Coding};

/// The vectors of the time on air: an empty PDU, and 27 octets of payload
/// with a MIC, the default data length's 328 us on LE 1M.
#[test]
fn the_time_on_air_of_le_1m_and_le_2m_follows_the_octets() {
    assert_eq!(Phy::M1.pdu_us(2), 80);
    assert_eq!(Phy::M1.pdu_us(2 + 27 + 4), 328);
    assert_eq!(Phy::M2.pdu_us(2), 44);
    assert_eq!(Phy::M2.pdu_us(2 + 27 + 4), 168);
    // 251 octets and a MIC: 2120 us on LE 1M, the longest time of LE 1M.
    assert_eq!(Phy::M1.pdu_us(2 + 251 + 4), 2120);
}

#[test]
fn the_link_layer_values_of_le_1m_and_le_2m() {
    assert!(Phy::from_bits(1) == Some(Phy::M1));
    assert!(Phy::from_power(1) == Some(Phy::M1));
    assert_eq!([Phy::M1.bit(), Phy::M1.hci(), Phy::M1.power_bit()], [1, 1, 1]);
    assert!(!Phy::M1.is_coded());
    // Two bits at once, no bit, and the reserved bits name no PHY.
    for bits in [0, 3, 8, 0x80] {
        assert!(Phy::from_bits(bits).is_none());
    }
    if cfg!(feature = "nrf51") {
        assert!(Phy::from_bits(2).is_none());
    } else {
        assert!(Phy::from_bits(2) == Some(Phy::M2));
        assert_eq!([Phy::M2.bit(), Phy::M2.hci(), Phy::M2.power_bit()], [2, 2, 2]);
    }
}

#[cfg(not(feature = "coded-phy"))]
#[test]
fn without_le_coded_its_bit_and_power_values_name_no_phy() {
    assert!(Phy::from_bits(4).is_none());
    assert!(Phy::from_power(3).is_none());
    assert!(Phy::from_power(4).is_none());
}

/// The vectors of Zephyr's `pdu.h` and of the specification's data length
/// limits: an empty PDU takes 720 us with S=8, 27 octets with a MIC
/// `PDU_DC_PAYLOAD_TIME_MIN_CODED`, 2704 us, and 958 us with S=2, and 251
/// octets with a MIC `PDU_DC_PAYLOAD_TIME_MAX_CODED`, 17040 us.
#[cfg(feature = "coded-phy")]
#[test]
fn the_time_on_air_of_le_coded_follows_the_coding() {
    assert_eq!(CODED_ADDRESS_US, 80 + 256 + 16 + 24);
    assert_eq!(Phy::CodedS8.pdu_us(2), 720);
    assert_eq!(Phy::CodedS2.pdu_us(2), 462);
    assert_eq!(Phy::CodedS8.pdu_us(2 + 27 + 4), 2704);
    assert_eq!(Phy::CodedS2.pdu_us(2 + 27 + 4), 958);
    assert_eq!(Phy::CodedS8.pdu_us(2 + 251 + 4), 17_040);
    assert_eq!(Phy::CodedS2.pdu_us(2 + 251 + 4), 4542);
    for phy in [Phy::CodedS8, Phy::CodedS2] {
        assert_eq!(phy.address_offset_us(), 376);
    }
}

/// LE Coded is bit 2 of a PHY bit field and HCI's PHY 3, and its codings
/// are the power control's PHYs 3 and 4 and bits 2 and 3 of its reports
/// (Core, Vol 6, Part B, 2.4.2.31 and 2.4.2.33).
#[cfg(feature = "coded-phy")]
#[test]
fn the_link_layer_values_of_le_coded() {
    assert!(Phy::from_bits(4) == Some(Phy::CodedS8));
    assert!(Phy::from_bits(5).is_none());
    assert!(Phy::from_power(3) == Some(Phy::CodedS8));
    assert!(Phy::from_power(4) == Some(Phy::CodedS2));
    assert!(Phy::from_power(5).is_none());
    for phy in [Phy::CodedS8, Phy::CodedS2] {
        assert!(phy.is_coded());
        assert_eq!([phy.bit(), phy.hci()], [4, 3]);
    }
    assert_eq!([Phy::CodedS8.power_bit(), Phy::CodedS2.power_bit()], [4, 8]);
    assert!(Phy::coded(Coding::S2) == Phy::CodedS2);
    assert!(Phy::CodedS8.with_coding(Coding::S2) == Phy::CodedS2);
    assert!(Phy::CodedS2.with_coding(Coding::S8) == Phy::CodedS8);
    assert!(Phy::M2.with_coding(Coding::S2) == Phy::M2);
}
