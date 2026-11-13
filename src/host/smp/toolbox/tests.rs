//! Tests of the toolbox: RFC 4493 with the messages split in every way, and
//! the sample data of the Core specification, volume 3, part H, appendix D.

use super::*;
use crate::host::test_aes::Software;

/// The octets of `text`, hexadecimal digits with any spaces between them.
pub(crate) fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0; N];
    let mut digits = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).map(|byte| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("not a hexadecimal digit: {byte}"),
    });
    for octet in &mut out {
        let high = digits.next().expect("too few digits");
        let low = digits.next().expect("too few digits");
        *octet = high.wrapping_shl(4) | low;
    }
    assert!(digits.next().is_none(), "too many digits");
    out
}

/// The key of the RFC 4493 examples.
const RFC_KEY: &str = "2b7e1516 28aed2a6 abf71588 09cf4f3c";

/// The 64-octet message of RFC 4493; the examples take its first 0, 16, 40
/// and 64 octets.
const RFC_MESSAGE: &str = "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 \
                           30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710";

/// The four examples of RFC 4493: message length and CMAC.
const RFC_EXAMPLES: [(usize, &str); 4] = [
    (0, "bb1d6929 e9593728 7fa37d12 9b756746"),
    (16, "070a16b4 6b4d4144 f79bdd9d d04a287c"),
    (40, "dfa66747 de9ae630 30ca3261 1497c827"),
    (64, "51f0bebf 7e3b9d92 fc497417 79363cfe"),
];

/// U of the samples: the X coordinate of the debug public key.
const SAMPLE_U: &str = "20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6";
/// V of the samples.
const SAMPLE_V: &str = "55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd";
/// N1, or X, of the samples.
const SAMPLE_N1: &str = "d5cb8454 d177733e ffffb2ec 712baeab";
/// N2, or Y, of the samples.
const SAMPLE_N2: &str = "a6e8e7cc 25a75f6e 216583f7 ff3dc4cf";
/// The Diffie-Hellman key W of the f5 sample.
const SAMPLE_W: &str = "ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698";
/// The MacKey of the f5 sample, the W of the f6 sample.
const SAMPLE_MAC_KEY: &str = "2965f176 a1084a02 fd3f6a20 ce636e20";

/// A1 of the samples: public device address 56:12:37:37:BF:CE.
fn sample_a1() -> [u8; 7] { address(Peer::new([0xCE, 0xBF, 0x37, 0x37, 0x12, 0x56], false)) }

/// A2 of the samples: public device address A7:13:70:2D:CF:C1.
fn sample_a2() -> [u8; 7] { address(Peer::new([0xC1, 0xCF, 0x2D, 0x70, 0x13, 0xA7], false)) }

#[test]
fn the_subkeys_match_rfc_4493() {
    let key = hex::<16>(RFC_KEY);
    let zero = Software.encrypt(key, [0; 16]);
    assert_eq!(zero, hex("7df76b0c 1ab899b3 3e42f047 b91b546f"));
    assert_eq!(double(zero), hex("fbeed618 35713366 7c85e08f 7236a8de"));
    assert_eq!(double(double(zero)), hex("f7ddac30 6ae266cc f90bc11e e46d513b"));
}

#[test]
fn cmac_matches_rfc_4493_however_the_message_is_split() {
    let key = hex::<16>(RFC_KEY);
    let message = hex::<64>(RFC_MESSAGE);
    for (len, expected) in RFC_EXAMPLES {
        let expected = hex::<16>(expected);
        let message = &message[..len];
        assert_eq!(cmac(&Software, key, &[message]), expected, "{len} octets in one part");
        assert_eq!(cmac(&Software, key, &[]), hex(RFC_EXAMPLES[0].1), "no parts at all");
        // Every split into two and three parts, empty parts included.
        for first in 0..=len {
            for second in first..=len {
                let parts = [&message[..first], &message[first..second], &message[second..]];
                assert_eq!(cmac(&Software, key, &parts), expected, "{len} octets split at {first} and {second}");
            }
        }
        // One octet at a time, through the streaming interface.
        let mut mac = Cmac::new(&Software, key);
        for octet in message {
            mac.update(core::slice::from_ref(octet));
        }
        assert_eq!(mac.finish(), expected, "{len} octets one at a time");
    }
}

#[test]
fn the_addresses_are_typed_and_most_significant_octet_first() {
    assert_eq!(sample_a1(), hex("00 561237 37bfce"));
    assert_eq!(sample_a2(), hex("00 a71370 2dcfc1"));
    assert_eq!(address(Peer::new([1, 2, 3, 4, 5, 0xC6], true)), [1, 0xC6, 5, 4, 3, 2, 1]);
}

/// Appendix D.2.
#[test]
fn f4_matches_the_sample_data() {
    let confirm = f4(&Software, &hex(SAMPLE_U), &hex(SAMPLE_V), &hex(SAMPLE_N1), 0);
    assert_eq!(confirm, hex("f2c916f1 07a9bd1c f1eda1be a974872d"));
}

/// Appendix D.3, with its intermediate key T.
#[test]
fn f5_matches_the_sample_data() {
    let w = hex::<32>(SAMPLE_W);
    assert_eq!(cmac(&Software, F5_SALT, &[&w]), hex("3c128f20 de883288 97624bdb 8dac6989"));
    let (mac_key, ltk) = f5(&Software, &w, (&hex(SAMPLE_N1), &hex(SAMPLE_N2)), (&sample_a1(), &sample_a2()));
    assert_eq!(mac_key, hex(SAMPLE_MAC_KEY));
    assert_eq!(ltk, hex("69867911 69d7cd23 980522b5 94750a38"));
}

/// Appendix D.4.
#[test]
fn f6_matches_the_sample_data() {
    let check = f6(
        &Software,
        &hex(SAMPLE_MAC_KEY),
        (&hex(SAMPLE_N1), &hex(SAMPLE_N2)),
        &hex("12a3343b b453bb54 08da42d2 0c2d0fc8"),
        hex("010102"),
        (&sample_a1(), &sample_a2()),
    );
    assert_eq!(check, hex("e3c47398 9cd0e8c5 d26c0b09 da958f61"));
}

/// Appendix D.5.
#[test]
fn g2_matches_the_sample_data() {
    let value = g2(&Software, &hex(SAMPLE_U), &hex(SAMPLE_V), &hex(SAMPLE_N1), &hex(SAMPLE_N2));
    assert_eq!(value, 0x2F9E_D5BA);
    assert_eq!(value % 1_000_000, 938_554);
}

/// Appendix D.7.
#[test]
fn ah_matches_the_sample_data() {
    let hash = ah(&Software, &hex("ec0234a3 57c8ad05 341010a6 0a397d9b"), hex("708194"));
    assert_eq!(hash, hex("0dfbaa"));
}
