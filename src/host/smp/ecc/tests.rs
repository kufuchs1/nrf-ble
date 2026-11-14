//! Tests of P-256: the debug key pair, the data sets of the Core
//! specification, seeded random key pairs, and the keys and scalars that are
//! refused.
//!
//! The arithmetic is that of `p256` behind nrf-ble-p256, whose own tests
//! check it against `p256` used directly (edge and random scalars) and check
//! its refusals, so these check our use of it: the byte order, the X
//! coordinate as the Diffie-Hellman key, the protocol checks of the central's
//! key, the hook and the wiping of the caller's octets.

use super::*;
use crate::host::smp::toolbox::tests::hex;
use core::cell::Cell;

/// The private key of the debug key pair (Core specification, volume 3,
/// part H, section 2.3.5.6.1).
const DEBUG_PRIVATE_KEY: &str = "3f49f6d4 a3c55f38 74c9b3e3 d2103f50 4aff607b eb40b799 5899b8a6 cd3c1abd";

/// The X coordinate of the debug private key times the debug public key.
const DEBUG_DH_KEY: &str = "70aad7e6 49f91c7c ae5f79fc 32992787 c38757a8 728b7b55 da7bb3cb 4800ab2d";

/// The order of the curve, the first scalar not below it.
const ORDER: &str = "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551";

/// The field prime, the first coordinate not below it.
const PRIME: &str = "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff";

/// A coordinate of zero.
const ZERO: &str = "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000";

/// The Y coordinate of the curve point whose X is zero.
const Y_OF_ZERO: &str = "66485c78 0e2f83d7 2433bd5d 84a06bb6 541c2af3 1dae8717 28bf856a 174f93f4";

/// The X coordinate of a curve point whose Y is one.
const X_OF_Y_ONE: &str = "6916fac4 5e568b6b 9e2e2ecd 611b282e 5fcc40a3 067d6010 57f879ce 5a8a73cc";

/// One plus the field prime, below 2^256: one again, reduced.
const ONE_PLUS_PRIME: &str = "ffffffff 00000001 00000000 00000000 00000001 00000000 00000000 00000000";

/// One, as a coordinate.
const ONE: &str = "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001";

/// A key pair from `secret`, which must be valid.
fn key_pair(mut secret: [u8; KEY_LEN]) -> KeyPair {
    KeyPair::generate(&mut secret, || ()).expect("a valid private key")
}

/// The negation of the public key `key`: the same X, and the field prime
/// less Y.
fn negated(key: &[u8; PUBLIC_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    let prime = hex::<KEY_LEN>(PRIME);
    let mut out = *key;
    let (_, y) = out.split_first_chunk_mut::<KEY_LEN>().expect("X then Y");
    let mut borrow = false;
    for (octet, prime_octet) in y.iter_mut().zip(prime).rev() {
        let (difference, first) = prime_octet.overflowing_sub(*octet);
        let (difference, second) = difference.overflowing_sub(u8::from(borrow));
        *octet = difference;
        borrow = first || second;
    }
    assert!(!borrow, "Y below the field prime");
    out
}

/// The public key `key`, which must be a point of the curve, without the
/// checks for the debug key and our own.
fn point(key: &[u8; PUBLIC_KEY_LEN]) -> PublicKey { PublicKey::from_coordinates(key).expect("a point of the curve") }

/// A public key from its two coordinates.
fn public_key(x: &str, y: &str) -> [u8; PUBLIC_KEY_LEN] {
    let mut key = [0; PUBLIC_KEY_LEN];
    key[..KEY_LEN].copy_from_slice(&hex::<KEY_LEN>(x));
    key[KEY_LEN..].copy_from_slice(&hex::<KEY_LEN>(y));
    key
}

/// The scalars of a seeded xorshift generator, 32 octets each.
fn scalars(mut seed: u64) -> impl Iterator<Item = [u8; KEY_LEN]> {
    core::iter::repeat_with(move || {
        let mut out = [0; KEY_LEN];
        for chunk in out.chunks_exact_mut(8) {
            seed ^= seed.wrapping_shl(13);
            seed ^= seed.wrapping_shr(7);
            seed ^= seed.wrapping_shl(17);
            chunk.copy_from_slice(&seed.to_be_bytes());
        }
        out
    })
}

#[test]
fn the_debug_private_key_gives_the_debug_public_key() {
    let calls = Cell::<u32>::new(0);
    let mut secret = hex(DEBUG_PRIVATE_KEY);
    let pair = KeyPair::generate(&mut secret, || calls.set(calls.get().checked_add(1).expect("few calls")))
        .expect("a valid key");
    assert_eq!(pair.public_key(), &DEBUG_PUBLIC_KEY);
    assert_eq!(secret, [0; KEY_LEN], "the caller's copy is wiped");
    assert_eq!(calls.get(), 1, "the hook is called once, for the one multiplication");
}

/// The debug key pair is refused as the central's key, so its own
/// Diffie-Hellman key is computed without the check, with the same call
/// `dh_key` makes.
#[test]
fn the_debug_key_pair_gives_its_dh_key() {
    let pair = key_pair(hex(DEBUG_PRIVATE_KEY));
    assert_eq!(pair.secret.diffie_hellman(&point(&DEBUG_PUBLIC_KEY)), hex(DEBUG_DH_KEY));
}

/// P-256 data set 1 (Core specification, volume 2, part G, section
/// 7.1.2.1), whose device A has the debug key pair.
#[test]
fn data_set_1_gives_its_keys() {
    let pair_a = key_pair(hex(DEBUG_PRIVATE_KEY));
    let pair_b = key_pair(hex("55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd"));
    let public_b = public_key(
        "1ea1f0f0 1faf1d96 09592284 f19e4c00 47b58afd 8615a69f 559077b2 2faaa190",
        "4c55f33e 429dad37 7356703a 9ab85160 472d1130 e28e3676 5f89aff9 15b1214a",
    );
    assert_eq!(pair_b.public_key(), &public_b);
    let calls = Cell::<u32>::new(0);
    let dh_key = pair_a.dh_key(&public_b, || calls.set(calls.get().checked_add(1).expect("few calls")));
    assert_eq!(dh_key, Ok(hex("ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698")));
    assert_eq!(calls.get(), 1);
    assert_eq!(pair_b.dh_key(pair_a.public_key(), || ()), Err(KeyError::Debug));
}

/// P-256 data set 2 (Core specification, volume 2, part G, section
/// 7.1.2.2), in both directions.
#[test]
fn data_set_2_gives_its_keys() {
    let pair_a = key_pair(hex("06a51669 3c9aa31a 6084545d 0c5db641 b48572b9 7203ddff b7ac73f7 d0457663"));
    let pair_b = key_pair(hex("529aa067 0d72cd64 97502ed4 73502b03 7e8803b5 c60829a5 a3caa219 505530ba"));
    let public_a = public_key(
        "2c31a47b 5779809e f44cb5ea af5c3e43 d5f8faad 4a8794cb 987e9b03 745c78dd",
        "91951218 3898dfbe cd52e240 8e43871f d0211091 17bd3ed4 eaf84377 43715d4f",
    );
    let public_b = public_key(
        "f465e43f f23d3f1b 9dc7dfc0 4da87581 84dbc966 204796ec cf0d6cf5 e16500cc",
        "0201d048 bcbbd899 eeefc424 164e33c2 01c2b010 ca6b4d43 a8a155ca d8ecb279",
    );
    assert_eq!(pair_a.public_key(), &public_a);
    assert_eq!(pair_b.public_key(), &public_b);
    let dh_key = Ok(hex("ab85843a 2f6d883f 62e5684b 38e30733 5fe6e194 5ecd1960 4105c6f2 3221eb69"));
    assert_eq!(pair_a.dh_key(&public_b, || ()), dh_key);
    assert_eq!(pair_b.dh_key(&public_a, || ()), dh_key);
}

/// The values the multiplication was measured with on the emulated nRF51,
/// from a Python implementation of P-256: the central's key is 7 times the
/// generator.
#[test]
fn the_benchmark_values_match_the_reference() {
    let pair = key_pair(hex("5a30557a 9fc4e90e 33587da2 c7ec1136 5b80a5ca ef14395e 83a8cdf2 173c6186"));
    assert_eq!(
        pair.public_key()[..KEY_LEN],
        hex::<KEY_LEN>("b78d4ac8 17725355 c3139369 9016f0ac ce2d9e82 9a26ed56 5176fd5e f470d5f3")
    );
    let peer = public_key(
        "8e533b6f a0bf7b46 25bb3066 7c01fb60 7ef9f8b8 a80fef5b 30062870 3187b2a3",
        "73eb1dbd e0331836 6d069f83 a6f59000 53c73633 cb041b21 c55e1a86 c1f400b4",
    );
    assert_eq!(
        pair.dh_key(&peer, || ()),
        Ok(hex("59f10624 e1f4d53d 1284bd2b 5440a4a3 887efcb1 b593f4a9 726d31a8 f3d8199e"))
    );
}

/// The negation of a key pair's public key is a point of the curve, and the
/// Diffie-Hellman key with it is that with the key itself: the X coordinate
/// is all it depends on, which the refusal of our own key by X relies on.
#[test]
fn a_negated_key_gives_the_same_dh_key() {
    let pair_a = key_pair(hex("06a51669 3c9aa31a 6084545d 0c5db641 b48572b9 7203ddff b7ac73f7 d0457663"));
    let pair_b = key_pair(hex("529aa067 0d72cd64 97502ed4 73502b03 7e8803b5 c60829a5 a3caa219 505530ba"));
    let public_b = *pair_b.public_key();
    let expected = pair_a.dh_key(&public_b, || ());
    assert!(expected.is_ok());
    assert_eq!(pair_a.dh_key(&negated(&public_b), || ()), expected);
    assert_ne!(negated(&public_b), public_b);
}

/// 16 seeded random key pairs: each public key is that of nrf-ble-p256, and
/// the Diffie-Hellman key is the same both ways.
#[test]
fn random_key_pairs_agree() {
    let mut secrets = scalars(0x5EED_0FB1_EC0D_E000);
    for _ in 0..16 {
        let (Some(secret_a), Some(secret_b)) = (secrets.next(), secrets.next()) else { unreachable!() };
        let (Some(pair_a), Some(pair_b)) =
            (KeyPair::generate(&mut secret_a.clone(), || ()), KeyPair::generate(&mut secret_b.clone(), || ()))
        else {
            // About one in four billion is not below the order.
            continue;
        };
        let direct_a = SecretKey::from_bytes(&secret_a).expect("valid");
        assert_eq!(pair_a.public_key(), &direct_a.public_key());
        let dh_key = pair_a.dh_key(pair_b.public_key(), || ());
        assert!(dh_key.is_ok());
        assert_eq!(pair_b.dh_key(pair_a.public_key(), || ()), dh_key);
        assert_eq!(dh_key, Ok(direct_a.diffie_hellman(&point(pair_b.public_key()))));
    }
}

#[test]
fn private_keys_out_of_range_are_refused_without_a_multiplication() {
    let mut above_order = hex::<KEY_LEN>(ORDER);
    let last = above_order.last_mut().expect("an octet");
    *last = last.checked_add(1).expect("no carry");
    for secret in [[0; KEY_LEN], hex(ORDER), above_order, [0xFF; KEY_LEN]] {
        let called = Cell::new(false);
        let mut copy = secret;
        assert!(KeyPair::generate(&mut copy, || called.set(true)).is_none(), "{secret:02x?}");
        assert!(!called.get());
        assert_eq!(copy, [0; KEY_LEN], "a refused key is wiped too");
    }
}

#[test]
fn central_keys_are_refused_without_a_multiplication() {
    let pair = key_pair(hex("06a51669 3c9aa31a 6084545d 0c5db641 b48572b9 7203ddff b7ac73f7 d0457663"));
    let own = *pair.public_key();
    let mut off_curve = public_key(
        "f465e43f f23d3f1b 9dc7dfc0 4da87581 84dbc966 204796ec cf0d6cf5 e16500cc",
        "0201d048 bcbbd899 eeefc424 164e33c2 01c2b010 ca6b4d43 a8a155ca d8ecb279",
    );
    off_curve[PUBLIC_KEY_LEN - 1] ^= 1;
    // X is zero on the curve, but the field prime is not a coordinate.
    let zero_x = public_key(ZERO, Y_OF_ZERO);
    let prime_x = public_key(PRIME, Y_OF_ZERO);
    // Y is one on the curve, but one plus the field prime is not a
    // coordinate: reduced it would be a point of the curve, so only the
    // check against the field prime refuses it.
    let y_one = public_key(X_OF_Y_ONE, ONE);
    let prime_y = public_key(X_OF_Y_ONE, ONE_PLUS_PRIME);
    let cases = [
        (DEBUG_PUBLIC_KEY, KeyError::Debug),
        (negated(&DEBUG_PUBLIC_KEY), KeyError::Debug),
        (own, KeyError::Own),
        (negated(&own), KeyError::Own),
        (off_curve, KeyError::Invalid),
        ([0; PUBLIC_KEY_LEN], KeyError::Invalid),
        ([0xFF; PUBLIC_KEY_LEN], KeyError::Invalid),
        (prime_x, KeyError::Invalid),
        (prime_y, KeyError::Invalid),
    ];
    for (peer, error) in cases {
        assert_eq!(check_public_key(&peer, &own), Err(error), "{peer:02x?}");
        let called = Cell::new(false);
        assert_eq!(pair.dh_key(&peer, || called.set(true)), Err(error), "{peer:02x?}");
        assert!(!called.get());
    }
    for valid in [zero_x, y_one] {
        assert_eq!(check_public_key(&valid, &own), Ok(()), "{valid:02x?}");
        assert!(pair.dh_key(&valid, || ()).is_ok(), "{valid:02x?}");
    }
}
