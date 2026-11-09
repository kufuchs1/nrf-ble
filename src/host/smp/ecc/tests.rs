//! Tests of P-256: the debug key pair, the data sets of the Core
//! specification, seeded random scalars against the `ecdh` of `p256`, and
//! the keys and scalars that are refused.

use super::*;
use crate::host::smp::toolbox::tests::hex;
use core::cell::Cell;
use p256::{PublicKey, ecdh};

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

/// A key pair from `secret`, which must be valid.
fn key_pair(secret: [u8; KEY_LEN]) -> KeyPair { KeyPair::generate(secret, || ()).expect("a valid private key") }

/// The negation of the public key `key`: the same X and the other Y.
fn negated(key: &[u8; PUBLIC_KEY_LEN]) -> [u8; PUBLIC_KEY_LEN] { encode(&point(key).neg()).expect("not the identity") }

/// The point of the public key `key`, which must be on the curve, without
/// the checks for the debug key and our own.
fn point(key: &[u8; PUBLIC_KEY_LEN]) -> ProjectivePoint {
    let x = FieldBytes::from(*key.first_chunk::<KEY_LEN>().expect("X"));
    let y = FieldBytes::from(*key.last_chunk::<KEY_LEN>().expect("Y"));
    ProjectivePoint::from(AffinePoint::from_coordinates(&x, &y).expect("a point of the curve"))
}

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
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            chunk.copy_from_slice(&seed.to_be_bytes());
        }
        out
    })
}

#[test]
fn the_debug_private_key_gives_the_debug_public_key() {
    let calls = Cell::new(0);
    let pair = KeyPair::generate(hex(DEBUG_PRIVATE_KEY), || calls.set(calls.get() + 1)).expect("a valid key");
    assert_eq!(pair.public_key(), &DEBUG_PUBLIC_KEY);
    assert_eq!(calls.get(), 1, "the hook is called once, for the one multiplication");
}

/// The debug key pair is refused as the central's key, so its own
/// Diffie-Hellman key is computed without the check.
#[test]
fn the_debug_key_pair_gives_its_dh_key() {
    let product = multiply(&hex(DEBUG_PRIVATE_KEY), &point(&DEBUG_PUBLIC_KEY));
    assert_eq!(x_coordinate(&product), Some(hex(DEBUG_DH_KEY)));
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
    let calls = Cell::new(0);
    let dh_key = pair_a.dh_key(&public_b, || calls.set(calls.get() + 1));
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

/// Scalars at the edges of the digit recoding: 1 and 2, the order less 1
/// and less 2, and every digit at the carry boundary.
#[test]
fn edge_scalars_match_p256() {
    let mut order_less_1 = hex::<KEY_LEN>(ORDER);
    order_less_1[KEY_LEN - 1] -= 1;
    let mut order_less_2 = order_less_1;
    order_less_2[KEY_LEN - 1] -= 1;
    let mut one = [0; KEY_LEN];
    one[KEY_LEN - 1] = 1;
    let mut two = [0; KEY_LEN];
    two[KEY_LEN - 1] = 2;
    for secret in [one, two, order_less_1, order_less_2, [0x88; KEY_LEN], [0x77; KEY_LEN], [0x80; KEY_LEN]] {
        let expected = PublicKey::from_secret_scalar(&NonZeroScalar::from_repr(secret.into()).expect("valid"));
        let expected = encode(&expected.to_projective()).expect("not the identity");
        assert_eq!(key_pair(secret).public_key(), &expected, "{secret:02x?}");
    }
    let generator = encode(&ProjectivePoint::GENERATOR).expect("not the identity");
    assert_eq!(key_pair(order_less_1).public_key(), &negated(&generator));
}

/// 64 seeded random key pairs and Diffie-Hellman keys against the `ecdh`
/// of the `p256` crate.
#[test]
fn random_scalars_match_p256_ecdh() {
    let mut secrets = scalars(0x5EED_0FB1_EC0D_E000);
    for _ in 0..64 {
        let (Some(secret_a), Some(secret_b)) = (secrets.next(), secrets.next()) else { unreachable!() };
        let (Some(pair_a), Some(pair_b)) = (KeyPair::generate(secret_a, || ()), KeyPair::generate(secret_b, || ()))
        else {
            // About one in four billion is not below the order.
            continue;
        };
        let scalar_a = NonZeroScalar::from_repr(secret_a.into()).expect("valid");
        let scalar_b = NonZeroScalar::from_repr(secret_b.into()).expect("valid");
        let public_a = PublicKey::from_secret_scalar(&scalar_a);
        let public_b = PublicKey::from_secret_scalar(&scalar_b);
        assert_eq!(Some(*pair_a.public_key()), encode(&public_a.to_projective()));
        assert_eq!(Some(*pair_b.public_key()), encode(&public_b.to_projective()));
        let expected: [u8; KEY_LEN] = (*ecdh::diffie_hellman(scalar_a, public_b.as_affine()).raw_secret_bytes()).into();
        assert_eq!(pair_a.dh_key(pair_b.public_key(), || ()), Ok(expected));
        assert_eq!(pair_b.dh_key(pair_a.public_key(), || ()), Ok(expected));
    }
}

#[test]
fn private_keys_out_of_range_are_refused_without_a_multiplication() {
    let mut above_order = hex::<KEY_LEN>(ORDER);
    above_order[KEY_LEN - 1] += 1;
    for secret in [[0; KEY_LEN], hex(ORDER), above_order, [0xFF; KEY_LEN]] {
        let called = Cell::new(false);
        assert!(KeyPair::generate(secret, || called.set(true)).is_none(), "{secret:02x?}");
        assert!(!called.get());
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
    let prime_y = public_key(ZERO, PRIME);
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
    assert_eq!(check_public_key(&zero_x, &own), Ok(()));
    assert!(pair.dh_key(&zero_x, || ()).is_ok());
}
