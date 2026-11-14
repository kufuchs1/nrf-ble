//! Tests of the API against the Core specification's P-256 data and against
//! `p256` used directly: the byte order, the X coordinate as the
//! Diffie-Hellman key, and the private and public keys that are refused.

use super::*;
use p256::{NonZeroScalar, ProjectivePoint, ecdh, elliptic_curve::point::AffineCoordinates as _};

/// The private key of the debug key pair (Core specification, volume 3,
/// part H, section 2.3.5.6.1).
const DEBUG_PRIVATE_KEY: &str = "3f49f6d4 a3c55f38 74c9b3e3 d2103f50 4aff607b eb40b799 5899b8a6 cd3c1abd";

/// The public key of the debug key pair, X.
const DEBUG_PUBLIC_X: &str = "20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6";

/// The public key of the debug key pair, Y.
const DEBUG_PUBLIC_Y: &str = "dc809c49 652aeb6d 63329abf 5a52155c 766345c2 8fed3024 741c8ed0 1589d28b";

/// The X coordinate of the debug private key times the debug public key.
const DEBUG_DH_KEY: &str = "70aad7e6 49f91c7c ae5f79fc 32992787 c38757a8 728b7b55 da7bb3cb 4800ab2d";

/// The order of the curve, the first scalar not below it.
const ORDER: &str = "ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551";

/// The field prime, the first coordinate not below it.
const PRIME: &str = "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff";

/// The generator, X (FIPS 186-5 / SEC 2).
const GENERATOR_X: &str = "6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296";

/// The generator, Y.
const GENERATOR_Y: &str = "4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5";

/// A coordinate of zero.
const ZERO: &str = "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000";

/// The Y coordinate of the curve point whose X is zero.
const Y_OF_ZERO: &str = "66485c78 0e2f83d7 2433bd5d 84a06bb6 541c2af3 1dae8717 28bf856a 174f93f4";

/// The X coordinate of a curve point whose Y is one.
const X_OF_Y_ONE: &str = "6916fac4 5e568b6b 9e2e2ecd 611b282e 5fcc40a3 067d6010 57f879ce 5a8a73cc";

/// One plus the field prime, below 2^256: one again, reduced.
const ONE_PLUS_PRIME: &str = "ffffffff 00000001 00000000 00000000 00000001 00000000 00000000 00000000";

/// One, as a coordinate or a scalar.
const ONE: &str = "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001";

/// The octets of the hexadecimal `text`, spaces ignored.
fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut digits = text.chars().filter(|c| !c.is_whitespace()).map(|c| c.to_digit(16).expect("a hexadecimal digit"));
    let mut out = [0; N];
    for octet in &mut out {
        let (Some(high), Some(low)) = (digits.next(), digits.next()) else { panic!("too short: {text}") };
        let value = high.checked_mul(16).and_then(|shifted| shifted.checked_add(low)).expect("two digits");
        *octet = u8::try_from(value).expect("an octet");
    }
    assert!(digits.next().is_none(), "too long: {text}");
    out
}

/// `octets` with `delta` added to its last, least significant octet, which
/// must neither carry nor borrow.
fn last_plus<const N: usize>(mut octets: [u8; N], delta: i8) -> [u8; N] {
    let last = octets.last_mut().expect("an octet");
    *last = last.checked_add_signed(delta).expect("no carry or borrow");
    octets
}

/// A public key from its two coordinates.
fn public_key(x: &str, y: &str) -> [u8; PUBLIC_KEY_LEN] {
    let mut key = [0; PUBLIC_KEY_LEN];
    key[..KEY_LEN].copy_from_slice(&hex::<KEY_LEN>(x));
    key[KEY_LEN..].copy_from_slice(&hex::<KEY_LEN>(y));
    key
}

/// The private key `secret`, which must be valid.
fn secret_key(secret: &[u8; KEY_LEN]) -> SecretKey { SecretKey::from_bytes(secret).expect("a valid private key") }

/// The public key `key`, which must be valid.
fn peer(key: &[u8; PUBLIC_KEY_LEN]) -> PublicKey { PublicKey::from_coordinates(key).expect("a valid public key") }

/// The coordinates of `point`, X then Y, from `p256` directly.
fn encode(point: &AffinePoint) -> [u8; PUBLIC_KEY_LEN] {
    let mut key = [0; PUBLIC_KEY_LEN];
    key[..KEY_LEN].copy_from_slice(&point.x());
    key[KEY_LEN..].copy_from_slice(&point.y());
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
fn the_debug_key_pair_gives_its_public_key_and_dh_key() {
    let secret = secret_key(&hex(DEBUG_PRIVATE_KEY));
    let public = public_key(DEBUG_PUBLIC_X, DEBUG_PUBLIC_Y);
    assert_eq!(secret.public_key(), public);
    assert_eq!(secret.diffie_hellman(&peer(&public)), hex(DEBUG_DH_KEY));
}

/// P-256 data set 1 (Core specification, volume 2, part G, section
/// 7.1.2.1), whose device A has the debug key pair, in both directions.
#[test]
fn data_set_1_gives_its_keys() {
    let secret_a = secret_key(&hex(DEBUG_PRIVATE_KEY));
    let secret_b = secret_key(&hex("55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd"));
    let public_b = public_key(
        "1ea1f0f0 1faf1d96 09592284 f19e4c00 47b58afd 8615a69f 559077b2 2faaa190",
        "4c55f33e 429dad37 7356703a 9ab85160 472d1130 e28e3676 5f89aff9 15b1214a",
    );
    assert_eq!(secret_b.public_key(), public_b);
    let dh_key = hex("ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698");
    assert_eq!(secret_a.diffie_hellman(&peer(&public_b)), dh_key);
    assert_eq!(secret_b.diffie_hellman(&peer(&secret_a.public_key())), dh_key);
}

/// P-256 data set 2 (Core specification, volume 2, part G, section
/// 7.1.2.2), in both directions.
#[test]
fn data_set_2_gives_its_keys() {
    let secret_a = secret_key(&hex("06a51669 3c9aa31a 6084545d 0c5db641 b48572b9 7203ddff b7ac73f7 d0457663"));
    let secret_b = secret_key(&hex("529aa067 0d72cd64 97502ed4 73502b03 7e8803b5 c60829a5 a3caa219 505530ba"));
    let public_a = public_key(
        "2c31a47b 5779809e f44cb5ea af5c3e43 d5f8faad 4a8794cb 987e9b03 745c78dd",
        "91951218 3898dfbe cd52e240 8e43871f d0211091 17bd3ed4 eaf84377 43715d4f",
    );
    let public_b = public_key(
        "f465e43f f23d3f1b 9dc7dfc0 4da87581 84dbc966 204796ec cf0d6cf5 e16500cc",
        "0201d048 bcbbd899 eeefc424 164e33c2 01c2b010 ca6b4d43 a8a155ca d8ecb279",
    );
    assert_eq!(secret_a.public_key(), public_a);
    assert_eq!(secret_b.public_key(), public_b);
    let dh_key = hex("ab85843a 2f6d883f 62e5684b 38e30733 5fe6e194 5ecd1960 4105c6f2 3221eb69");
    assert_eq!(secret_a.diffie_hellman(&peer(&public_b)), dh_key);
    assert_eq!(secret_b.diffie_hellman(&peer(&public_a)), dh_key);
}

/// Scalars at the edges of the digit recoding against `p256` directly: 1 and
/// 2, the order less 1 and less 2, and every digit at the carry boundary.
/// One gives the generator, the order less one its negation.
#[test]
fn edge_scalars_match_p256() {
    let order_less_1 = last_plus(hex::<KEY_LEN>(ORDER), -1);
    let order_less_2 = last_plus(order_less_1, -1);
    let one = hex::<KEY_LEN>(ONE);
    let two = last_plus(one, 1);
    for secret in [one, two, order_less_1, order_less_2, [0x88; KEY_LEN], [0x77; KEY_LEN], [0x80; KEY_LEN]] {
        let expected = Point::from_secret_scalar(&NonZeroScalar::from_repr(secret.into()).expect("valid"));
        assert_eq!(secret_key(&secret).public_key(), encode(expected.as_affine()), "{secret:02x?}");
    }
    let generator = public_key(GENERATOR_X, GENERATOR_Y);
    assert_eq!(encode(&ProjectivePoint::GENERATOR.to_affine()), generator);
    assert_eq!(secret_key(&one).public_key(), generator);
    let negated = encode(&(-ProjectivePoint::GENERATOR).to_affine());
    assert_eq!(negated[..KEY_LEN], generator[..KEY_LEN]);
    assert_ne!(negated, generator);
    assert_eq!(secret_key(&order_less_1).public_key(), negated);
}

/// 64 seeded random key pairs and Diffie-Hellman keys against `p256` used
/// directly: its public key of the scalar, and its `ecdh`.
#[test]
fn random_scalars_match_p256_ecdh() {
    let mut secrets = scalars(0x5EED_0FB1_EC0D_E000);
    for _ in 0..64 {
        let (Some(octets_a), Some(octets_b)) = (secrets.next(), secrets.next()) else { unreachable!() };
        let (Some(secret_a), Some(secret_b)) = (SecretKey::from_bytes(&octets_a), SecretKey::from_bytes(&octets_b))
        else {
            // About one in four billion is not below the order.
            continue;
        };
        let scalar_a = NonZeroScalar::from_repr(octets_a.into()).expect("valid");
        let scalar_b = NonZeroScalar::from_repr(octets_b.into()).expect("valid");
        let public_a = Point::from_secret_scalar(&scalar_a);
        let public_b = Point::from_secret_scalar(&scalar_b);
        assert_eq!(secret_a.public_key(), encode(public_a.as_affine()));
        assert_eq!(secret_b.public_key(), encode(public_b.as_affine()));
        let expected: [u8; KEY_LEN] = (*ecdh::diffie_hellman(scalar_a, public_b.as_affine()).raw_secret_bytes()).into();
        assert_eq!(secret_a.diffie_hellman(&peer(&secret_b.public_key())), expected);
        assert_eq!(secret_b.diffie_hellman(&peer(&secret_a.public_key())), expected);
    }
}

#[test]
fn private_keys_out_of_range_are_refused() {
    let above_order = last_plus(hex::<KEY_LEN>(ORDER), 1);
    for secret in [[0; KEY_LEN], hex(ORDER), above_order, hex(PRIME), [0xFF; KEY_LEN]] {
        assert!(SecretKey::from_bytes(&secret).is_none(), "{secret:02x?}");
    }
}

#[test]
fn public_keys_off_the_curve_or_out_of_range_are_refused() {
    let mut off_curve = public_key(DEBUG_PUBLIC_X, DEBUG_PUBLIC_Y);
    off_curve[PUBLIC_KEY_LEN - 1] ^= 1;
    let mut off_curve_x = public_key(DEBUG_PUBLIC_X, DEBUG_PUBLIC_Y);
    off_curve_x[0] ^= 0x80;
    // X is zero on the curve, but the field prime is not a coordinate:
    // reduced it would be zero, so only the check against the prime refuses
    // it.
    let prime_x = public_key(PRIME, Y_OF_ZERO);
    // Y is one on the curve, but one plus the field prime is not a
    // coordinate: reduced it would be one.
    let prime_y = public_key(X_OF_Y_ONE, ONE_PLUS_PRIME);
    // (0, 0) is how the identity is often written; it is not on the curve.
    for key in [off_curve, off_curve_x, prime_x, prime_y, [0; PUBLIC_KEY_LEN], [0xFF; PUBLIC_KEY_LEN]] {
        assert!(PublicKey::from_coordinates(&key).is_none(), "{key:02x?}");
    }
}

/// The points at the edges of the coordinate checks are taken, and a
/// Diffie-Hellman key with them matches `p256` directly.
#[test]
fn public_keys_at_the_edges_are_taken() {
    let secret = hex::<KEY_LEN>("06a51669 3c9aa31a 6084545d 0c5db641 b48572b9 7203ddff b7ac73f7 d0457663");
    let scalar = NonZeroScalar::from_repr(secret.into()).expect("valid");
    for key in [public_key(ZERO, Y_OF_ZERO), public_key(X_OF_Y_ONE, ONE), public_key(GENERATOR_X, GENERATOR_Y)] {
        let x = FieldBytes::from(*key.first_chunk::<KEY_LEN>().expect("X"));
        let y = FieldBytes::from(*key.last_chunk::<KEY_LEN>().expect("Y"));
        let affine = AffinePoint::from_coordinates(&x, &y).expect("a point of the curve");
        let expected: [u8; KEY_LEN] = (*ecdh::diffie_hellman(scalar, affine).raw_secret_bytes()).into();
        assert_eq!(secret_key(&secret).diffie_hellman(&peer(&key)), expected, "{key:02x?}");
    }
}
