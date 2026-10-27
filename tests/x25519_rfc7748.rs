// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0-OR-Commercial
// Copyright (c) 2026 Buntato
//! X25519 test vectors from RFC 7748 sections 5.2 and 6.1.

use anvil_pqc::Error;
use anvil_pqc::x25519::{BASEPOINT, public_key, shared_secret, x25519};

fn h32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect();
    v.try_into().expect("32 bytes")
}

#[test]
fn section_5_2_single_vectors() {
    assert_eq!(
        x25519(
            &h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            &h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        ),
        h32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    );
    // This u-coordinate has its top bit set, which the function must mask.
    assert_eq!(
        x25519(
            &h32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            &h32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
        ),
        h32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    );
}

fn iterate(n: usize) -> [u8; 32] {
    let mut k = BASEPOINT;
    let mut u = BASEPOINT;
    for _ in 0..n {
        let next = x25519(&k, &u);
        u = k;
        k = next;
    }
    k
}

#[test]
fn section_5_2_iterated_once_and_a_thousand_times() {
    assert_eq!(
        iterate(1),
        h32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
    );
    assert_eq!(
        iterate(1000),
        h32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
    );
}

#[test]
#[ignore = "takes a while; run with --ignored --release"]
fn section_5_2_iterated_a_million_times() {
    assert_eq!(
        iterate(1_000_000),
        h32("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424")
    );
}

#[test]
fn section_6_1_diffie_hellman() {
    let a = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let ka = public_key(&a);
    let kb = public_key(&b);
    assert_eq!(
        ka,
        h32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        kb,
        h32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let k = h32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(shared_secret(&a, &kb), Ok(k));
    assert_eq!(shared_secret(&b, &ka), Ok(k));
}

#[test]
fn small_order_points_give_the_all_zero_error() {
    let a = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    // u = 0 and u = 1 have small order; so does p (which reduces to 0) and
    // p + 1 (which reduces to 1).
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    let mut p1 = p;
    p1[0] = 0xee;
    let mut one = [0u8; 32];
    one[0] = 1;
    for u in [[0u8; 32], one, p, p1] {
        assert_eq!(shared_secret(&a, &u), Err(Error::ZeroSharedSecret));
    }
}
