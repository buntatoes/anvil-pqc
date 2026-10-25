// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! ML-KEM-768 round trips, input checks, and implicit rejection.

use anvil_pqc::Error;
use anvil_pqc::keccak::shake256_bytes;
use anvil_pqc::mlkem::{
    CIPHERTEXT_LEN, DECAPSULATION_KEY_LEN, DecapsulationKey, ENCAPSULATION_KEY_LEN,
    EncapsulationKey, keygen, keygen_from_seed,
};

fn seed(n: u8) -> [u8; 64] {
    std::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(n))
}

#[test]
fn sizes_match_table_3() {
    let (ek, dk) = keygen_from_seed(&seed(1));
    assert_eq!(ek.as_bytes().len(), 1184);
    assert_eq!(dk.as_bytes().len(), 2400);
    let (ct, k) = ek.encapsulate_with(&[7; 32]);
    assert_eq!(ct.len(), 1088);
    assert_eq!(k.len(), 32);
    assert_eq!(
        (ENCAPSULATION_KEY_LEN, DECAPSULATION_KEY_LEN, CIPHERTEXT_LEN),
        (1184, 2400, 1088)
    );
}

#[test]
fn round_trip_with_seeds_and_with_system_randomness() {
    for n in 0..8 {
        let (ek, dk) = keygen_from_seed(&seed(n));
        let (ct, k) = ek.encapsulate_with(&[n; 32]);
        assert_eq!(dk.decapsulate(&ct), Ok(k));
        assert_eq!(dk.encapsulation_key(), ek);
    }
    let (ek, dk) = keygen().expect("random keygen");
    let (ct, k) = ek.encapsulate().expect("random encapsulate");
    assert_eq!(dk.decapsulate(&ct), Ok(k));
}

#[test]
fn keys_survive_a_trip_through_bytes() {
    let (ek, dk) = keygen_from_seed(&seed(3));
    let ek2 = EncapsulationKey::from_bytes(ek.as_bytes()).expect("ek");
    let dk2 = DecapsulationKey::from_bytes(dk.as_bytes()).expect("dk");
    let (ct, k) = ek2.encapsulate_with(&[9; 32]);
    assert_eq!(dk2.decapsulate(&ct), Ok(k));
}

#[test]
fn same_seed_same_keys_different_seed_different_keys() {
    let (a, _) = keygen_from_seed(&seed(5));
    let (b, _) = keygen_from_seed(&seed(5));
    let (c, _) = keygen_from_seed(&seed(6));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn tampered_ciphertext_gives_the_rejection_key() {
    let s = seed(11);
    let z = &s[32..];
    let (ek, dk) = keygen_from_seed(&s);
    let (ct, k) = ek.encapsulate_with(&[42; 32]);
    // Flip a bit in the u part, in the v part, and the very last bit.
    for (i, bit) in [
        (0usize, 0u8),
        (500, 3),
        (CIPHERTEXT_LEN - 100, 5),
        (CIPHERTEXT_LEN - 1, 7),
    ] {
        let mut bad = ct.clone();
        bad[i] ^= 1 << bit;
        let got = dk.decapsulate(&bad).expect("right length");
        let want = shake256_bytes::<32>(&[z, &bad]);
        assert_eq!(got, want, "byte {i}: J(z || c)");
        assert_ne!(got, k);
        // Deterministic: the same bad ciphertext gives the same key again.
        assert_eq!(dk.decapsulate(&bad), Ok(got));
    }
}

#[test]
fn a_different_key_pair_rejects_too() {
    let (ek, _) = keygen_from_seed(&seed(1));
    let (_, dk_other) = keygen_from_seed(&seed(2));
    let (ct, k) = ek.encapsulate_with(&[1; 32]);
    let got = dk_other.decapsulate(&ct).expect("right length");
    assert_ne!(got, k);
    assert_eq!(got, shake256_bytes::<32>(&[&seed(2)[32..], &ct]));
}

#[test]
fn wrong_lengths_are_errors() {
    let (ek, dk) = keygen_from_seed(&seed(4));
    let (ct, _) = ek.encapsulate_with(&[0; 32]);
    assert_eq!(
        dk.decapsulate(&ct[..CIPHERTEXT_LEN - 1]),
        Err(Error::BadLength)
    );
    let mut long = ct.clone();
    long.push(0);
    assert_eq!(dk.decapsulate(&long), Err(Error::BadLength));
    assert_eq!(dk.decapsulate(&[]), Err(Error::BadLength));
    assert_eq!(
        EncapsulationKey::from_bytes(&ek.as_bytes()[1..]).unwrap_err(),
        Error::BadLength
    );
    assert_eq!(
        DecapsulationKey::from_bytes(&dk.as_bytes()[1..]).unwrap_err(),
        Error::BadLength
    );
}

#[test]
fn encapsulation_key_with_a_coefficient_of_q_fails_the_modulus_check() {
    let (ek, _) = keygen_from_seed(&seed(8));
    let mut bad = ek.as_bytes().to_vec();
    // Set the first 12-bit coefficient to 3329 = 0xd01.
    bad[0] = 0x01;
    bad[1] = (bad[1] & 0xf0) | 0x0d;
    assert_eq!(
        EncapsulationKey::from_bytes(&bad).unwrap_err(),
        Error::BadEncapsulationKey
    );
    // 4095 is out of range as well.
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    assert_eq!(
        EncapsulationKey::from_bytes(&bad).unwrap_err(),
        Error::BadEncapsulationKey
    );
    // The rho seed at the end is not checked; any bytes are fine there.
    let mut ok = ek.as_bytes().to_vec();
    *ok.last_mut().expect("nonempty") ^= 0xff;
    assert!(EncapsulationKey::from_bytes(&ok).is_ok());
}

#[test]
fn decapsulation_key_with_a_wrong_hash_fails_the_hash_check() {
    let (_, dk) = keygen_from_seed(&seed(9));
    let mut bad = dk.as_bytes().to_vec();
    bad[768 * 3 + 32] ^= 1;
    assert_eq!(
        DecapsulationKey::from_bytes(&bad).unwrap_err(),
        Error::BadDecapsulationKey
    );
    // Changing the embedded ek without fixing the hash fails too.
    let mut bad = dk.as_bytes().to_vec();
    bad[384 * 3 + 5] ^= 1;
    assert_eq!(
        DecapsulationKey::from_bytes(&bad).unwrap_err(),
        Error::BadDecapsulationKey
    );
}
