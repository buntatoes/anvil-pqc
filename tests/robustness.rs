// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! Seeded junk input: wrong lengths and random values must give errors or
//! keys, never a panic.

use anvil_pqc::hybrid::{self, client_share_from_seed, server_respond_with};
use anvil_pqc::mlkem::{self, DecapsulationKey, EncapsulationKey, keygen_from_seed};
use anvil_pqc::x25519;

/// xorshift64*, fixed seed so failures repeat.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn len_near(&mut self, target: usize) -> usize {
        match self.next() % 4 {
            0 => target,
            1 => target.saturating_sub((self.next() % 4) as usize),
            2 => target + (self.next() % 4) as usize,
            _ => (self.next() % (2 * target as u64 + 1)) as usize,
        }
    }
}

#[test]
fn junk_ciphertexts() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let (_, dk) = keygen_from_seed(&[7; 64]);
    for _ in 0..200 {
        let n = rng.len_near(mlkem::CIPHERTEXT_LEN);
        let c = rng.bytes(n);
        let r = dk.decapsulate(&c);
        assert_eq!(r.is_ok(), n == mlkem::CIPHERTEXT_LEN);
    }
}

#[test]
fn junk_encapsulation_keys() {
    let mut rng = Rng(0xfeed_beef_cafe_f00d);
    let mut accepted = 0;
    for _ in 0..200 {
        let n = rng.len_near(mlkem::ENCAPSULATION_KEY_LEN);
        let mut b = rng.bytes(n);
        // Half the time, clear the top bit of each 12-bit value so every
        // value is below q, the key passes the modulus check, and gets used.
        if n == mlkem::ENCAPSULATION_KEY_LEN && rng.next() & 1 == 0 {
            for i in (0..1152).step_by(3) {
                b[i + 1] &= 0xf7;
                b[i + 2] &= 0x7f;
            }
        }
        if let Ok(ek) = EncapsulationKey::from_bytes(&b) {
            accepted += 1;
            let (ct, _) = ek.encapsulate_with(&[1; 32]);
            assert_eq!(ct.len(), mlkem::CIPHERTEXT_LEN);
        }
    }
    assert!(accepted > 0);
}

#[test]
fn junk_decapsulation_keys() {
    let mut rng = Rng(0x1357_9bdf_2468_ace0);
    for _ in 0..100 {
        let n = rng.len_near(mlkem::DECAPSULATION_KEY_LEN);
        let b = rng.bytes(n);
        assert!(DecapsulationKey::from_bytes(&b).is_err());
    }
}

#[test]
fn junk_hybrid_shares() {
    let mut rng = Rng(0xdead_0000_beef_1111);
    let (state, _) = client_share_from_seed(&[3; 64], &[4; 32]);
    for _ in 0..100 {
        let n = rng.len_near(hybrid::CLIENT_SHARE_LEN);
        let _ = server_respond_with(&rng.bytes(n), &[5; 32], &[6; 32]);
        let n = rng.len_near(hybrid::SERVER_SHARE_LEN);
        let s = rng.bytes(n);
        let r = state.finish(&s);
        if n != hybrid::SERVER_SHARE_LEN {
            assert!(r.is_err());
        }
    }
}

#[test]
fn junk_x25519_points() {
    let mut rng = Rng(0x2222_3333_4444_5555);
    for _ in 0..50 {
        let k: [u8; 32] = rng.bytes(32).try_into().expect("32");
        let u: [u8; 32] = rng.bytes(32).try_into().expect("32");
        let _ = x25519::shared_secret(&k, &u);
    }
}
