// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0-OR-Commercial
// Copyright (c) 2026 Buntato
//! The AVX2 code and the portable code give the same bytes through the
//! public API. On a CPU without AVX2 both runs use the portable code, and
//! the tests say so on stderr.

use anvil_pqc::accel::{avx2_active, portable_only};
use anvil_pqc::hybrid::{client_share_from_seed, server_respond_with};
use anvil_pqc::mlkem::{DecapsulationKey, EncapsulationKey, keygen_from_seed};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.next() as u8;
        }
    }
}

fn note_path() {
    if !avx2_active() {
        eprintln!("no AVX2 on this CPU: both runs use the portable code");
    }
}

#[test]
fn portable_only_switches_off_and_back() {
    let before = avx2_active();
    portable_only(|| assert!(!avx2_active()));
    assert_eq!(avx2_active(), before);
    let caught = std::panic::catch_unwind(|| portable_only(|| panic!("inside")));
    assert!(caught.is_err());
    assert_eq!(avx2_active(), before);
}

#[test]
fn mlkem_same_bytes_both_ways() {
    note_path();
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..500 {
        let mut seed = [0u8; 64];
        let mut m = [0u8; 32];
        rng.fill(&mut seed);
        rng.fill(&mut m);
        let run = || {
            let (ek, dk) = keygen_from_seed(&seed);
            let (ct, k) = ek.encapsulate_with(&m);
            let mut bad = ct.clone();
            let at = (seed[0] as usize * 7) % bad.len();
            bad[at] ^= 1 << (seed[1] % 8);
            let k_good = dk.decapsulate(&ct).expect("length");
            let k_bad = dk.decapsulate(&bad).expect("length");
            (
                ek.as_bytes().to_vec(),
                dk.as_bytes().to_vec(),
                ct,
                k,
                k_good,
                k_bad,
            )
        };
        let fast = run();
        let slow = portable_only(run);
        assert_eq!(fast, slow);
        assert_eq!(fast.3, fast.4);
        assert_ne!(fast.3, fast.5);
        // Keys made one way work the other way.
        let ek = EncapsulationKey::from_bytes(&fast.0).expect("ek");
        let dk = DecapsulationKey::from_bytes(&fast.1).expect("dk");
        let (ct, k) = portable_only(|| ek.encapsulate_with(&m));
        assert_eq!(dk.decapsulate(&ct), Ok(k));
    }
}

#[test]
fn hybrid_same_bytes_both_ways() {
    note_path();
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    for _ in 0..100 {
        let mut seed = [0u8; 64];
        let mut cx = [0u8; 32];
        let mut m = [0u8; 32];
        let mut xs = [0u8; 32];
        rng.fill(&mut seed);
        rng.fill(&mut cx);
        rng.fill(&mut m);
        rng.fill(&mut xs);
        let run = || {
            let (state, share) = client_share_from_seed(&seed, &cx);
            let (reply, secret) = server_respond_with(&share, &m, &xs).expect("server");
            let finished = state.finish(&reply).expect("client");
            (share, reply, secret, finished)
        };
        let fast = run();
        let slow = portable_only(run);
        assert_eq!(fast, slow);
        assert_eq!(fast.2, fast.3);
    }
}
