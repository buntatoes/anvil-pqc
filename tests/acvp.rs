// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0-OR-Commercial
// Copyright (c) 2026 Buntato
//! NIST ACVP vectors for ML-KEM-768. See tests/data/acvp-mlkem768.txt for
//! where they come from.
//!
//! Each check runs twice: on whatever this CPU uses (AVX2 where it has it)
//! and with the portable code forced.

use anvil_pqc::accel::{avx2_active, portable_only};
use anvil_pqc::keccak::sha3_256;
use anvil_pqc::mlkem::{DecapsulationKey, EncapsulationKey, keygen_from_seed};
use std::collections::HashMap;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn cases() -> Vec<HashMap<String, String>> {
    let text = include_str!("data/acvp-mlkem768.txt");
    let mut out = Vec::new();
    let mut cur = HashMap::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let (k, v) = line.split_once('=').expect("key=value");
        cur.insert(k.to_string(), v.to_string());
    }
    out
}

fn of_kind(kind: &str) -> Vec<HashMap<String, String>> {
    cases().into_iter().filter(|c| c["kind"] == kind).collect()
}

fn check_key_generation() {
    let cases = of_kind("keygen");
    assert_eq!(cases.len(), 25);
    for c in cases {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&unhex(&c["d"]));
        seed[32..].copy_from_slice(&unhex(&c["z"]));
        let (ek, dk) = keygen_from_seed(&seed);
        assert_eq!(
            sha3_256(&[ek.as_bytes()]).to_vec(),
            unhex(&c["ek_sha3"]),
            "tc {}",
            c["tc"]
        );
        assert_eq!(
            sha3_256(&[dk.as_bytes()]).to_vec(),
            unhex(&c["dk_sha3"]),
            "tc {}",
            c["tc"]
        );
    }
}

fn check_encapsulation() {
    let cases = of_kind("encap");
    assert!(!cases.is_empty());
    for c in cases {
        let ek = EncapsulationKey::from_bytes(&unhex(&c["ek"])).expect("valid ek");
        let m: [u8; 32] = unhex(&c["m"]).try_into().expect("32 bytes");
        let (ct, k) = ek.encapsulate_with(&m);
        assert_eq!(ct, unhex(&c["c"]), "tc {}", c["tc"]);
        assert_eq!(k.to_vec(), unhex(&c["k"]), "tc {}", c["tc"]);
    }
}

fn check_decapsulation_including_implicit_rejection() {
    let cases = of_kind("decap");
    let rejected = cases
        .iter()
        .filter(|c| c["reason"] == "modified ciphertext")
        .count();
    assert!(rejected > 0, "the set should include modified ciphertexts");
    for c in cases {
        let dk = DecapsulationKey::from_bytes(&unhex(&c["dk"])).expect("valid dk");
        let k = dk.decapsulate(&unhex(&c["c"])).expect("right length");
        assert_eq!(
            k.to_vec(),
            unhex(&c["k"]),
            "tc {} ({})",
            c["tc"],
            c["reason"]
        );
    }
}

fn check_encapsulation_key_check() {
    for c in of_kind("ek_check") {
        let ok = EncapsulationKey::from_bytes(&unhex(&c["ek"])).is_ok();
        assert_eq!(ok, c["pass"] == "true", "tc {} ({})", c["tc"], c["reason"]);
    }
}

fn check_decapsulation_key_check() {
    for c in of_kind("dk_check") {
        let ok = DecapsulationKey::from_bytes(&unhex(&c["dk"])).is_ok();
        assert_eq!(ok, c["pass"] == "true", "tc {} ({})", c["tc"], c["reason"]);
    }
}

#[test]
fn key_generation() {
    check_key_generation();
}

#[test]
fn key_generation_portable() {
    portable_only(|| {
        assert!(!avx2_active());
        check_key_generation();
    });
}

#[test]
fn encapsulation() {
    check_encapsulation();
}

#[test]
fn encapsulation_portable() {
    portable_only(|| {
        assert!(!avx2_active());
        check_encapsulation();
    });
}

#[test]
fn decapsulation_including_implicit_rejection() {
    check_decapsulation_including_implicit_rejection();
}

#[test]
fn decapsulation_including_implicit_rejection_portable() {
    portable_only(|| {
        assert!(!avx2_active());
        check_decapsulation_including_implicit_rejection();
    });
}

#[test]
fn encapsulation_key_check() {
    check_encapsulation_key_check();
}

#[test]
fn encapsulation_key_check_portable() {
    portable_only(|| {
        assert!(!avx2_active());
        check_encapsulation_key_check();
    });
}

#[test]
fn decapsulation_key_check() {
    check_decapsulation_key_check();
}

#[test]
fn decapsulation_key_check_portable() {
    portable_only(|| {
        assert!(!avx2_active());
        check_decapsulation_key_check();
    });
}
