// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! Post-quantum key exchange for anvil.
//!
//! - [`mlkem`]: ML-KEM-768 from NIST FIPS 203.
//! - [`x25519`]: X25519 from RFC 7748.
//! - [`hybrid`]: the X25519MLKEM768 key share and shared secret used by
//!   TLS 1.3, from draft-ietf-tls-ecdhe-mlkem-03.
//! - [`keccak`]: SHA3-256, SHA3-512, SHAKE128, and SHAKE256 from FIPS 202,
//!   which ML-KEM needs.
//!
//! Everything is std only. Randomness comes from `/dev/urandom` on Unix and
//! from `BCryptGenRandom` on Windows; elsewhere use the `*_with` /
//! `*_from_seed` functions and supply your own random bytes.
//!
//! On x86_64 CPUs with AVX2, the ML-KEM hot loops run on AVX2 and give the
//! same bytes as the portable code, which stays the default and the
//! reference; see [`accel`].
//!
//! There are two unsafe blocks: the Windows random call, in its own module,
//! and the call into the AVX2 code in `accel::run`, made right after the CPU
//! check. Each has its own `#[allow(unsafe_code)]`; everything else is under
//! `#![deny(unsafe_code)]`.

#![deny(unsafe_code)]

pub mod accel;
#[cfg(target_arch = "x86_64")]
mod avx2;
pub mod hybrid;
pub mod keccak;
pub mod mlkem;
pub mod x25519;

#[cfg(windows)]
#[allow(unsafe_code)]
mod sys_random;

/// Things that can go wrong. None of them say anything about secret data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An input had the wrong number of bytes.
    BadLength,
    /// An encapsulation key failed the FIPS 203 section 7.2 modulus check.
    BadEncapsulationKey,
    /// A decapsulation key failed the FIPS 203 section 7.3 hash check.
    BadDecapsulationKey,
    /// X25519 gave the all-zero value: the peer sent a small-order point.
    ZeroSharedSecret,
    /// The system random source could not be read.
    NoRandomness,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::BadLength => "input has the wrong length",
            Error::BadEncapsulationKey => "encapsulation key failed the modulus check",
            Error::BadDecapsulationKey => "decapsulation key failed the hash check",
            Error::ZeroSharedSecret => "X25519 shared secret is all zero",
            Error::NoRandomness => "could not read the system random source",
        })
    }
}

impl std::error::Error for Error {}

/// Compare two byte strings without stopping at the first difference.
/// Lengths are treated as public.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Overwrite `dst` with `src` when `choose` is true, using a mask instead of
/// a branch.
pub(crate) fn ct_select(dst: &mut [u8], src: &[u8], choose: bool) {
    let mask = 0u8.wrapping_sub(u8::from(std::hint::black_box(choose)));
    for (d, s) in dst.iter_mut().zip(src) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Fill `buf` from the system random source.
#[cfg(unix)]
pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|_| Error::NoRandomness)
}

/// Fill `buf` from the system random source, `BCryptGenRandom` with the
/// system's preferred generator.
#[cfg(windows)]
pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    sys_random::fill(buf)
}

/// Fill `buf` from the system random source. There is none on this platform
/// yet, so this always fails; use the seeded functions.
#[cfg(not(any(unix, windows)))]
pub fn fill_random(_buf: &mut [u8]) -> Result<(), Error> {
    Err(Error::NoRandomness)
}
