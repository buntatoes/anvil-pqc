// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! Picks the AVX2 code or the portable code, once per call.
//!
//! The portable code is the default and the reference. On x86_64 CPUs that
//! have AVX2, the hot loops of ML-KEM (the NTT, its inverse, multiplication
//! in the NTT domain, polynomial addition and subtraction) and four Keccak
//! permutations side by side for SHAKE128 matrix sampling run on AVX2
//! instead. The results are the same bytes either way; the tests compare the
//! two paths directly. Without AVX2, or on other CPUs, everything runs on
//! the portable code and nothing is reported, because nothing is lost.
//!
//! This module holds the crate's one unsafe block outside `sys_random`: the
//! call into the AVX2 code in `run`, made only after the CPU check passed.

use crate::mlkem::Poly;
use std::cell::Cell;

/// One piece of work the AVX2 code can do. Each variant mirrors a portable
/// function with the same arguments.
// Off x86_64 nothing reads the fields: every job goes to the portable code.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) enum Job<'a> {
    Ntt(&'a mut Poly),
    NttInverse(&'a mut Poly),
    /// `out = f ∘ g` in the NTT domain.
    MultiplyNtts(&'a Poly, &'a Poly, &'a mut Poly),
    /// `a += b`.
    PolyAdd(&'a mut Poly, &'a Poly),
    /// `out = a - b`.
    PolySub(&'a Poly, &'a Poly, &'a mut Poly),
    /// Keccak-p[1600, 24] on four separate states.
    KeccakX4(&'a mut [[u64; 25]; 4]),
}

thread_local! {
    static PORTABLE_ONLY: Cell<bool> = const { Cell::new(false) };
}

#[cfg(target_arch = "x86_64")]
fn cpu_has_avx2() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    // 0 = not looked yet, 1 = no, 2 = yes.
    static SEEN: AtomicU8 = AtomicU8::new(0);
    match SEEN.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => {
            let yes = std::is_x86_feature_detected!("avx2");
            SEEN.store(if yes { 2 } else { 1 }, Ordering::Relaxed);
            yes
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_has_avx2() -> bool {
    false
}

/// True when calls on this thread go to the AVX2 code: the CPU has AVX2 and
/// [`portable_only`] isn't in effect.
pub fn avx2_active() -> bool {
    cpu_has_avx2() && !PORTABLE_ONLY.with(Cell::get)
}

/// Runs `f` with the AVX2 code switched off on this thread, so everything
/// inside uses the portable code. Other threads aren't affected. Meant for
/// tests and for comparing the two paths.
pub fn portable_only<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            PORTABLE_ONLY.with(|p| p.set(self.0));
        }
    }
    let _restore = Restore(PORTABLE_ONLY.with(|p| p.replace(true)));
    f()
}

/// Does `job` on AVX2 and returns true, or returns false without touching
/// anything, in which case the caller runs the portable code.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(crate) fn run(job: Job<'_>) -> bool {
    if !avx2_active() {
        return false;
    }
    // SAFETY: avx2_active() just confirmed that this CPU has AVX2, which is
    // the only target feature crate::avx2::run enables.
    unsafe { crate::avx2::run(job) };
    true
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn run(_job: Job<'_>) -> bool {
    false
}
