// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0-OR-Commercial
// Copyright (c) 2026 Buntato
//! The AVX2 versions of the ML-KEM hot loops and of four Keccak permutations
//! at once. Every function here gives exactly what its portable twin gives;
//! the tests in `mlkem` and `keccak` check that on random and boundary inputs.
//!
//! Everything is safe code. The only way in is `run`, which `accel::run`
//! calls after checking that the CPU has AVX2.
//!
//! Coefficients stay fully reduced, in 0..q, the same as in the portable
//! code, so no lazy reduction can leave a different representative behind.
//! Nothing here branches on, or indexes memory by, a coefficient or a state
//! word: the reductions use unsigned minimum, and every lane layout is fixed.

use crate::accel::Job;
use crate::keccak::{RHO, ROUND_CONSTANTS};
use crate::mlkem::{GAMMAS, Poly, ZETAS};
use std::arch::x86_64::*;

const Q: u16 = 3329;

/// floor(w * 2^16 / q), the precomputed quotient for multiplying by the
/// constant w (0 <= w < q).
const fn quotient_of(w: u16) -> u16 {
    (((w as u32) << 16) / Q as u32) as u16
}

/// Which 2*len-coefficient block lane `lane` of the gathered vector belongs
/// to, for layers len = 8, 4 and 2, in the 32 coefficients 32c..32c+32. The
/// gathers in `split` give this layout.
const fn lane_block(len: usize, c: usize, lane: usize) -> usize {
    match len {
        8 => 2 * c + lane / 8,
        4 => 4 * c + [0, 2, 1, 3][lane / 4],
        _ => 8 * c + [0, 1, 4, 5, 2, 3, 6, 7][lane / 2],
    }
}

/// Per-lane zetas for the small layers, and their precomputed quotients.
/// Forward layers use ZETAS[128/len + block] (Algorithm 9), inverse layers
/// ZETAS[256/len - 1 - block] (Algorithm 10).
const fn lane_zetas(len: usize, inverse: bool, quotient: bool) -> [[u16; 16]; 8] {
    let mut out = [[0u16; 16]; 8];
    let mut c = 0;
    while c < 8 {
        let mut lane = 0;
        while lane < 16 {
            let b = lane_block(len, c, lane);
            let z = if inverse {
                ZETAS[256 / len - 1 - b]
            } else {
                ZETAS[128 / len + b]
            };
            out[c][lane] = if quotient { quotient_of(z) } else { z };
            lane += 1;
        }
        c += 1;
    }
    out
}

const FWD_Z8: [[u16; 16]; 8] = lane_zetas(8, false, false);
const FWD_Z8Q: [[u16; 16]; 8] = lane_zetas(8, false, true);
const FWD_Z4: [[u16; 16]; 8] = lane_zetas(4, false, false);
const FWD_Z4Q: [[u16; 16]; 8] = lane_zetas(4, false, true);
const FWD_Z2: [[u16; 16]; 8] = lane_zetas(2, false, false);
const FWD_Z2Q: [[u16; 16]; 8] = lane_zetas(2, false, true);
const INV_Z8: [[u16; 16]; 8] = lane_zetas(8, true, false);
const INV_Z8Q: [[u16; 16]; 8] = lane_zetas(8, true, true);
const INV_Z4: [[u16; 16]; 8] = lane_zetas(4, true, false);
const INV_Z4Q: [[u16; 16]; 8] = lane_zetas(4, true, true);
const INV_Z2: [[u16; 16]; 8] = lane_zetas(2, true, false);
const INV_Z2Q: [[u16; 16]; 8] = lane_zetas(2, true, true);

/// The entry point. Matches the job to its function; all of them need only
/// AVX2.
#[target_feature(enable = "avx2")]
pub(crate) fn run(job: Job<'_>) {
    match job {
        Job::Ntt(f) => ntt(f),
        Job::NttInverse(f) => ntt_inverse(f),
        Job::MultiplyNtts(f, g, out) => multiply_ntts(f, g, out),
        Job::PolyAdd(a, b) => poly_add(a, b),
        Job::PolySub(a, b, out) => poly_sub(a, b, out),
        Job::KeccakX4(states) => keccak_f1600_x4(states),
    }
}

// Moving data in and out. The pointer loads and stores are unsafe even with
// AVX2 enabled, so values go in lane by lane; the compiler turns these into
// plain vector loads and stores.

#[target_feature(enable = "avx2")]
fn load(a: &[u16; 16]) -> __m256i {
    let e = |i: usize| a[i] as i16;
    _mm256_set_epi16(
        e(15),
        e(14),
        e(13),
        e(12),
        e(11),
        e(10),
        e(9),
        e(8),
        e(7),
        e(6),
        e(5),
        e(4),
        e(3),
        e(2),
        e(1),
        e(0),
    )
}

#[target_feature(enable = "avx2")]
fn store(v: __m256i, out: &mut [u16; 16]) {
    out[0] = _mm256_extract_epi16::<0>(v) as u16;
    out[1] = _mm256_extract_epi16::<1>(v) as u16;
    out[2] = _mm256_extract_epi16::<2>(v) as u16;
    out[3] = _mm256_extract_epi16::<3>(v) as u16;
    out[4] = _mm256_extract_epi16::<4>(v) as u16;
    out[5] = _mm256_extract_epi16::<5>(v) as u16;
    out[6] = _mm256_extract_epi16::<6>(v) as u16;
    out[7] = _mm256_extract_epi16::<7>(v) as u16;
    out[8] = _mm256_extract_epi16::<8>(v) as u16;
    out[9] = _mm256_extract_epi16::<9>(v) as u16;
    out[10] = _mm256_extract_epi16::<10>(v) as u16;
    out[11] = _mm256_extract_epi16::<11>(v) as u16;
    out[12] = _mm256_extract_epi16::<12>(v) as u16;
    out[13] = _mm256_extract_epi16::<13>(v) as u16;
    out[14] = _mm256_extract_epi16::<14>(v) as u16;
    out[15] = _mm256_extract_epi16::<15>(v) as u16;
}

#[target_feature(enable = "avx2")]
fn load_poly(f: &Poly) -> [__m256i; 16] {
    let mut v = [_mm256_setzero_si256(); 16];
    for (o, c) in v.iter_mut().zip(f.as_chunks::<16>().0) {
        *o = load(c);
    }
    v
}

#[target_feature(enable = "avx2")]
fn store_poly(v: &[__m256i; 16], f: &mut Poly) {
    for (c, x) in f.as_chunks_mut::<16>().0.iter_mut().zip(v) {
        store(*x, c);
    }
}

// Arithmetic mod q on 16 lanes of 16 bits. Inputs and outputs are in 0..q.

/// x mod q for x in 0..2q: x - q wraps to at least 2^16 - q > x when x < q,
/// so the unsigned minimum picks the right one without a branch.
#[target_feature(enable = "avx2")]
fn reduce_once(x: __m256i) -> __m256i {
    _mm256_min_epu16(x, _mm256_sub_epi16(x, _mm256_set1_epi16(Q as i16)))
}

#[target_feature(enable = "avx2")]
fn add(a: __m256i, b: __m256i) -> __m256i {
    reduce_once(_mm256_add_epi16(a, b))
}

/// (a + q - b) mod q, as the portable `subq`.
#[target_feature(enable = "avx2")]
fn sub(a: __m256i, b: __m256i) -> __m256i {
    reduce_once(_mm256_add_epi16(
        _mm256_sub_epi16(a, b),
        _mm256_set1_epi16(Q as i16),
    ))
}

/// a * w mod q for a constant w, with wq = quotient_of(w). The estimate
/// floor(a * wq / 2^16) of floor(a * w / q) is low by at most 1, so
/// a*w - estimate*q is in 0..2q and fits 16 bits; it is computed mod 2^16.
#[target_feature(enable = "avx2")]
fn mul_const(a: __m256i, w: __m256i, wq: __m256i) -> __m256i {
    let est = _mm256_mulhi_epu16(a, wq);
    let r = _mm256_sub_epi16(
        _mm256_mullo_epi16(a, w),
        _mm256_mullo_epi16(est, _mm256_set1_epi16(Q as i16)),
    );
    reduce_once(r)
}

#[target_feature(enable = "avx2")]
fn forward_butterfly(a: __m256i, b: __m256i, z: __m256i, zq: __m256i) -> (__m256i, __m256i) {
    let t = mul_const(b, z, zq);
    (add(a, t), sub(a, t))
}

#[target_feature(enable = "avx2")]
fn inverse_butterfly(a: __m256i, b: __m256i, z: __m256i, zq: __m256i) -> (__m256i, __m256i) {
    (add(a, b), mul_const(sub(b, a), z, zq))
}

/// Gathers the 32 coefficients in x, y (in order) into the two halves of
/// each butterfly for layer len (8, 4 or 2): lane k of the first vector
/// pairs with lane k of the second.
#[target_feature(enable = "avx2")]
fn split(len: usize, x: __m256i, y: __m256i) -> (__m256i, __m256i) {
    match len {
        8 => (
            _mm256_permute2x128_si256::<0x20>(x, y),
            _mm256_permute2x128_si256::<0x31>(x, y),
        ),
        4 => (_mm256_unpacklo_epi64(x, y), _mm256_unpackhi_epi64(x, y)),
        _ => {
            // Put the first pair of each four-coefficient block in the low
            // 64 bits of its half, then split as for len 4.
            let xs = _mm256_shuffle_epi32::<0xd8>(x);
            let ys = _mm256_shuffle_epi32::<0xd8>(y);
            (_mm256_unpacklo_epi64(xs, ys), _mm256_unpackhi_epi64(xs, ys))
        }
    }
}

/// Undoes `split`.
#[target_feature(enable = "avx2")]
fn join(len: usize, a: __m256i, b: __m256i) -> (__m256i, __m256i) {
    match len {
        8 => (
            _mm256_permute2x128_si256::<0x20>(a, b),
            _mm256_permute2x128_si256::<0x31>(a, b),
        ),
        4 => (_mm256_unpacklo_epi64(a, b), _mm256_unpackhi_epi64(a, b)),
        _ => (
            _mm256_shuffle_epi32::<0xd8>(_mm256_unpacklo_epi64(a, b)),
            _mm256_shuffle_epi32::<0xd8>(_mm256_unpackhi_epi64(a, b)),
        ),
    }
}

/// Algorithm 9.
#[target_feature(enable = "avx2")]
fn ntt(f: &mut Poly) {
    let mut v = load_poly(f);
    // len = 128, 64, 32, 16: both halves of a butterfly are whole vectors.
    let mut i = 1;
    let mut half = 8; // len / 16
    while half >= 1 {
        let mut start = 0;
        while start < 16 {
            let z = _mm256_set1_epi16(ZETAS[i] as i16);
            let zq = _mm256_set1_epi16(quotient_of(ZETAS[i]) as i16);
            i += 1;
            for j in start..start + half {
                (v[j], v[j + half]) = forward_butterfly(v[j], v[j + half], z, zq);
            }
            start += 2 * half;
        }
        half /= 2;
    }
    // len = 8, 4, 2: 32 coefficients at a time, regrouped in registers.
    for c in 0..8 {
        let (mut x, mut y) = (v[2 * c], v[2 * c + 1]);
        for (len, z, zq) in [
            (8, &FWD_Z8, &FWD_Z8Q),
            (4, &FWD_Z4, &FWD_Z4Q),
            (2, &FWD_Z2, &FWD_Z2Q),
        ] {
            let (a, b) = split(len, x, y);
            let (a, b) = forward_butterfly(a, b, load(&z[c]), load(&zq[c]));
            (x, y) = join(len, a, b);
        }
        (v[2 * c], v[2 * c + 1]) = (x, y);
    }
    store_poly(&v, f);
}

/// Algorithm 10.
#[target_feature(enable = "avx2")]
fn ntt_inverse(f: &mut Poly) {
    let mut v = load_poly(f);
    for c in 0..8 {
        let (mut x, mut y) = (v[2 * c], v[2 * c + 1]);
        for (len, z, zq) in [
            (2, &INV_Z2, &INV_Z2Q),
            (4, &INV_Z4, &INV_Z4Q),
            (8, &INV_Z8, &INV_Z8Q),
        ] {
            let (a, b) = split(len, x, y);
            let (a, b) = inverse_butterfly(a, b, load(&z[c]), load(&zq[c]));
            (x, y) = join(len, a, b);
        }
        (v[2 * c], v[2 * c + 1]) = (x, y);
    }
    let mut i = 15;
    let mut half = 1;
    while half <= 8 {
        let mut start = 0;
        while start < 16 {
            let z = _mm256_set1_epi16(ZETAS[i] as i16);
            let zq = _mm256_set1_epi16(quotient_of(ZETAS[i]) as i16);
            i -= 1;
            for j in start..start + half {
                (v[j], v[j + half]) = inverse_butterfly(v[j], v[j + half], z, zq);
            }
            start += 2 * half;
        }
        half *= 2;
        // The next layer starts at ZETAS[256/len - 1] for the new len.
        i = 16 / half - 1;
    }
    let n = _mm256_set1_epi16(3303);
    let nq = _mm256_set1_epi16(quotient_of(3303) as i16);
    for x in v.iter_mut() {
        *x = mul_const(*x, n, nq);
    }
    store_poly(&v, f);
}

/// x mod q on 8 lanes of 32 bits, for x < 2^25. The estimate
/// floor(floor(x / 2^13) * floor(2^26 / q) / 2^13) of floor(x / q) is never
/// high and is low by at most 3, so three conditional subtractions finish.
#[target_feature(enable = "avx2")]
fn reduce32(x: __m256i) -> __m256i {
    let q = _mm256_set1_epi32(i32::from(Q));
    let t = _mm256_srli_epi32::<13>(x);
    let est = _mm256_srli_epi32::<13>(_mm256_mullo_epi32(
        t,
        _mm256_set1_epi32((1 << 26) / i32::from(Q)),
    ));
    let mut r = _mm256_sub_epi32(x, _mm256_mullo_epi32(est, q));
    for _ in 0..3 {
        r = _mm256_min_epu32(r, _mm256_sub_epi32(r, q));
    }
    r
}

/// Algorithms 11 and 12. Each 32-bit lane holds one pair (a0, a1).
#[target_feature(enable = "avx2")]
fn multiply_ntts(f: &Poly, g: &Poly, out: &mut Poly) {
    let low = _mm256_set1_epi32(0xffff);
    let fc = f.as_chunks::<16>().0;
    let gc = g.as_chunks::<16>().0;
    let oc = out.as_chunks_mut::<16>().0;
    for k in 0..16 {
        let a = load(&fc[k]);
        let b = load(&gc[k]);
        let (a0, a1) = (_mm256_and_si256(a, low), _mm256_srli_epi32::<16>(a));
        let (b0, b1) = (_mm256_and_si256(b, low), _mm256_srli_epi32::<16>(b));
        let gm = |l: usize| i32::from(GAMMAS[8 * k + l]);
        let gamma = _mm256_set_epi32(gm(7), gm(6), gm(5), gm(4), gm(3), gm(2), gm(1), gm(0));
        // Each sum is below 2 * 3328^2 < 2^25.
        let a1b1 = reduce32(_mm256_mullo_epi32(a1, b1));
        let c0 = reduce32(_mm256_add_epi32(
            _mm256_mullo_epi32(a0, b0),
            _mm256_mullo_epi32(a1b1, gamma),
        ));
        let c1 = reduce32(_mm256_add_epi32(
            _mm256_mullo_epi32(a0, b1),
            _mm256_mullo_epi32(a1, b0),
        ));
        store(_mm256_or_si256(c0, _mm256_slli_epi32::<16>(c1)), &mut oc[k]);
    }
}

#[target_feature(enable = "avx2")]
fn poly_add(a: &mut Poly, b: &Poly) {
    for (x, y) in a
        .as_chunks_mut::<16>()
        .0
        .iter_mut()
        .zip(b.as_chunks::<16>().0)
    {
        store(add(load(x), load(y)), x);
    }
}

#[target_feature(enable = "avx2")]
fn poly_sub(a: &Poly, b: &Poly, out: &mut Poly) {
    let pairs = a.as_chunks::<16>().0.iter().zip(b.as_chunks::<16>().0);
    for (o, (x, y)) in out.as_chunks_mut::<16>().0.iter_mut().zip(pairs) {
        store(sub(load(x), load(y)), o);
    }
}

#[target_feature(enable = "avx2")]
fn rotate_left(v: __m256i, n: u32) -> __m256i {
    // A shift by 64 gives 0, so n = 0 leaves v as it is.
    let left = _mm256_sllv_epi64(v, _mm256_set1_epi64x(i64::from(n)));
    let right = _mm256_srlv_epi64(v, _mm256_set1_epi64x(64 - i64::from(n)));
    _mm256_or_si256(left, right)
}

/// Keccak-p[1600, 24] on four states, one per 64-bit lane, step for step as
/// `keccak::keccak_f1600`.
#[target_feature(enable = "avx2")]
fn keccak_f1600_x4(states: &mut [[u64; 25]; 4]) {
    let mut a = [_mm256_setzero_si256(); 25];
    for (w, lane) in a.iter_mut().enumerate() {
        let s = |k: usize| states[k][w] as i64;
        *lane = _mm256_set_epi64x(s(3), s(2), s(1), s(0));
    }
    for rc in ROUND_CONSTANTS {
        // θ
        let mut c = [_mm256_setzero_si256(); 5];
        for x in 0..5 {
            c[x] = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_xor_si256(a[x], a[x + 5]),
                    _mm256_xor_si256(a[x + 10], a[x + 15]),
                ),
                a[x + 20],
            );
        }
        for x in 0..5 {
            let d = _mm256_xor_si256(c[(x + 4) % 5], rotate_left(c[(x + 1) % 5], 1));
            for y in 0..5 {
                a[x + 5 * y] = _mm256_xor_si256(a[x + 5 * y], d);
            }
        }
        // ρ and π
        let mut b = [_mm256_setzero_si256(); 25];
        for x in 0..5 {
            for y in 0..5 {
                let src = (x + 3 * y) % 5 + 5 * x;
                b[x + 5 * y] = rotate_left(a[src], RHO[src]);
            }
        }
        // χ: andnot(p, q) is !p & q.
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = _mm256_xor_si256(
                    b[x + 5 * y],
                    _mm256_andnot_si256(b[(x + 1) % 5 + 5 * y], b[(x + 2) % 5 + 5 * y]),
                );
            }
        }
        // ι
        a[0] = _mm256_xor_si256(a[0], _mm256_set1_epi64x(rc as i64));
    }
    for (w, lane) in a.iter().enumerate() {
        states[0][w] = _mm256_extract_epi64::<0>(*lane) as u64;
        states[1][w] = _mm256_extract_epi64::<1>(*lane) as u64;
        states[2][w] = _mm256_extract_epi64::<2>(*lane) as u64;
        states[3][w] = _mm256_extract_epi64::<3>(*lane) as u64;
    }
}
