// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! ML-KEM-768, written from NIST FIPS 203 (August 2024).
//!
//! Section and algorithm numbers in the comments point at FIPS 203. The
//! parameter set is ML-KEM-768 (Table 2): k = 3, eta1 = eta2 = 2, du = 10,
//! dv = 4. Key and ciphertext sizes follow Table 3.
//!
//! Work on secret data avoids branches and table lookups that depend on the
//! secret. Reductions use `%` by the constant q, which compiles to a multiply
//! and shift rather than a division instruction on the targets we build for.
//! The ciphertext comparison in decapsulation and the choice between the real
//! and the rejection key are done with masks, not `if`.

use crate::keccak::{sha3_256, sha3_512, shake128, shake256_bytes};
use crate::{Error, ct_eq, ct_select};

const N: usize = 256;
const Q: u32 = 3329;
const K: usize = 3;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 10;
const DV: usize = 4;

/// Bytes in an encapsulation key: 384k + 32.
pub const ENCAPSULATION_KEY_LEN: usize = 384 * K + 32;
/// Bytes in a decapsulation key: 768k + 96.
pub const DECAPSULATION_KEY_LEN: usize = 768 * K + 96;
/// Bytes in a ciphertext: 32(du k + dv).
pub const CIPHERTEXT_LEN: usize = 32 * (DU * K + DV);
/// Bytes in the shared secret.
pub const SHARED_SECRET_LEN: usize = 32;
/// Bytes in a key-generation seed: d followed by z.
pub const SEED_LEN: usize = 64;

const DK_PKE_LEN: usize = 384 * K;

type Poly = [u16; N];

/// BitRev7 from section 2.3.
const fn bitrev7(i: usize) -> usize {
    let mut r = 0;
    let mut b = 0;
    while b < 7 {
        r |= ((i >> b) & 1) << (6 - b);
        b += 1;
    }
    r
}

const fn pow_mod(base: u32, mut exp: usize) -> u32 {
    let mut result = 1u32;
    let mut b = base % Q;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * b % Q;
        }
        b = b * b % Q;
        exp >>= 1;
    }
    result
}

/// ζ^BitRev7(i) mod q with ζ = 17, used by Algorithms 9 and 10 (Appendix A).
const ZETAS: [u16; 128] = {
    let mut out = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = pow_mod(17, bitrev7(i)) as u16;
        i += 1;
    }
    out
};

/// ζ^(2 BitRev7(i) + 1) mod q, used by Algorithm 11 (Appendix A).
const GAMMAS: [u16; 128] = {
    let mut out = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = pow_mod(17, 2 * bitrev7(i) + 1) as u16;
        i += 1;
    }
    out
};

fn mulq(a: u16, b: u16) -> u16 {
    ((u32::from(a) * u32::from(b)) % Q) as u16
}

fn addq(a: u16, b: u16) -> u16 {
    ((u32::from(a) + u32::from(b)) % Q) as u16
}

fn subq(a: u16, b: u16) -> u16 {
    ((u32::from(a) + Q - u32::from(b)) % Q) as u16
}

/// Algorithm 9.
fn ntt(f: &mut Poly) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i += 1;
            for j in start..start + len {
                let t = mulq(zeta, f[j + len]);
                f[j + len] = subq(f[j], t);
                f[j] = addq(f[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Algorithm 10.
fn ntt_inverse(f: &mut Poly) {
    let mut i = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[i];
            i -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = addq(t, f[j + len]);
                f[j + len] = mulq(zeta, subq(f[j + len], t));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = mulq(*c, 3303);
    }
}

/// Algorithms 11 and 12.
fn multiply_ntts(f: &Poly, g: &Poly) -> Poly {
    let mut h = [0u16; N];
    for i in 0..128 {
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
        h[2 * i] = addq(mulq(a0, b0), mulq(mulq(a1, b1), GAMMAS[i]));
        h[2 * i + 1] = addq(mulq(a0, b1), mulq(a1, b0));
    }
    h
}

fn poly_add(a: &mut Poly, b: &Poly) {
    for (x, y) in a.iter_mut().zip(b) {
        *x = addq(*x, *y);
    }
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0u16; N];
    for i in 0..N {
        out[i] = subq(a[i], b[i]);
    }
    out
}

/// Compress_d, equation 4.7: round(2^d x / q) mod 2^d.
fn compress(x: u16, d: usize) -> u16 {
    // q is odd, so adding floor(q/2) before the floor division rounds to the
    // nearest integer with no tie to break.
    let scaled = (u32::from(x) << d) + Q / 2;
    ((scaled / Q) & ((1 << d) - 1)) as u16
}

/// Decompress_d, equation 4.8: round(q y / 2^d), halves rounded up.
fn decompress(y: u16, d: usize) -> u16 {
    ((Q * u32::from(y) + (1 << (d - 1))) >> d) as u16
}

/// Algorithm 5, ByteEncode_d, appending 32d bytes to `out`.
fn byte_encode(f: &Poly, d: usize, out: &mut Vec<u8>) {
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in f {
        acc |= u32::from(c) << bits;
        bits += d;
        while bits >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// Algorithm 6, ByteDecode_d, reading exactly 32d bytes. For d = 12 every
/// value is reduced mod q, as the algorithm says.
fn byte_decode(bytes: &[u8], d: usize) -> Poly {
    debug_assert_eq!(bytes.len(), 32 * d);
    let mut f = [0u16; N];
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut idx = 0;
    let mask = (1u32 << d) - 1;
    for c in f.iter_mut() {
        while bits < d {
            acc |= u32::from(bytes[idx]) << bits;
            idx += 1;
            bits += 8;
        }
        let v = acc & mask;
        acc >>= d;
        bits -= d;
        *c = if d == 12 { (v % Q) as u16 } else { v as u16 };
    }
    f
}

/// Algorithm 7, SampleNTT. Its input is public (the seed rho), so the
/// rejection loop may branch freely.
fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly {
    let mut xof = shake128();
    xof.absorb(rho);
    xof.absorb(&[j, i]);
    let mut a = [0u16; N];
    let mut count = 0;
    let mut buf = [0u8; 168];
    while count < N {
        xof.squeeze(&mut buf);
        // Three bytes give two 12-bit candidates; 168 is a multiple of 3.
        for start in (0..buf.len()).step_by(3) {
            let c = &buf[start..start + 3];
            let d1 = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
            let d2 = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
            if u32::from(d1) < Q && count < N {
                a[count] = d1;
                count += 1;
            }
            if u32::from(d2) < Q && count < N {
                a[count] = d2;
                count += 1;
            }
        }
    }
    a
}

/// Algorithm 8, SamplePolyCBD_eta, for eta = 2 (64 * eta = 128 bytes in).
fn sample_poly_cbd(bytes: &[u8]) -> Poly {
    debug_assert_eq!(bytes.len(), 64 * 2);
    let mut f = [0u16; N];
    // With eta = 2, each byte holds the four bits for two coefficients.
    for (i, &b) in bytes.iter().enumerate() {
        for half in 0..2 {
            let nib = u32::from(b >> (4 * half));
            let x = (nib & 1) + ((nib >> 1) & 1);
            let y = ((nib >> 2) & 1) + ((nib >> 3) & 1);
            f[2 * i + half] = ((x + Q - y) % Q) as u16;
        }
    }
    f
}

/// PRF_eta(s, b) from equation 4.3, for eta = 2.
fn prf_eta2(s: &[u8; 32], b: u8) -> [u8; 128] {
    shake256_bytes::<128>(&[s, &[b]])
}

fn expand_matrix(rho: &[u8; 32]) -> [[Poly; K]; K] {
    let mut a = [[[0u16; N]; K]; K];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            *entry = sample_ntt(rho, j as u8, i as u8);
        }
    }
    a
}

/// Algorithm 13, K-PKE.KeyGen. Returns (ek_PKE, dk_PKE).
fn kpke_keygen(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let g = sha3_512(&[d, &[K as u8]]);
    let rho: [u8; 32] = g[..32].try_into().expect("32 bytes");
    let sigma: [u8; 32] = g[32..].try_into().expect("32 bytes");
    let a = expand_matrix(&rho);
    let mut n = 0u8;
    let mut s = [[0u16; N]; K];
    for p in s.iter_mut() {
        debug_assert_eq!(ETA1, 2);
        *p = sample_poly_cbd(&prf_eta2(&sigma, n));
        n += 1;
    }
    let mut e = [[0u16; N]; K];
    for p in e.iter_mut() {
        *p = sample_poly_cbd(&prf_eta2(&sigma, n));
        n += 1;
    }
    for p in s.iter_mut().chain(e.iter_mut()) {
        ntt(p);
    }
    let mut ek = Vec::with_capacity(ENCAPSULATION_KEY_LEN);
    for i in 0..K {
        let mut t = e[i];
        for (j, sj) in s.iter().enumerate() {
            poly_add(&mut t, &multiply_ntts(&a[i][j], sj));
        }
        byte_encode(&t, 12, &mut ek);
    }
    ek.extend_from_slice(&rho);
    let mut dk = Vec::with_capacity(DK_PKE_LEN);
    for p in &s {
        byte_encode(p, 12, &mut dk);
    }
    for p in s.iter_mut() {
        *p = [0; N];
    }
    std::hint::black_box(&s);
    (ek, dk)
}

/// Algorithm 14, K-PKE.Encrypt. `ek` must already have passed the length check.
fn kpke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let mut t = [[0u16; N]; K];
    for (i, p) in t.iter_mut().enumerate() {
        *p = byte_decode(&ek[384 * i..384 * (i + 1)], 12);
    }
    let rho: [u8; 32] = ek[384 * K..].try_into().expect("32 bytes");
    let a = expand_matrix(&rho);
    let mut n = 0u8;
    let mut y = [[0u16; N]; K];
    for p in y.iter_mut() {
        debug_assert_eq!(ETA1, 2);
        *p = sample_poly_cbd(&prf_eta2(r, n));
        n += 1;
    }
    let mut e1 = [[0u16; N]; K];
    for p in e1.iter_mut() {
        debug_assert_eq!(ETA2, 2);
        *p = sample_poly_cbd(&prf_eta2(r, n));
        n += 1;
    }
    let e2 = sample_poly_cbd(&prf_eta2(r, n));
    for p in y.iter_mut() {
        ntt(p);
    }
    let mut c = Vec::with_capacity(CIPHERTEXT_LEN);
    // u = NTT^-1(A^T ∘ y) + e1
    for (i, e1i) in e1.iter().enumerate() {
        let mut u = [0u16; N];
        for (j, yj) in y.iter().enumerate() {
            poly_add(&mut u, &multiply_ntts(&a[j][i], yj));
        }
        ntt_inverse(&mut u);
        poly_add(&mut u, e1i);
        let mut comp = [0u16; N];
        for (o, &x) in comp.iter_mut().zip(&u) {
            *o = compress(x, DU);
        }
        byte_encode(&comp, DU, &mut c);
    }
    // v = NTT^-1(t^T ∘ y) + e2 + mu
    let mut v = [0u16; N];
    for j in 0..K {
        poly_add(&mut v, &multiply_ntts(&t[j], &y[j]));
    }
    ntt_inverse(&mut v);
    poly_add(&mut v, &e2);
    let mut mu = byte_decode(m, 1);
    for x in mu.iter_mut() {
        *x = decompress(*x, 1);
    }
    poly_add(&mut v, &mu);
    let mut comp = [0u16; N];
    for (o, &x) in comp.iter_mut().zip(&v) {
        *o = compress(x, DV);
    }
    byte_encode(&comp, DV, &mut c);
    c
}

/// Algorithm 15, K-PKE.Decrypt. `c` must be CIPHERTEXT_LEN bytes.
fn kpke_decrypt(dk_pke: &[u8], c: &[u8]) -> [u8; 32] {
    let c1 = &c[..32 * DU * K];
    let c2 = &c[32 * DU * K..];
    let mut w_acc = [0u16; N];
    for i in 0..K {
        let mut u = byte_decode(&c1[32 * DU * i..32 * DU * (i + 1)], DU);
        for x in u.iter_mut() {
            *x = decompress(*x, DU);
        }
        ntt(&mut u);
        let s = byte_decode(&dk_pke[384 * i..384 * (i + 1)], 12);
        poly_add(&mut w_acc, &multiply_ntts(&s, &u));
    }
    ntt_inverse(&mut w_acc);
    let mut v = byte_decode(c2, DV);
    for x in v.iter_mut() {
        *x = decompress(*x, DV);
    }
    let w = poly_sub(&v, &w_acc);
    let mut bits = [0u16; N];
    for (o, &x) in bits.iter_mut().zip(&w) {
        *o = compress(x, 1);
    }
    let mut m = Vec::with_capacity(32);
    byte_encode(&bits, 1, &mut m);
    m.try_into().expect("32 bytes")
}

/// A checked ML-KEM-768 encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct EncapsulationKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncapsulationKey({} bytes)", self.bytes.len())
    }
}

impl EncapsulationKey {
    /// Run the encapsulation key check from section 7.2: the type (length)
    /// check, then the modulus check, ByteEncode12(ByteDecode12(ek)) == ek.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ENCAPSULATION_KEY_LEN {
            return Err(Error::BadLength);
        }
        let mut test = Vec::with_capacity(DK_PKE_LEN);
        for i in 0..K {
            byte_encode(
                &byte_decode(&bytes[384 * i..384 * (i + 1)], 12),
                12,
                &mut test,
            );
        }
        if test[..] != bytes[..DK_PKE_LEN] {
            return Err(Error::BadEncapsulationKey);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// The 1184-byte encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Algorithm 17, ML-KEM.Encaps_internal, with the caller's 32 random
    /// bytes `m`. Use [`EncapsulationKey::encapsulate`] unless you need a
    /// repeatable result for a test.
    pub fn encapsulate_with(&self, m: &[u8; 32]) -> (Vec<u8>, [u8; SHARED_SECRET_LEN]) {
        let h = sha3_256(&[&self.bytes]);
        let g = sha3_512(&[m, &h]);
        let key: [u8; 32] = g[..32].try_into().expect("32 bytes");
        let r: [u8; 32] = g[32..].try_into().expect("32 bytes");
        (kpke_encrypt(&self.bytes, m, &r), key)
    }

    /// Algorithm 20, ML-KEM.Encaps, with randomness from the system.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), Error> {
        let mut m = [0u8; 32];
        crate::fill_random(&mut m)?;
        let out = self.encapsulate_with(&m);
        m = [0; 32];
        std::hint::black_box(&m);
        Ok(out)
    }
}

/// A checked ML-KEM-768 decapsulation key. Cleared when dropped.
#[derive(Clone)]
pub struct DecapsulationKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecapsulationKey(..)")
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        self.bytes.iter_mut().for_each(|b| *b = 0);
        std::hint::black_box(&self.bytes);
    }
}

impl DecapsulationKey {
    /// Run the decapsulation key checks from section 7.3: the type (length)
    /// check and the hash check H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != DECAPSULATION_KEY_LEN {
            return Err(Error::BadLength);
        }
        let test = sha3_256(&[&bytes[384 * K..768 * K + 32]]);
        if !ct_eq(&test, &bytes[768 * K + 32..768 * K + 64]) {
            return Err(Error::BadDecapsulationKey);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// The 2400-byte encoding. Treat it as secret.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The matching encapsulation key, read out of the decapsulation key.
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey {
            bytes: self.bytes[384 * K..768 * K + 32].to_vec(),
        }
    }

    /// Algorithms 21 and 18. A ciphertext of the wrong length is an error
    /// (the ciphertext type check in section 7.3). Any ciphertext of the right
    /// length gives a key: the real one if it re-encrypts to itself, and
    /// J(z || c) if not (implicit rejection). The caller cannot tell which.
    pub fn decapsulate(&self, c: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], Error> {
        if c.len() != CIPHERTEXT_LEN {
            return Err(Error::BadLength);
        }
        let dk_pke = &self.bytes[..DK_PKE_LEN];
        let ek_pke = &self.bytes[384 * K..768 * K + 32];
        let h = &self.bytes[768 * K + 32..768 * K + 64];
        let z = &self.bytes[768 * K + 64..];
        let mut m = kpke_decrypt(dk_pke, c);
        let g = sha3_512(&[&m, h]);
        let mut key: [u8; 32] = g[..32].try_into().expect("32 bytes");
        let r: [u8; 32] = g[32..].try_into().expect("32 bytes");
        let reject = shake256_bytes::<32>(&[z, c]);
        let c2 = kpke_encrypt(ek_pke, &m, &r);
        let same = ct_eq(c, &c2);
        ct_select(&mut key, &reject, !same);
        m = [0; 32];
        std::hint::black_box(&m);
        Ok(key)
    }
}

/// Algorithm 16, ML-KEM.KeyGen_internal, from a 64-byte seed d || z.
pub fn keygen_from_seed(seed: &[u8; SEED_LEN]) -> (EncapsulationKey, DecapsulationKey) {
    let d: [u8; 32] = seed[..32].try_into().expect("32 bytes");
    let z = &seed[32..];
    let (ek, dk_pke) = kpke_keygen(&d);
    let h = sha3_256(&[&ek]);
    let mut dk = Vec::with_capacity(DECAPSULATION_KEY_LEN);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h);
    dk.extend_from_slice(z);
    (
        EncapsulationKey { bytes: ek },
        DecapsulationKey { bytes: dk },
    )
}

/// Algorithm 19, ML-KEM.KeyGen, with randomness from the system.
pub fn keygen() -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    let mut seed = [0u8; SEED_LEN];
    crate::fill_random(&mut seed)?;
    let out = keygen_from_seed(&seed);
    seed = [0; SEED_LEN];
    std::hint::black_box(&seed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Appendix A, first table: zeta^BitRev7(i) mod q.
    const APPENDIX_A_ZETAS: [u16; 128] = [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
        296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
        289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
        17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
        1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
        2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885,
        2154,
    ];

    /// Appendix A, second table: zeta^(2 BitRev7(i) + 1) mod q, printed
    /// there as signed values.
    const APPENDIX_A_GAMMAS: [i16; 128] = [
        17, -17, 2761, -2761, 583, -583, 2649, -2649, 1637, -1637, 723, -723, 2288, -2288, 1100,
        -1100, 1409, -1409, 2662, -2662, 3281, -3281, 233, -233, 756, -756, 2156, -2156, 3015,
        -3015, 3050, -3050, 1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789, 1847, -1847, 952,
        -952, 1461, -1461, 2687, -2687, 939, -939, 2308, -2308, 2437, -2437, 2388, -2388, 733,
        -733, 2337, -2337, 268, -268, 641, -641, 1584, -1584, 2298, -2298, 2037, -2037, 3220,
        -3220, 375, -375, 2549, -2549, 2090, -2090, 1645, -1645, 1063, -1063, 319, -319, 2773,
        -2773, 757, -757, 2099, -2099, 561, -561, 2466, -2466, 2594, -2594, 2804, -2804, 1092,
        -1092, 403, -403, 1026, -1026, 1143, -1143, 2150, -2150, 2775, -2775, 886, -886, 1722,
        -1722, 1212, -1212, 1874, -1874, 1029, -1029, 2110, -2110, 2935, -2935, 885, -885, 2154,
        -2154,
    ];

    #[test]
    fn computed_zetas_match_appendix_a() {
        assert_eq!(ZETAS, APPENDIX_A_ZETAS);
        for (got, want) in GAMMAS.iter().zip(APPENDIX_A_GAMMAS) {
            assert_eq!(i32::from(*got), i32::from(want).rem_euclid(Q as i32));
        }
    }

    #[test]
    fn ntt_round_trips() {
        let mut f = [0u16; N];
        for (i, c) in f.iter_mut().enumerate() {
            *c = ((i * 37 + 11) as u32 % Q) as u16;
        }
        let orig = f;
        ntt(&mut f);
        ntt_inverse(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook() {
        let mut a = [0u16; N];
        let mut b = [0u16; N];
        for i in 0..N {
            a[i] = ((i * 7 + 3) as u32 % Q) as u16;
            b[i] = ((i * i + 5) as u32 % Q) as u16;
        }
        // Multiply in Z_q[X]/(X^256 + 1) directly.
        let mut want = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let p = i64::from(a[i]) * i64::from(b[j]);
                if i + j < N {
                    want[i + j] += p;
                } else {
                    want[i + j - N] -= p;
                }
            }
        }
        let want: Vec<u16> = want
            .iter()
            .map(|&x| x.rem_euclid(Q as i64) as u16)
            .collect();
        let (mut fa, mut fb) = (a, b);
        ntt(&mut fa);
        ntt(&mut fb);
        let mut got = multiply_ntts(&fa, &fb);
        ntt_inverse(&mut got);
        assert_eq!(&got[..], &want[..]);
    }

    #[test]
    fn compress_and_decompress_follow_section_4_2_1() {
        for d in [1, 4, 10] {
            for y in 0..(1u16 << d) {
                assert_eq!(compress(decompress(y, d), d), y);
            }
            for x in 0..Q as u16 {
                // Compare against exact rational rounding.
                let want =
                    ((2 * (u64::from(x) << d) + u64::from(Q)) / (2 * u64::from(Q))) % (1u64 << d);
                assert_eq!(u64::from(compress(x, d)), want);
            }
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        for d in [1usize, 4, 10, 12] {
            let mut f = [0u16; N];
            for (i, c) in f.iter_mut().enumerate() {
                *c = ((i * 977 + 13) % (if d == 12 { Q as usize } else { 1 << d })) as u16;
            }
            let mut b = Vec::new();
            byte_encode(&f, d, &mut b);
            assert_eq!(b.len(), 32 * d);
            assert_eq!(byte_decode(&b, d), f);
        }
    }
}
