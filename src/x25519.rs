// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! X25519, written from RFC 7748 section 5.
//!
//! Field elements mod p = 2^255 - 19 are held as five 51-bit limbs. The
//! Montgomery ladder runs a fixed 255 steps and swaps with a mask (the
//! constant-time cswap of section 5), so its timing does not depend on the
//! scalar.

use crate::Error;

const MASK: u64 = (1 << 51) - 1;

type Fe = [u64; 5];

/// The u-coordinate of the base point, 9.
pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

fn weak_carry(mut h: [u64; 5]) -> Fe {
    for _ in 0..2 {
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= MASK;
        }
        h[0] += 19 * (h[4] >> 51);
        h[4] &= MASK;
    }
    h
}

fn decode_u(b: &[u8; 32]) -> Fe {
    let w = |i: usize| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes"));
    // Section 5: mask the top bit of the last byte. Values from p to 2^255 - 1
    // are accepted and reduced by the arithmetic.
    let (w0, w1, w2, w3) = (w(0), w(1), w(2), w(3) & 0x7fff_ffff_ffff_ffff);
    [
        w0 & MASK,
        ((w0 >> 51) | (w1 << 13)) & MASK,
        ((w1 >> 38) | (w2 << 26)) & MASK,
        ((w2 >> 25) | (w3 << 39)) & MASK,
        (w3 >> 12) & MASK,
    ]
}

fn encode(h: &Fe) -> [u8; 32] {
    let h = weak_carry(*h);
    // h is now below 2^255. Subtract p once if h >= p: h >= p exactly when
    // h + 19 reaches 2^255.
    let mut t = h;
    t[0] += 19;
    for i in 0..4 {
        t[i + 1] += t[i] >> 51;
        t[i] &= MASK;
    }
    let ge_p = t[4] >> 51; // 1 if h >= p
    t[4] &= MASK;
    let mask = 0u64.wrapping_sub(ge_p);
    let mut r = [0u64; 5];
    for i in 0..5 {
        r[i] = (t[i] & mask) | (h[i] & !mask);
    }
    let words = [
        r[0] | (r[1] << 51),
        (r[1] >> 13) | (r[2] << 38),
        (r[2] >> 26) | (r[3] << 25),
        (r[3] >> 39) | (r[4] << 12),
    ];
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn add(a: &Fe, b: &Fe) -> Fe {
    weak_carry([
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ])
}

fn sub(a: &Fe, b: &Fe) -> Fe {
    // Add 2p first so no limb goes negative; inputs are weakly reduced.
    const TWO_P0: u64 = 2 * ((1 << 51) - 19);
    const TWO_P: u64 = 2 * ((1 << 51) - 1);
    weak_carry([
        a[0] + TWO_P0 - b[0],
        a[1] + TWO_P - b[1],
        a[2] + TWO_P - b[2],
        a[3] + TWO_P - b[3],
        a[4] + TWO_P - b[4],
    ])
}

fn carry_wide(r: [u128; 5]) -> Fe {
    let mut r = r;
    for i in 0..4 {
        r[i + 1] += r[i] >> 51;
        r[i] &= u128::from(MASK);
    }
    let c = r[4] >> 51;
    r[4] &= u128::from(MASK);
    r[0] += 19 * c;
    weak_carry([
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
    ])
}

fn mul(a: &Fe, b: &Fe) -> Fe {
    let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
    let b19 = [b[0], 19 * b[1], 19 * b[2], 19 * b[3], 19 * b[4]];
    carry_wide([
        m(a[0], b[0]) + m(a[1], b19[4]) + m(a[2], b19[3]) + m(a[3], b19[2]) + m(a[4], b19[1]),
        m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[4]) + m(a[3], b19[3]) + m(a[4], b19[2]),
        m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b19[4]) + m(a[4], b19[3]),
        m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[4]),
        m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
    ])
}

fn square(a: &Fe) -> Fe {
    mul(a, a)
}

fn mul_small(a: &Fe, k: u64) -> Fe {
    let m = |x: u64| u128::from(x) * u128::from(k);
    carry_wide([m(a[0]), m(a[1]), m(a[2]), m(a[3]), m(a[4])])
}

/// z^(p - 2), which is 1/z for nonzero z and 0 for zero. The exponent is a
/// public constant, so branching on its bits is fine.
fn invert(z: &Fe) -> Fe {
    let mut exp = [0xffu8; 32];
    exp[0] = 0xeb; // p - 2 = 2^255 - 21
    exp[31] = 0x7f;
    let mut result: Fe = [1, 0, 0, 0, 0];
    for bit in (0..255).rev() {
        result = square(&result);
        if (exp[bit / 8] >> (bit % 8)) & 1 == 1 {
            result = mul(&result, z);
        }
    }
    result
}

fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// The X25519 function from RFC 7748 section 5: scalar multiplication of the
/// u-coordinate `u` by the clamped `scalar`.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = decode_u(u);
    let mut x2: Fe = [1, 0, 0, 0, 0];
    let mut z2: Fe = [0; 5];
    let mut x3 = x1;
    let mut z3: Fe = [1, 0, 0, 0, 0];
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;

        let a = add(&x2, &z2);
        let aa = square(&a);
        let b = sub(&x2, &z2);
        let bb = square(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = square(&add(&da, &cb));
        z3 = mul(&x1, &square(&sub(&da, &cb)));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&aa, &mul_small(&e, 121665)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    k = [0; 32];
    std::hint::black_box(&k);
    encode(&mul(&x2, &invert(&z2)))
}

/// The public key for a 32-byte private key: X25519(secret, 9).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASEPOINT)
}

/// The shared secret X25519(secret, peer), refusing the all-zero result as
/// RFC 7748 section 6.1 allows (the peer sent a small-order point). The zero
/// test ORs every byte together rather than stopping early.
pub fn shared_secret(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], Error> {
    let k = x25519(secret, peer);
    let acc = k.iter().fold(0u8, |acc, &b| acc | b);
    if std::hint::black_box(acc) == 0 {
        return Err(Error::ZeroSharedSecret);
    }
    Ok(k)
}
