// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! SHA3-256, SHA3-512, SHAKE128, and SHAKE256, written from FIPS 202.
//!
//! The state is 25 lanes of 64 bits, lane `(x, y)` at index `x + 5y`, with
//! bytes loaded little-endian (FIPS 202 sections 3.1.2 and B.1). The rotation
//! offsets and round constants are worked out from the step definitions in
//! section 3.2 when the crate is compiled, so no table is typed in by hand.

/// Rotation offsets for ρ, from FIPS 202 Algorithm 2.
pub(crate) const RHO: [u32; 25] = {
    let mut out = [0u32; 25];
    let (mut x, mut y) = (1usize, 0usize);
    let mut t = 0usize;
    while t < 24 {
        out[x + 5 * y] = (((t + 1) * (t + 2) / 2) % 64) as u32;
        let next_y = (2 * x + 3 * y) % 5;
        x = y;
        y = next_y;
        t += 1;
    }
    out
};

/// One bit of the round-constant LFSR, FIPS 202 Algorithm 5.
const fn rc(t: usize) -> u64 {
    let steps = t % 255;
    if steps == 0 {
        return 1;
    }
    // R as 8 bits, R[0] in the low bit.
    let mut r: u16 = 1;
    let mut i = 1;
    while i <= steps {
        r <<= 1; // R = 0 || R; the old R[7] is now R[8].
        let r8 = (r >> 8) & 1;
        r ^= r8; // R[0]
        r ^= r8 << 4;
        r ^= r8 << 5;
        r ^= r8 << 6;
        r &= 0xff; // Trunc8
        i += 1;
    }
    (r & 1) as u64
}

/// Round constants for the 24 rounds of Keccak-p[1600, 24], FIPS 202 Algorithm 6.
pub(crate) const ROUND_CONSTANTS: [u64; 24] = {
    let mut out = [0u64; 24];
    let mut ir = 0;
    while ir < 24 {
        let mut lane = 0u64;
        let mut j = 0;
        while j <= 6 {
            lane |= rc(j + 7 * ir) << ((1u32 << j) - 1);
            j += 1;
        }
        out[ir] = lane;
        ir += 1;
    }
    out
};

/// Keccak-p[1600, 24] on a state of 25 lanes.
pub fn keccak_f1600(a: &mut [u64; 25]) {
    for rc in ROUND_CONSTANTS {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // ρ and π together: A'[x, y] = rot(A[(x + 3y) mod 5, x]).
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let src = (x + 3 * y) % 5 + 5 * x;
                b[x + 5 * y] = a[src].rotate_left(RHO[src]);
            }
        }
        // χ
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι
        a[0] ^= rc;
    }
}

/// A Keccak sponge with a byte rate and a domain-separation suffix.
///
/// The suffix holds the domain bits and the first padding bit: `0x06` for
/// SHA-3 (`01` then pad) and `0x1f` for SHAKE (`1111` then pad).
#[derive(Clone)]
pub struct Sponge {
    state: [u64; 25],
    rate: usize,
    suffix: u8,
    pos: usize,
    squeezing: bool,
}

impl Sponge {
    fn new(rate: usize, suffix: u8) -> Self {
        Self {
            state: [0; 25],
            rate,
            suffix,
            pos: 0,
            squeezing: false,
        }
    }

    fn xor_byte(&mut self, i: usize, b: u8) {
        self.state[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    fn byte(&self, i: usize) -> u8 {
        (self.state[i / 8] >> (8 * (i % 8))) as u8
    }

    /// Feed more input. Input after the first squeeze is a programming error
    /// and is ignored.
    pub fn absorb(&mut self, data: &[u8]) {
        if self.squeezing {
            debug_assert!(false, "absorb after squeeze");
            return;
        }
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    fn finish_absorb(&mut self) {
        // pad10*1 with the domain bits in front (FIPS 202 section 5.1 and B.2).
        self.xor_byte(self.pos, self.suffix);
        self.xor_byte(self.rate - 1, 0x80);
        keccak_f1600(&mut self.state);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Write the next `out.len()` output bytes.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.finish_absorb();
        }
        for o in out.iter_mut() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            *o = self.byte(self.pos);
            self.pos += 1;
        }
    }
}

impl Drop for Sponge {
    fn drop(&mut self) {
        // The state can hold key material; clear it.
        self.state = [0; 25];
        std::hint::black_box(&self.state);
    }
}

/// SHAKE128 with incremental absorb and squeeze.
pub fn shake128() -> Sponge {
    Sponge::new(168, 0x1f)
}

/// SHAKE256 with incremental absorb and squeeze.
pub fn shake256() -> Sponge {
    Sponge::new(136, 0x1f)
}

/// SHA3-256 of the concatenation of `parts`.
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Sponge::new(136, 0x06);
    for p in parts {
        s.absorb(p);
    }
    let mut out = [0u8; 32];
    s.squeeze(&mut out);
    out
}

/// SHA3-512 of the concatenation of `parts`.
pub fn sha3_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut s = Sponge::new(72, 0x06);
    for p in parts {
        s.absorb(p);
    }
    let mut out = [0u8; 64];
    s.squeeze(&mut out);
    out
}

/// SHAKE256 of the concatenation of `parts`, `N` bytes out.
pub fn shake256_bytes<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut s = shake256();
    for p in parts {
        s.absorb(p);
    }
    let mut out = [0u8; N];
    s.squeeze(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn derived_constants_have_the_known_shape() {
        // Round 0 constant is 1 and every offset is below 64; lane (0,0) is not rotated.
        assert_eq!(ROUND_CONSTANTS[0], 1);
        assert_eq!(RHO[0], 0);
        assert_eq!(RHO[1], 1);
        assert!(RHO.iter().all(|&r| r < 64));
    }

    #[test]
    fn empty_and_abc_digests() {
        assert_eq!(
            hex(&sha3_256(&[])),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&sha3_256(&[b"abc"])),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(&sha3_512(&[b"abc"])),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        let mut out = [0u8; 32];
        shake128().squeeze(&mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
        assert_eq!(
            hex(&shake256_bytes::<32>(&[])),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn split_input_and_long_output_match_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let whole = sha3_256(&[&data]);
        let parts = sha3_256(&[&data[..135], &data[135..137], &data[137..]]);
        assert_eq!(whole, parts);
        let mut a = shake128();
        a.absorb(&data);
        let mut one = [0u8; 500];
        a.squeeze(&mut one);
        let mut b = shake128();
        b.absorb(&data);
        let mut two = [0u8; 500];
        b.squeeze(&mut two[..3]);
        b.squeeze(&mut two[3..200]);
        b.squeeze(&mut two[200..]);
        assert_eq!(one, two);
    }

    /// The AVX2 four-state permutation against four portable ones.
    #[test]
    fn four_way_permutation_matches_portable() {
        use crate::accel::{self, Job};
        let mut x = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..5_000 {
            let mut states = [[0u64; 25]; 4];
            for s in states.iter_mut() {
                for w in s.iter_mut() {
                    *w = next();
                }
            }
            if round == 0 {
                states = [
                    [0; 25],
                    [u64::MAX; 25],
                    [1; 25],
                    [0x8000_0000_0000_0000; 25],
                ];
            }
            let mut want = states;
            for s in want.iter_mut() {
                keccak_f1600(s);
            }
            if !accel::run(Job::KeccakX4(&mut states)) {
                eprintln!("no AVX2 on this CPU: four-way permutation not checked");
                return;
            }
            assert_eq!(states, want);
        }
    }
}
