<div align="center">
  <h1>anvil-pqc</h1>
  <p>Post-quantum key exchange: ML-KEM-768, X25519, and the X25519MLKEM768 hybrid.</p>
  <p>
    <img src="https://img.shields.io/badge/release-v.02-e8c37a?style=flat-square" alt="v.02" />
    <img src="https://img.shields.io/badge/status-Proof_of_Concept-d4a359?style=flat-square" alt="Proof of Concept" />
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-PolyForm_Noncommercial_1.0.0_%7C_Paid_Commercial_%28Non--Compete%29-blue?style=flat-square" alt="PolyForm Noncommercial 1.0.0 | Paid Commercial (Non-Compete)" /></a>
    <a href="./SECURITY.md"><img src="https://img.shields.io/badge/security-policy-2ea44f?style=flat-square" alt="Security" /></a>
    <img src="https://img.shields.io/badge/rust-2024-orange?style=flat-square" alt="Rust 2024" />
  </p>
</div>

Version 0.2.0 (`v.02`).

This is the post-quantum and hybrid key-exchange library for Anvil. I wrote it from the specs: NIST FIPS 203 for ML-KEM, FIPS 202 for SHA-3, RFC 7748 for X25519, and draft-ietf-tls-ecdhe-mlkem-03 for the hybrid.

## How the browser uses it

`anvil-net` links this crate alongside `anvil-cipher`:

| Piece | How `anvil-net` uses it |
| --- | --- |
| `mlkem` (ML-KEM-768) | Key generation, encapsulation, and decapsulation inside `pqc_tls13` |
| `x25519` | Classical X25519 shares and fallback shared secret inside `pqc_tls13` |
| `hybrid` (`X25519MLKEM768` shares and secret) | TLS 1.3 `key_share` extension builder/parser, 64-byte combined shared secret, and pre-connection self-test (`verify_pqc_hybrid_self_test`) |
| `keccak` (SHA3-256, SHA3-512, SHAKE128, SHAKE256) | ML-KEM internals, TLS 1.3 transcript hashing (`transcript_sha3_256`), and `sha3-256-` Subresource Integrity checks (`policy::sri_sha3_256_token`) |

For live socket handshakes, Linux uses the system OpenSSL (offering `X25519MLKEM768` first via `SSL_set1_groups_list`) and Windows uses Schannel, while `anvil-net::pqc_tls13` runs the in-house `X25519MLKEM768` + `HKDF-SHA256` + `AES-256-GCM` key-exchange and TLS 1.3 key-schedule self-test before sessions open.

## What it does

- `mlkem`: ML-KEM-768 key generation, encapsulation, and decapsulation (FIPS 203 Algorithms 16 to 21). Keys come in through `EncapsulationKey::from_bytes` and `DecapsulationKey::from_bytes`, which run the section 7 input checks (length and modulus check for the encapsulation key, length and hash check for the decapsulation key). Decapsulation checks the ciphertext length and uses implicit rejection: a ciphertext that doesn't re-encrypt to itself gives `J(z || c)` instead of an error, and the caller can't tell the difference.
- `x25519`: the X25519 function, the public key from a private key, and a shared secret that refuses the all-zero result.
- `hybrid`: the X25519MLKEM768 group for TLS 1.3, codepoint 4588 (0x11EC). See below for exactly what it follows.
- `keccak`: SHA3-256, SHA3-512, SHAKE128, and SHAKE256. ML-KEM needs them and anvil-cipher doesn't have them, so they live here.
- `accel`: on x86_64 CPUs with AVX2, ML-KEM's hot loops run on AVX2, with the portable code as the default and the reference. See below.
- `fill_random` reads `/dev/urandom` on Unix and calls `BCryptGenRandom` (the system's preferred generator) on Windows. Every function that needs randomness also has a version that takes the random bytes from you (`keygen_from_seed`, `encapsulate_with`, `client_share_from_seed`, `server_respond_with`).

## The hybrid, exactly

From draft-ietf-tls-ecdhe-mlkem-03, sections 3 and 4:

- Client key share, 1216 bytes: the ML-KEM-768 encapsulation key (1184), then the X25519 public key (32).
- Server key share, 1120 bytes: the ML-KEM-768 ciphertext (1088), then the X25519 public key (32).
- Shared secret, 64 bytes: the ML-KEM shared secret (32), then the X25519 shared secret (32). ML-KEM goes first for this group, the reverse of the other hybrids in the draft.
- The server runs the FIPS 203 section 7.2 check on the client's encapsulation key. The client checks the ciphertext length. Both sides refuse an all-zero X25519 result. In TLS each of those is an illegal_parameter alert; here it's an `Error`.

The 64-byte secret is the (EC)DHE input to the TLS 1.3 key schedule (`anvil-net::pqc_tls13::Tls13HandshakeKeys`).

## How it was checked

- All 25 ML-KEM-768 key generation cases from NIST's ACVP server, plus encapsulation, decapsulation (including modified ciphertexts that must hit implicit rejection), and both key checks. They're in `tests/data/acvp-mlkem768.txt`, which says where they came from.
- The RFC 7748 X25519 vectors: the two single vectors, the 1 and 1,000 iteration runs, and the section 6.1 key exchange. The 1,000,000 iteration run is there too but ignored by default: `cargo test --release -- --ignored`.
- The NTT constants are worked out at compile time and compared against both tables in FIPS 203 Appendix A. The Keccak constants are worked out from FIPS 202 section 3.2.
- Round trips, implicit rejection, bad keys, and seeded runs of junk input. Junk gives an error or a key, never a panic.
- By hand, outside the tests, against OpenSSL 3.5.7: keys from the same seed are byte-for-byte the same, encapsulation with the same randomness gives the same ciphertext and secret, and ML-KEM-768 and X25519MLKEM768 both work in both directions (OpenSSL encapsulates and this crate decapsulates, and the other way round).

## AVX2

On x86_64 CPUs that have AVX2, these parts of ML-KEM run on AVX2:

- the NTT and its inverse (FIPS 203 Algorithms 9 and 10),
- multiplication in the NTT domain (Algorithms 11 and 12),
- polynomial addition and subtraction,
- sampling the matrix A (Algorithm 7): eight of its nine SHAKE128 streams go four at a time, with four Keccak permutations side by side.

The CPU is checked once at run time and the answer is kept. Without AVX2, on 32-bit x86, and on every other CPU, everything runs on the portable code. That code is the default and the reference: the AVX2 code has to give the same bytes, and the tests check that.

- The tests compare each AVX2 function with its portable twin on boundary cases and tens of thousands of seeded random inputs, including every product a·b mod q in the pair multiplication. The ACVP vectors and seeded runs of the whole API (key generation, encapsulation, decapsulation, the hybrid) run both ways.
- `accel::portable_only(|| ...)` runs a closure with the AVX2 code switched off on that thread. `accel::avx2_active()` says which code the thread is using.
- Not on AVX2: X25519, single Keccak permutations (SHA3-256, SHA3-512, SHAKE256, and so the PRF and the hashes in ML-KEM), the ninth matrix entry, compression, and byte encoding.
- The AVX2 code follows the same rules as the portable code: no branches, divisions, or memory lookups that depend on secret data. Reductions use unsigned minimums, and lane layouts are fixed. A rough two-class timing check on one machine found no difference for either path; that's a smoke test, not a proof.
- Measured on one shared x86_64 virtual machine, release build, median of five runs: key generation about 1.7 times as fast, encapsulation about 1.8, decapsulation about 1.85, and the NTT about 15. Other machines will differ.
- So far it has only been tested on CPUs that have AVX2. The portable path is tested on the same machine with `portable_only`, not on a CPU without AVX2.

## Limits

- Only ML-KEM-768. No ML-KEM-512 or ML-KEM-1024, and no SecP256r1MLKEM768 or SecP384r1MLKEM1024.
- Secret-dependent branches and table lookups are avoided, the ciphertext comparison and key choice in decapsulation use masks, and the X25519 ladder swaps with masks. Nobody has measured the timing, and the compiler is free to undo some of it, so don't treat this as hardened against side channels.
- Secrets are overwritten when dropped, but the compiler may keep copies elsewhere.
- On platforms other than Unix and Windows there is no system random source, and `fill_random` returns `Error::NoRandomness`; use the seeded functions there.
- Not audited.

## Build

```
cargo test
```

Rust 2024 edition, Rust 1.99.1 or newer. No crates.io dependencies. There are two unsafe blocks: the `BCryptGenRandom` call on Windows, in `src/sys_random.rs`, and the call into the AVX2 code in `src/accel.rs`, made right after the CPU check says AVX2 is there. The AVX2 code itself is safe Rust.

## The other repositories

The browser is [anvil-browser](https://github.com/buntatoes/anvil-browser) and the page engine is [anvil-engine](https://github.com/buntatoes/anvil-engine), built alongside the eleven companion libraries below. None of them come from crates.io.

| Repository | What it is |
| --- | --- |
| [anvil-cipher](https://github.com/buntatoes/anvil-cipher) | AES-128, AES-256, CTR, AES-256-GCM, SHA-256, HMAC-SHA256, HKDF-SHA256 |
| [anvil-compress](https://github.com/buntatoes/anvil-compress) | DEFLATE, zlib, gzip |
| [anvil-css](https://github.com/buntatoes/anvil-css) | CSS Syntax Level 3 tokenizer, Selectors Level 4 matcher, and property/media/@supports parser |
| [anvil-hpack](https://github.com/buntatoes/anvil-hpack) | HPACK header compression for HTTP/2 |
| [anvil-image](https://github.com/buntatoes/anvil-image) | PNG, JPEG, GIF, WebP (`VP8L` + `VP8 `), ICO, BMP, PPM |
| [anvil-js](https://github.com/buntatoes/anvil-js) | Self-hosted ES2022+ JavaScript compiler and Core JS Web/DOM runtime for `AnvilVM` |
| [anvil-json](https://github.com/buntatoes/anvil-json) | JSON |
| [anvil-pqc](https://github.com/buntatoes/anvil-pqc) | ML-KEM-768, X25519, X25519MLKEM768, SHA-3 |
| [anvil-ttf](https://github.com/buntatoes/anvil-ttf) | TrueType and OpenType (`glyf`, `CFF `, `kern`, `GPOS`) |
| [anvil-gpu](https://github.com/buntatoes/anvil-gpu) | Compositor passes for boxes, shadows, gradients, and NV12/I420, on the CPU or a GPU |
| [anvil-video](https://github.com/buntatoes/anvil-video) | CPU frames (AVID/ADCT) and PCM/ADPCM/FLAC/MDCT audio in MP4, fMP4, and WebM containers |

## License

Dual-licensed under the **PolyForm Noncommercial License 1.0.0** and a **Paid Commercial License with a Non-Compete Clause**. Copyright (c) 2026 Buntato. See [LICENSE](./LICENSE).
