<div align="center">
  <h1>Anvil PQC</h1>
  <p>Post-quantum and hybrid key exchange in Go: ML-KEM-768, X25519, X25519MLKEM768, and SHA-3.</p>
  <p>
    <img src="https://img.shields.io/badge/release-v.03-e8c37a?style=flat-square" alt="v.03" />
    <img src="https://img.shields.io/badge/status-Proof_of_Concept-d4a359?style=flat-square" alt="Proof of Concept" />
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Noncommercial_%28based_on_PolyForm_1.0.0%29_%7C_Paid_Commercial_%28Non--Compete%29-blue?style=flat-square" alt="Noncommercial (based on PolyForm 1.0.0) | Paid Commercial (Non-Compete)" /></a>
    <a href="./SECURITY.md"><img src="https://img.shields.io/badge/security-policy-2ea44f?style=flat-square" alt="Security" /></a>
    <img src="https://img.shields.io/badge/go-1.22%2B-00ADD8?style=flat-square" alt="Go 1.22+" />
  </p>
</div>

Version 0.3.0 (`v.03`).

This is the post-quantum and hybrid key-exchange library for Anvil (`github.com/buntatoes/anvil-pqc`), written from scratch in pure Go from the specs: NIST FIPS 203 for ML-KEM-768, FIPS 202 for SHA-3 / SHAKE, RFC 7748 for X25519, and `draft-ietf-tls-ecdhe-mlkem-03` for the `X25519MLKEM768` TLS 1.3 hybrid.

## How the browser uses it

`anvil-net` drives `anvil-pqc` alongside `anvil-cipher`:

| Piece | How `anvil-net` uses it |
| --- | --- |
| `mlkem.go` (ML-KEM-768) | Key generation, encapsulation, and decapsulation inside `pqc_tls13` |
| `x25519.go` | Classical X25519 shares and fallback shared secret inside `pqc_tls13` |
| `hybrid.go` (`X25519MLKEM768` shares and secret) | TLS 1.3 `key_share` extension builder/parser, 64-byte combined shared secret, and pre-connection self-test (`verify_pqc_hybrid_self_test`) |
| `keccak.go` (SHA3-256, SHA3-512, SHAKE128, SHAKE256) | ML-KEM internals, TLS 1.3 transcript hashing (`transcript_sha3_256`), and `sha3-256-` Subresource Integrity checks (`policy::sri_sha3_256_token`) |

For live socket handshakes, Linux uses the system OpenSSL (offering `X25519MLKEM768` first via `SSL_set1_groups_list`) and Windows uses Schannel, while `anvil-net::pqc_tls13` runs the in-house `X25519MLKEM768` + `HKDF-SHA256` + `AES-256-GCM` key-exchange and TLS 1.3 key-schedule self-test before sessions open.

## What it does

- **ML-KEM-768** (`mlkem.go`): Key generation, encapsulation, and decapsulation (FIPS 203 Algorithms 16 to 21) plus 4-way SHAKE128 matrix expansion (`sampleNTTX4`). Keys come in through `EncapsulationKeyFromBytes` and `DecapsulationKeyFromBytes`, which run the section 7 input checks (length and modulus check for the encapsulation key, length and hash check for the decapsulation key). Decapsulation checks the ciphertext length and uses constant-time implicit rejection: a ciphertext that does not re-encrypt to itself gives `J(z || c)` instead of an error.
- **X25519** (`x25519.go`): Five 51-bit limb arithmetic modulo `2^255 - 19`, constant-time 255-step Montgomery ladder (`X25519`), `X25519PublicKey`, and `X25519SharedSecret` refusing the all-zero small-order output.
- **Hybrid `X25519MLKEM768`** (`hybrid.go`): TLS 1.3 NamedGroup codepoint `0x11EC` (`4588`), 1,216-byte client share (`mlkem768_ek || x25519_pub`), 1,120-byte server share (`mlkem768_ct || x25519_pub`), and 64-byte combined shared secret (`mlkem_ss || x25519_ss`).
- **SHA-3 & SHAKE** (`keccak.go`): `KeccakF1600`, 4-way `KeccakF1600X4`, `SHA3_256`, `SHA3_512`, `SHAKE128Bytes`, `SHAKE256Bytes`, and incremental `Sponge` with constants derived from FIPS 202 Algorithms 2, 5, and 6.
- **CLI & Worker** (`cmd/anvil-pqc`): Provides `--worker` binary protocol IPC and `--self-test` verification for `anvil-browser`.

## How it was checked

- All 25 ML-KEM-768 key generation cases from NIST's ACVP server, plus encapsulation, decapsulation (including modified ciphertexts that must hit implicit rejection), and both key checks (`testdata/acvp-mlkem768.txt`).
- The RFC 7748 X25519 vectors: the two single vectors (including high-bit masking), the 1 and 1,000 iteration runs, the section 6.1 Diffie-Hellman exchange, and small-order point (`0`, `1`, `p`, `p + 1`) rejection.
- The NTT constants are computed at initialization and compared against FIPS 203 Appendix A. The Keccak constants are computed from FIPS 202 section 3.2.

## Build

```sh
go vet ./...
go test -v ./...
go build ./cmd/anvil-pqc
```

Go 1.22 or newer (`CGO_ENABLED=0`). Zero external Go module dependencies.

## The other repositories

The browser is [anvil-browser](https://github.com/buntatoes/anvil-browser) and the page engine is [anvil-engine](https://github.com/buntatoes/anvil-engine), built alongside the nine companion libraries below.

| Repository | What it is |
| --- | --- |
| [anvil-cipher](https://github.com/buntatoes/anvil-cipher) | AES-128, AES-256, CTR, AES-256-GCM, SHA-256, HMAC-SHA256, HKDF-SHA256 |
| [anvil-compress](https://github.com/buntatoes/anvil-compress) | DEFLATE, zlib, gzip (Go) |
| [anvil-hpack](https://github.com/buntatoes/anvil-hpack) | HPACK header compression for HTTP/2 (Go) |
| [anvil-image](https://github.com/buntatoes/anvil-image) | PNG, JPEG, GIF, WebP (`VP8L` + `VP8 `), ICO, BMP, PPM |
| [anvil-json](https://github.com/buntatoes/anvil-json) | JSON & RFC 6901 JSON Pointer (Go) |
| [anvil-pqc](https://github.com/buntatoes/anvil-pqc) | ML-KEM-768, X25519, X25519MLKEM768, SHA-3 (Go) |
| [anvil-ttf](https://github.com/buntatoes/anvil-ttf) | TrueType and OpenType (`glyf`, `CFF `, `kern`, `GPOS`) |
| [anvil-gpu](https://github.com/buntatoes/anvil-gpu) | Compositor passes for boxes, shadows, gradients, and NV12/I420 (Go) |
| [anvil-video](https://github.com/buntatoes/anvil-video) | Opus, VP8, VP9, AV1, AVID/ADCT, and MP4/fMP4/WebM containers (Go) |

## License

Dual-licensed under **noncommercial terms based on the PolyForm Noncommercial License 1.0.0** and a **Paid Commercial License with a Non-Compete Clause**. Copyright (c) 2026 Buntato. See [LICENSE](./LICENSE).
