# Security

Report problems in private:

https://github.com/buntatoes/anvil-pqc/security/advisories/new

The browser repository takes the same kind of report:

https://github.com/buntatoes/anvil-browser/security/advisories/new

Do not put the details in a public issue.

## What is checked

- Encapsulation keys get the FIPS 203 section 7.2 length and modulus checks before use.
- Decapsulation keys get the section 7.3 length and hash checks before use.
- A ciphertext of the wrong length is an error. A ciphertext of the right length that doesn't re-encrypt to itself gives the implicit-rejection key, chosen with a mask, not a branch.
- X25519 refuses an all-zero shared secret, so small-order points from a peer are rejected.
- Hybrid shares of the wrong length are errors.
- Junk input of any length gives an error or a key, never a panic.

## What isn't

- The code tries to avoid secret-dependent branches and lookups, on the portable and the AVX2 path alike. Its timing has only had a rough two-class check on one machine, which is not a proof.
- The AVX2 code is only used on x86_64 CPUs that report AVX2. It has only been tested on such CPUs; elsewhere the portable code runs.
- Nothing here has been audited. `anvil-net` links this crate for `pqc_tls13` (`X25519MLKEM768` hybrid key shares, TLS 1.3 key-schedule self-testing, and `sha3-256-` Subresource Integrity checks).

Version 0.1.2 is current.
