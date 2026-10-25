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

- The code tries to avoid secret-dependent branches and lookups, but its timing hasn't been measured.
- Nothing here has been audited. The browser doesn't use this crate for real connections yet.

Version 0.1.0 is current.
