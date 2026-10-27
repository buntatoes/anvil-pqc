// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0-OR-Commercial
// Copyright (c) 2026 Buntato
//! The X25519MLKEM768 hybrid group for TLS 1.3, following
//! draft-ietf-tls-ecdhe-mlkem-03 (November 2025), sections 3 and 4.
//!
//! - Named group codepoint 4588 (0x11EC).
//! - Client key_exchange: ML-KEM-768 encapsulation key (1184 bytes), then
//!   the X25519 public key (32 bytes). 1216 bytes.
//! - Server key_exchange: ML-KEM-768 ciphertext (1088 bytes), then the
//!   X25519 public key (32 bytes). 1120 bytes.
//! - Shared secret: ML-KEM shared secret (32 bytes), then the X25519 shared
//!   secret (32 bytes). 64 bytes. The draft notes the ML-KEM part comes
//!   first here, the reverse of the other hybrid groups, for historical
//!   reasons.
//! - The server runs the FIPS 203 section 7.2 encapsulation key check on the
//!   client's key; the client checks the ciphertext length; both refuse an
//!   all-zero X25519 result. Each failure maps to an illegal_parameter alert
//!   in TLS; here it is an [`Error`].
//!
//! The 64-byte secret is what goes into the TLS 1.3 key schedule as the
//! (EC)DHE input. The key schedule itself is not part of this crate.

use crate::mlkem::{
    self, CIPHERTEXT_LEN, DecapsulationKey, ENCAPSULATION_KEY_LEN, EncapsulationKey,
};
use crate::{Error, fill_random, x25519};

/// The TLS NamedGroup codepoint for X25519MLKEM768.
pub const CODEPOINT: u16 = 0x11ec;
/// Bytes in the client's key_exchange value.
pub const CLIENT_SHARE_LEN: usize = ENCAPSULATION_KEY_LEN + 32;
/// Bytes in the server's key_exchange value.
pub const SERVER_SHARE_LEN: usize = CIPHERTEXT_LEN + 32;
/// Bytes in the combined shared secret.
pub const SHARED_SECRET_LEN: usize = 64;

/// What the client keeps between sending its share and reading the server's.
/// Cleared when dropped.
pub struct ClientState {
    mlkem: DecapsulationKey,
    x25519_secret: [u8; 32],
}

impl std::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientState(..)")
    }
}

impl Drop for ClientState {
    fn drop(&mut self) {
        self.x25519_secret = [0; 32];
        std::hint::black_box(&self.x25519_secret);
    }
}

/// Make the client share from a 64-byte ML-KEM seed (d || z) and a 32-byte
/// X25519 private key. Returns the state to keep and the 1216 bytes to send.
pub fn client_share_from_seed(
    mlkem_seed: &[u8; mlkem::SEED_LEN],
    x25519_secret: &[u8; 32],
) -> (ClientState, Vec<u8>) {
    let (ek, dk) = mlkem::keygen_from_seed(mlkem_seed);
    let mut share = Vec::with_capacity(CLIENT_SHARE_LEN);
    share.extend_from_slice(ek.as_bytes());
    share.extend_from_slice(&x25519::public_key(x25519_secret));
    (
        ClientState {
            mlkem: dk,
            x25519_secret: *x25519_secret,
        },
        share,
    )
}

/// Make the client share with fresh system randomness.
pub fn client_share() -> Result<(ClientState, Vec<u8>), Error> {
    let mut seed = [0u8; mlkem::SEED_LEN];
    let mut secret = [0u8; 32];
    fill_random(&mut seed)?;
    fill_random(&mut secret)?;
    let out = client_share_from_seed(&seed, &secret);
    seed = [0; mlkem::SEED_LEN];
    secret = [0; 32];
    std::hint::black_box((&seed, &secret));
    Ok(out)
}

/// The server side, with caller-supplied randomness: the 32-byte ML-KEM
/// encapsulation randomness `m` and the server's X25519 private key.
/// Returns the 1120-byte server share and the 64-byte shared secret.
pub fn server_respond_with(
    client_share: &[u8],
    m: &[u8; 32],
    x25519_secret: &[u8; 32],
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), Error> {
    if client_share.len() != CLIENT_SHARE_LEN {
        return Err(Error::BadLength);
    }
    let (ek_bytes, peer) = client_share.split_at(ENCAPSULATION_KEY_LEN);
    let ek = EncapsulationKey::from_bytes(ek_bytes)?;
    let peer: [u8; 32] = peer.try_into().map_err(|_| Error::BadLength)?;
    let ecdh = x25519::shared_secret(x25519_secret, &peer)?;
    let (ct, kem) = ek.encapsulate_with(m);
    let mut share = Vec::with_capacity(SERVER_SHARE_LEN);
    share.extend_from_slice(&ct);
    share.extend_from_slice(&x25519::public_key(x25519_secret));
    Ok((share, combine(&kem, &ecdh)))
}

/// The server side with fresh system randomness.
pub fn server_respond(client_share: &[u8]) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN]), Error> {
    let mut m = [0u8; 32];
    let mut secret = [0u8; 32];
    fill_random(&mut m)?;
    fill_random(&mut secret)?;
    let out = server_respond_with(client_share, &m, &secret);
    m = [0; 32];
    secret = [0; 32];
    std::hint::black_box((&m, &secret));
    out
}

impl ClientState {
    /// Read the server share and return the 64-byte shared secret.
    pub fn finish(&self, server_share: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], Error> {
        if server_share.len() != SERVER_SHARE_LEN {
            return Err(Error::BadLength);
        }
        let (ct, peer) = server_share.split_at(CIPHERTEXT_LEN);
        let peer: [u8; 32] = peer.try_into().map_err(|_| Error::BadLength)?;
        let ecdh = x25519::shared_secret(&self.x25519_secret, &peer)?;
        let kem = self.mlkem.decapsulate(ct)?;
        Ok(combine(&kem, &ecdh))
    }
}

fn combine(kem: &[u8; 32], ecdh: &[u8; 32]) -> [u8; SHARED_SECRET_LEN] {
    let mut out = [0u8; SHARED_SECRET_LEN];
    out[..32].copy_from_slice(kem);
    out[32..].copy_from_slice(ecdh);
    out
}
