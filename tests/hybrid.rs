// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0-OR-Commercial
// Copyright (c) 2026 Buntato
//! X25519MLKEM768 layout and behavior, per draft-ietf-tls-ecdhe-mlkem-03.

use anvil_pqc::Error;
use anvil_pqc::hybrid::{
    CLIENT_SHARE_LEN, CODEPOINT, SERVER_SHARE_LEN, client_share, client_share_from_seed,
    server_respond, server_respond_with,
};
use anvil_pqc::{mlkem, x25519};

const SEED: [u8; 64] = [0x5a; 64];
const CLIENT_X: [u8; 32] = [0x11; 32];
const SERVER_X: [u8; 32] = [0x22; 32];
const M: [u8; 32] = [0x33; 32];

#[test]
fn codepoint_and_sizes() {
    assert_eq!(CODEPOINT, 4588);
    assert_eq!(CLIENT_SHARE_LEN, 1216);
    assert_eq!(SERVER_SHARE_LEN, 1120);
}

#[test]
fn shares_and_secret_are_concatenated_in_draft_order() {
    let (state, share) = client_share_from_seed(&SEED, &CLIENT_X);
    let (ek, dk) = mlkem::keygen_from_seed(&SEED);
    // Client share: ML-KEM encapsulation key first, then X25519.
    assert_eq!(&share[..1184], ek.as_bytes());
    assert_eq!(&share[1184..], &x25519::public_key(&CLIENT_X));

    let (server, secret) = server_respond_with(&share, &M, &SERVER_X).expect("server");
    let (ct, kem) = ek.encapsulate_with(&M);
    // Server share: ciphertext first, then X25519.
    assert_eq!(&server[..1088], &ct[..]);
    assert_eq!(&server[1088..], &x25519::public_key(&SERVER_X));
    // Secret: ML-KEM part first, then X25519.
    let ecdh = x25519::shared_secret(&SERVER_X, &x25519::public_key(&CLIENT_X)).expect("ecdh");
    assert_eq!(&secret[..32], &kem);
    assert_eq!(&secret[32..], &ecdh);
    assert_eq!(dk.decapsulate(&ct), Ok(kem));

    assert_eq!(state.finish(&server), Ok(secret));
}

#[test]
fn random_round_trip() {
    let (state, share) = client_share().expect("client");
    let (server, secret) = server_respond(&share).expect("server");
    assert_eq!(state.finish(&server), Ok(secret));
}

#[test]
fn server_refuses_bad_client_shares() {
    let (_, share) = client_share_from_seed(&SEED, &CLIENT_X);
    assert_eq!(
        server_respond_with(&share[..1215], &M, &SERVER_X).unwrap_err(),
        Error::BadLength
    );
    let mut bad = share.clone();
    bad[0] = 0xff;
    bad[1] = 0xff; // first coefficient 4095
    assert_eq!(
        server_respond_with(&bad, &M, &SERVER_X).unwrap_err(),
        Error::BadEncapsulationKey
    );
    let mut zero_x = share.clone();
    zero_x[1184..].fill(0);
    assert_eq!(
        server_respond_with(&zero_x, &M, &SERVER_X).unwrap_err(),
        Error::ZeroSharedSecret
    );
}

#[test]
fn client_refuses_bad_server_shares() {
    let (state, share) = client_share_from_seed(&SEED, &CLIENT_X);
    let (server, secret) = server_respond_with(&share, &M, &SERVER_X).expect("server");
    assert_eq!(state.finish(&server[..1119]).unwrap_err(), Error::BadLength);
    let mut zero_x = server.clone();
    zero_x[1088..].fill(0);
    assert_eq!(state.finish(&zero_x).unwrap_err(), Error::ZeroSharedSecret);
    // A changed ciphertext still gives a secret, but not the right one:
    // the ML-KEM half is the implicit-rejection key.
    let mut tampered = server.clone();
    tampered[10] ^= 4;
    let got = state.finish(&tampered).expect("right length");
    assert_ne!(&got[..32], &secret[..32]);
    assert_eq!(&got[32..], &secret[32..]);
}
