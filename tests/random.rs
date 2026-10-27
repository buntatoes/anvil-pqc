// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0-OR-Commercial
// Copyright (c) 2026 Buntato
//! The system random source, on Unix and on Windows.

use anvil_pqc::fill_random;
use anvil_pqc::hybrid::{CLIENT_SHARE_LEN, SERVER_SHARE_LEN, client_share, server_respond};

#[test]
fn fills_the_whole_buffer_with_fresh_bytes() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    fill_random(&mut a).expect("system random source");
    fill_random(&mut b).expect("system random source");
    // 64 random bytes are all zero, or the same twice, with chance 2^-512.
    assert_ne!(a, [0u8; 64]);
    assert_ne!(a, b);
}

#[test]
fn fills_odd_and_empty_lengths() {
    for len in [0usize, 1, 31, 33, 1000] {
        let mut buf = vec![0u8; len];
        fill_random(&mut buf).expect("system random source");
        assert_eq!(buf.len(), len);
        if len >= 31 {
            assert!(buf.iter().any(|&x| x != 0), "{len}");
        }
    }
}

#[test]
fn hybrid_round_trip_with_system_randomness() {
    let (state, share) = client_share().expect("client");
    assert_eq!(share.len(), CLIENT_SHARE_LEN);
    let (server, secret) = server_respond(&share).expect("server");
    assert_eq!(server.len(), SERVER_SHARE_LEN);
    assert_eq!(state.finish(&server), Ok(secret));
    let (_, other) = client_share().expect("client");
    assert_ne!(share, other);
}
