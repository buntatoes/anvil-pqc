// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Buntato
//! The Windows system random source: `BCryptGenRandom` from `bcrypt.dll`.
//!
//! This is the only module allowed to use `unsafe`, and it has one unsafe
//! call. The rest of the crate is built with `#![deny(unsafe_code)]`.

use crate::Error;

/// `BCRYPT_USE_SYSTEM_PREFERRED_RNG`: use the system's own generator, so no
/// algorithm handle is needed.
const USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

// SAFETY: this is the documented bcrypt signature. The handle is a pointer
// (`BCRYPT_ALG_HANDLE`), the buffer is a byte pointer with a `ULONG` length,
// the flags are a `ULONG`, and the result is an `NTSTATUS`.
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut core::ffi::c_void,
        buffer: *mut u8,
        len: u32,
        flags: u32,
    ) -> i32;
}

/// Fill `buf` from the system's preferred generator.
pub(crate) fn fill(buf: &mut [u8]) -> Result<(), Error> {
    // The length is a u32, so a very large buffer is filled in pieces.
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        // SAFETY: `chunk` is a live, writable slice, and its length fits in
        // a u32 because of `chunks_mut` above, so bcrypt writes only inside
        // it. A null algorithm handle is allowed together with
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG. Nothing is kept after the call.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(Error::NoRandomness);
        }
    }
    Ok(())
}
