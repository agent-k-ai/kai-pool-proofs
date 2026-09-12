// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
#![forbid(unsafe_code)]
pub mod rlp;
pub type Result<T> = core::result::Result<T, &'static str>;
fn ensure(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message)
    }
}
pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut h = Keccak::v256();
    h.update(bytes);
    let mut out = [0; 32];
    h.finalize(&mut out);
    out
}
