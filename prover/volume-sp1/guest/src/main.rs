// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
#![no_main]
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let result = kai_volume_chunk::evaluate_frames(|| {
        // 6.7.0 read_vec_raw uses usize::MAX as the exhausted hint-stream sentinel.
        if sp1_zkvm::syscalls::syscall_hint_len() == usize::MAX {
            Ok(None)
        } else {
            Ok(Some(sp1_zkvm::io::read_vec()))
        }
    })
    .expect("invalid volume chunk");
    // The only public-values write, after headers, exhaustion, logs, range and EOF.
    sp1_zkvm::io::commit_slice(&result.journal);
}
