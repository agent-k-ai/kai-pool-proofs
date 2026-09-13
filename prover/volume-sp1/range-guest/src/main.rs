// SPDX-License-Identifier: Apache-2.0
#![no_main]
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let pending = kai_volume_range::framing::evaluate_frames(|| {
        if sp1_zkvm::syscalls::syscall_hint_len() == usize::MAX {
            Ok(None)
        } else {
            Ok(Some(sp1_zkvm::io::read_vec()))
        }
    })
    .expect("invalid volume range");
    // SDK 6.7.0 deferred verification fixes successful child status to zero.
    // Exact full SHA256 of the same 800 bytes decoded by the relation, in child order.
    for child in &pending.children {
        sp1_zkvm::lib::verify::verify_sp1_proof(&child.vk_words, &child.journal_sha256);
    }
    // The sole public write occurs after every predicate and verification call.
    sp1_zkvm::io::commit_slice(&pending.journal);
}
