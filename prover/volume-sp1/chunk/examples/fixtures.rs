// SPDX-License-Identifier: Apache-2.0
//! Emits labelled, reproducible offline diagnostic input; does not contact a chain.
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use kai_volume_chunk::framing::write_frame;
fn main() {
    let dir = std::env::args().nth(1).expect("NEW output directory");
    std::fs::create_dir(&dir).unwrap();
    let real = real_frames();
    let mut bad = real.clone();
    let last = bad[1].len() - 1;
    bad[1][last] ^= 1;
    let large = synthetic_frames(&[
        receipts()[0].clone(),
        receipt(
            true,
            &[log(&[7; 20], &[], &vec![0x55; 320 * 1024]), real_swap_log()],
        ),
    ]);
    let malformed = synthetic_frames(&[
        receipts()[0].clone(),
        receipt(true, &[real_swap_log(), vec![0xc0]]),
    ]);
    let mut trailing = real.clone();
    trailing.push(vec![]);
    let (header, nodes) = kai_volume_chunk::framing::decode_block(&real[1]).unwrap();
    let missing = vec![
        real[0].clone(),
        kai_volume_chunk::framing::encode_block(header, &nodes[..nodes.len() - 1]).unwrap(),
    ];
    for (name, frames) in [
        ("synthetic-malformed-late-log", malformed),
        ("synthetic-trailing-frame", trailing),
        ("synthetic-missing-node", missing),
        ("real-block-synthetic-terms", real),
        ("synthetic-corrupt-node", bad),
        ("synthetic-large-complete-block", large),
    ] {
        let mut file = std::fs::File::create(format!("{dir}/{name}.frames")).unwrap();
        for frame in frames {
            write_frame(&mut file, &frame).unwrap();
        }
    }
}
