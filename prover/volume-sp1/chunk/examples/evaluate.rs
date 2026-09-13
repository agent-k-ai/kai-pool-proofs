// SPDX-License-Identifier: Apache-2.0
//! Executes the chunk relation natively on a frames file.
//! Execution-only diagnostics: no SP1 proving, no signing, no network.
//!
//! Usage: cargo run --example evaluate -- <frames-file> [journal-out]
use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: evaluate <frames-file> [journal-out]");
    let mut file = std::fs::File::open(path).expect("open frames file");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read frames file");
    let mut input: &[u8] = &bytes;
    let outcome = kai_volume_chunk::evaluate_frames(|| {
        kai_volume_chunk::framing::read_frame(&mut input)
    })
    .unwrap_or_else(|e| {
        eprintln!("GUEST_FAIL: {e}");
        std::process::exit(1);
    });
    let d = &outcome.diagnostics;
    println!("blocks={}", d.blocks);
    println!("receipts={}", d.receipts);
    println!("failed_receipts={}", d.failed_receipts);
    println!("logs={}", d.logs);
    println!("journal=0x{}", hex::encode(outcome.journal));
    if let Some(out) = args.get(2) {
        std::fs::write(out, outcome.journal).expect("write journal");
        println!("journal_out={out}");
    }
}