// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
use kai_volume_chunk::{evaluate_frames, framing::read_frame};
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin, SP1_CIRCUIT_VERSION};
use std::{fs, time::Instant};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || !matches!(args[1].as_str(), "execute" | "reject") {
        return Err(
            "usage: volume-chunk-host execute|reject GUEST.elf CHUNK.frames NEW-OUTPUT-DIR".into(),
        );
    }
    // No environment-selected backend, setup/prove, private RPC or transaction path.
    let started = Instant::now();
    let elf_bytes = fs::read(&args[2])?;
    let input = fs::read(&args[3])?;
    let mut cursor = input.as_slice();
    let expected = evaluate_frames(|| read_frame(&mut cursor));
    if args[1] == "execute" && expected.is_err() {
        return Err(expected.unwrap_err().into());
    }
    if args[1] == "reject" && expected.is_ok() {
        return Err("reject fixture is natively valid".into());
    }
    if SP1_CIRCUIT_VERSION.trim() != "v6.1.0" {
        return Err("unexpected circuit version".into());
    }
    if std::env::var("WITHOUT_VK_VERIFICATION").is_ok_and(|v| v != "false") {
        return Err("VK verification must remain enabled".into());
    }
    let mut stdin = SP1Stdin::new();
    let mut cursor = input.as_slice();
    while let Some(frame) = read_frame(&mut cursor)? {
        stdin.write_slice(&frame);
    }
    let client = ProverClient::builder().light().build().await;
    // In 6.7.0 execute() returning Ok does NOT by itself assert successful halt.
    // Gas reporting is enabled so exit_code and instruction counts are populated.
    let (public_values, report) = client
        .execute(Elf::from(elf_bytes.clone()), stdin)
        .calculate_gas(true)
        .await?;
    if args[1] == "reject" {
        if report.exit_code != 1 || !public_values.as_slice().is_empty() {
            return Err("expected guest panic (exit 1) with zero public bytes".into());
        }
        fs::create_dir(&args[4])?;
        let metrics = serde_json::json!({
            "status":"guest-rejected", "cryptographicProofGenerated":false,
            "cryptographicProofVerified":false, "exitCode":report.exit_code,
            "publicValuesBytes":public_values.as_slice().len(),
            "instructions":report.total_instruction_count(),
            "inputSha256":hex::encode(Sha256::digest(&input)),
            "guestElfSha256":hex::encode(Sha256::digest(&elf_bytes))
        });
        fs::write(
            format!("{}/metrics.json", args[4]),
            serde_json::to_vec_pretty(&metrics)?,
        )?;
        fs::write(
            format!("{}/execution-report.txt", args[4]),
            format!("{report:?}"),
        )?;
        println!("{metrics}");
        return Ok(());
    }
    if report.exit_code != 0 {
        return Err("guest did not halt successfully".into());
    }
    let expected = expected?;
    if public_values.as_slice() != expected.journal {
        return Err("guest/native journal mismatch".into());
    }
    fs::create_dir(&args[4])?;
    fs::write(
        format!("{}/public-values.bin", args[4]),
        public_values.as_slice(),
    )?;
    fs::write(
        format!("{}/execution-report.txt", args[4]),
        format!("{report:?}"),
    )?;
    let metrics = serde_json::json!({
        "release":env!("CARGO_PKG_VERSION"), "status":"execution-only",
        "guestSourceCommit": if hex::encode(Sha256::digest(&elf_bytes)) == "6e74010b78aee1d7de9abf760cc7fe620d0539f25d6a4fe61120e3d23fa4e855" {
            Some("00aba6b1646879fe6c6f485bb530437caeb22988")
        } else { None },
        "sp1Version":"6.7.0", "circuitVersion":SP1_CIRCUIT_VERSION.trim(), "gasCalculation":true, "exitCode":report.exit_code,
        "backend":"LightProver CPU execution", "cryptographicProofGenerated":false,
        "cryptographicProofVerified":false, "canonicalChainEstablished":false,
        "deployedRaceEstablished":false,
        "guestElfSha256":hex::encode(Sha256::digest(&elf_bytes)),
        "inputSha256":hex::encode(Sha256::digest(&input)), "inputBytes":input.len(),
        "publicValuesBytes":public_values.as_slice().len(),
        "instructions":report.total_instruction_count(), "syscalls":report.total_syscall_count(),
        "blocks":expected.diagnostics.blocks,"receipts":expected.diagnostics.receipts,
        "failedReceipts":expected.diagnostics.failed_receipts,"logs":expected.diagnostics.logs,
        "elapsedSeconds":started.elapsed().as_secs_f64()
    });
    fs::write(
        format!("{}/metrics.json", args[4]),
        serde_json::to_vec_pretty(&metrics)?,
    )?;
    println!("{metrics}");
    Ok(())
}
