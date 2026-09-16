// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
use kai_volume_chunk::{evaluate_frames, framing::read_frame};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, RiscvAir, SP1Proof,
    SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin, SP1VerifyingKey, StatusCode,
    SP1_CIRCUIT_VERSION,
};
use std::{error::Error, fs, path::Path, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const GUEST_SOURCE: &str = "598f94eb09fb5d8f5f0beb8b29ade20de5832738";
const GUEST_SHA256: &str = "65f03aa5cb1a26e6640f4a100174e721020b13450a7ffe201c8fa3d3d5ed6fbd";

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn record(out: &Path, metrics: &Value) -> Result<()> {
    fs::write(
        out.join("metrics.json"),
        serde_json::to_vec_pretty(metrics)?,
    )?;
    println!("{metrics}");
    Ok(())
}
fn save_vk(out: &Path, vk: &SP1VerifyingKey, metrics: &mut Value) -> Result<()> {
    let bytes = bincode::serialize(vk)?;
    fs::write(out.join("program-vk.bin"), &bytes)?;
    metrics["programVkBincodeSha256"] = json!(sha(&bytes));
    metrics["programVkBytes32"] = json!(vk.bytes32());
    metrics["programVkHashU32"] = json!(vk.hash_u32());
    Ok(())
}
fn check_bundle(proof: &SP1ProofWithPublicValues, expected: &[u8]) -> Result<()> {
    if !matches!(&proof.proof, SP1Proof::Compressed(_)) {
        return Err("expected actual SP1Proof::Compressed variant".into());
    }
    if proof.public_values.as_slice().len() != 800 || proof.public_values.as_slice() != expected {
        return Err("proof public values differ from native/retained 800-byte journal".into());
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if !((args.len() == 7 && args[1] == "prove") || (args.len() == 8 && args[1] == "verify")) {
        return Err("usage: volume-chunk-proof prove|verify GUEST.elf CHUNK.frames EXPECTED.journal NEW-OUTPUT-DIR SOURCE-MANIFEST.json [PROOF.bin]".into());
    }
    // The manifest is provenance supplied by the caller; its hash is not proof authority.
    run(&args).await
}

async fn run(args: &[String]) -> Result<()> {
    let started = Instant::now();
    let elf = fs::read(&args[2])?;
    let input = fs::read(&args[3])?;
    let retained = fs::read(&args[4])?;
    let out = Path::new(&args[5]);
    let source_manifest = fs::read(&args[6])?;
    if sha(&elf) != GUEST_SHA256 || SP1_CIRCUIT_VERSION.trim() != "v6.1.0" {
        return Err("unexpected retained ELF or circuit version".into());
    }
    if std::env::var("WITHOUT_VK_VERIFICATION").is_ok_and(|v| v != "false") {
        return Err("VK verification must remain enabled".into());
    }
    let mut cursor = input.as_slice();
    let native = evaluate_frames(|| read_frame(&mut cursor))?;
    if retained.as_slice() != native.journal {
        return Err("retained journal does not equal freshly evaluated native journal".into());
    }
    fs::create_dir(out)?;
    fs::write(out.join("native-journal.bin"), native.journal)?;
    fs::write(out.join("source-manifest.json"), &source_manifest)?;
    let mut metrics = json!({
        "release":env!("CARGO_PKG_VERSION"), "phase":args[1], "status":"native-validated",
        "guestSourceCommit":GUEST_SOURCE, "sourceManifestSha256":sha(&source_manifest),
        "sdkVersion":"6.7.0", "circuitVersion":SP1_CIRCUIT_VERSION.trim(),
        "guestElfSha256":sha(&elf), "inputSha256":sha(&input), "inputBytes":input.len(),
        "nativeJournalSha256":sha(&native.journal), "retainedJournalSha256":sha(&retained),
        "proofForm":"SP1Proof::Compressed", "cryptographicProofGenerated":false,
        "cryptographicProofVerified":false, "syntheticTerms":true,
        "deployedRaceEstablished":false, "canonicalChainEstablished":false,
        "expectedExitStatus":0, "blocks":native.diagnostics.blocks,
        "receipts":native.diagnostics.receipts, "logs":native.diagnostics.logs
    });
    record(out, &metrics)?;
    sp1_sdk::setup_logger();
    let proof;
    if args[1] == "prove" {
        let config = sp1_prover::worker::SP1WorkerConfig::new(RiscvAir::machine());
        let c = &config.prover_config.core_prover_config;
        let r = &config.prover_config.recursion_prover_config;
        let ctrl = &config.controller_config;
        if !c.verify_intermediates || !r.verify_intermediates {
            return Err("intermediate verification must remain enabled".into());
        }
        metrics["resolvedWorkerConfig"] = json!({
            "coreWorkers":c.num_core_workers, "coreBuffer":c.core_buffer_size,
            "setupWorkers":c.num_setup_workers, "setupBuffer":c.setup_buffer_size,
            "normalizeProgramCache":c.normalize_program_cache_size,
            "splicingWorkers":ctrl.num_splicing_workers, "splicingBuffer":ctrl.splicing_buffer_size,
            "globalMemoryBuffer":ctrl.global_memory_buffer_size,
            "prepareReduceWorkers":r.num_prepare_reduce_workers, "prepareReduceBuffer":r.prepare_reduce_buffer_size,
            "recursionExecutorWorkers":r.num_recursion_executor_workers, "recursionExecutorBuffer":r.recursion_executor_buffer_size,
            "recursionProverWorkers":r.num_recursion_prover_workers, "recursionProverBuffer":r.recursion_prover_buffer_size,
            "coreVerifyIntermediates":c.verify_intermediates, "recursionVerifyIntermediates":r.verify_intermediates,
            "elementThreshold":ctrl.opts.sharding_threshold.element_threshold,
            "heightThreshold":ctrl.opts.sharding_threshold.height_threshold, "nativeMemoryLimit":ctrl.opts.memory_limit
        });
        record(out, &metrics)?;
        let setup = Instant::now();
        // Explicit CPU backend. Never from_env(), mock(), or an experimental prover.
        let client = ProverClient::builder().cpu().build().await;
        let pk = client.setup(Elf::from(elf)).await?;
        save_vk(out, pk.verifying_key(), &mut metrics)?;
        metrics["setupSeconds"] = json!(setup.elapsed().as_secs_f64());
        metrics["status"] = json!("setup-complete-proof-starting");
        record(out, &metrics)?;
        let mut stdin = SP1Stdin::new();
        let mut cursor = input.as_slice();
        while let Some(frame) = read_frame(&mut cursor)? {
            stdin.write_slice(&frame);
        }
        let proving = Instant::now();
        proof = client.prove(&pk, stdin).compressed().await?;
        metrics["proveSeconds"] = json!(proving.elapsed().as_secs_f64());
        check_bundle(&proof, &retained)?;
        // Save the genuine candidate before verification; only final metrics mark success.
        proof.save(out.join("proof.bin"))?;
        metrics["cryptographicProofGenerated"] = json!(true);
        metrics["status"] = json!("candidate-saved-verification-pending");
        record(out, &metrics)?;
        let verifying = Instant::now();
        client.verify(&proof, pk.verifying_key(), Some(StatusCode::SUCCESS))?;
        metrics["verificationSeconds"] = json!(verifying.elapsed().as_secs_f64());
        metrics["sdkExplicitSuccessResult"] = json!("Ok(())");
        // This diagnostic binary builds the CPU prover above and never reads
        // PROVER_BACKEND, so the label is accurate. Not part of the runtime host set.
        metrics["backend"] = json!("CpuProver");
    } else {
        // This command must be invoked as a new process. Its VK is freshly derived from
        // ELF bytes, never loaded from the producer or taken from an untrusted host flag.
        let setup = Instant::now();
        let client = ProverClient::builder().light().build().await;
        let pk = client.setup(Elf::from(elf)).await?;
        save_vk(out, pk.verifying_key(), &mut metrics)?;
        metrics["setupSeconds"] = json!(setup.elapsed().as_secs_f64());
        record(out, &metrics)?;
        proof = SP1ProofWithPublicValues::load(&args[7])?;
        check_bundle(&proof, &retained)?;
        let verifying = Instant::now();
        client.verify(&proof, pk.verifying_key(), Some(StatusCode::SUCCESS))?;
        client.verify(&proof, pk.verifying_key(), None)?;
        metrics["verificationSeconds"] = json!(verifying.elapsed().as_secs_f64());
        metrics["sdkExplicitSuccessResult"] = json!("Ok(())");
        metrics["sdkDefaultSuccessResult"] = json!("Ok(())");
        // These are verifier checks against the actual proof, not execution tests.
        let wrong_status = client
            .verify(&proof, pk.verifying_key(), StatusCode::new(1))
            .err()
            .ok_or("proof unexpectedly verified with expected exit status 1")?;
        let mut changed = proof.clone();
        let mut bytes = retained.clone();
        bytes[0] ^= 1;
        changed.public_values = SP1PublicValues::from(bytes.as_slice());
        let wrong_values = client
            .verify(&changed, pk.verifying_key(), None)
            .err()
            .ok_or("proof unexpectedly verified after public-value mutation")?;
        metrics["wrongStatusRejected"] = json!(wrong_status.to_string());
        metrics["mutatedPublicValuesRejected"] = json!(wrong_values.to_string());
        metrics["backend"] = json!("LightProver: standard full cryptographic Prover::verify");
        metrics["proofFileSha256"] = json!(sha(&fs::read(&args[7])?));
    }
    let serialized = bincode::serialize(&proof)?;
    let payload = bincode::serialize(&proof.proof)?;
    metrics["proofBundleSha256"] = json!(sha(&serialized));
    metrics["proofBundleBytes"] = json!(serialized.len());
    metrics["proofPayloadBincodeSha256"] = json!(sha(&payload));
    metrics["publicValuesSha256"] = json!(sha(proof.public_values.as_slice()));
    metrics["publicValuesBytes"] = json!(proof.public_values.as_slice().len());
    fs::write(
        out.join("public-values.bin"),
        proof.public_values.as_slice(),
    )?;
    metrics["status"] = json!("compressed-proof-sdk-verified");
    metrics["cryptographicProofVerified"] = json!(true);
    metrics["elapsedSeconds"] = json!(started.elapsed().as_secs_f64());
    record(out, &metrics)
}
