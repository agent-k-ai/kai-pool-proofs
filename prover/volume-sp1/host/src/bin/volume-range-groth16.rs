// SPDX-License-Identifier: Apache-2.0
//! Final range wrapping with an integrity-checked existing ceremony cache only.
use kai_volume_chunk::framing::read_frame;
use kai_volume_core::VolumeTermsV1;
use kai_volume_range::{
    framing::{evaluate_frames, Request},
    key::pack31,
    suite::{Role, VolumeProofSuiteV1, CIRCUIT_IDENTITY},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, RiscvAir, SP1Proof,
    SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin, StatusCode, SP1_CIRCUIT_VERSION,
};
use std::{error::Error, fs, path::Path, time::Instant};

#[path = "../prover_backend.rs"]
mod prover_backend;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[path = "../plan.rs"]
#[allow(dead_code)]
mod plan;
#[path = "../batch.rs"]
#[allow(dead_code)]
mod batch;
use plan::cache_gate;
// SDK 6.7.0 embeds the runner override at BUILD time. A runtime environment
// variable cannot relocate it. Refuse a different path instead of silently
// executing an unpinned helper; public users build with their own pinned path.
fn runner_binding() -> Result<()> {
    let compiled = option_env!("SP1_CORE_RUNNER_OVERRIDE_BINARY")
        .ok_or("build host with an explicit pinned external runner")?;
    let selected = std::env::var("SP1_CORE_RUNNER_OVERRIDE_BINARY")?;
    if fs::canonicalize(compiled)? != fs::canonicalize(selected)? {
        return Err("runtime runner differs from SDK build-time binding; rebuild host at your own pinned path".into());
    }
    Ok(())
}
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn save(out: &Path, m: &Value) -> Result<()> {
    fs::write(out.join("metrics.json"), serde_json::to_vec_pretty(m)?)?;
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    // An unknown PROVER_BACKEND must fail here, before any output or proving work.
    prover_backend::backend()?;
    runner_binding()?;
    let a: Vec<_> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("serve") {
        return batch::serve(&a).await;
    }
    if a.len() < 8
        || !matches!(a[1].as_str(), "prove" | "verify")
        || (a[1] == "verify" && a.len() != 8)
    {
        return Err("prove|verify PLAN INPUT.frames NEW-OUT PARAMETER-MANIFEST.json SOURCE-MANIFEST.json CHILD.proof...|FINAL.proof".into());
    }
    if SP1_CIRCUIT_VERSION.trim() != "v6.1.0"
        || std::env::var("SP1_CIRCUIT_MODE").unwrap_or_else(|_| "release".into()) != "release"
        || std::env::var("WITHOUT_VK_VERIFICATION").is_ok_and(|v| v != "false")
    {
        return Err("standard circuit and VK verification required".into());
    }
    let cfg = sp1_prover::worker::SP1WorkerConfig::new(RiscvAir::machine());
    if !cfg.prover_config.core_prover_config.verify_intermediates
        || !cfg
            .prover_config
            .recursion_prover_config
            .verify_intermediates
    {
        return Err("intermediate verification disabled".into());
    }
    sp1_sdk::setup_logger();
    let start = Instant::now();
    let plan = Path::new(&a[2]);
    let pm = fs::read(plan.join("plan.json"))?;
    let meta: Value = serde_json::from_slice(&pm)?;
    let mut data = Vec::new();
    for name in ["chunk.elf", "range.elf", "terms.abi", "suite.abi"] {
        let b = fs::read(plan.join(name))?;
        if meta["files"][name]["sha256"].as_str() != Some(sha(&b).as_str()) {
            return Err("frozen plan artifact mismatch".into());
        }
        data.push(b);
    }
    let terms = VolumeTermsV1::abi_decode(&data[2])?;
    let suite = VolumeProofSuiteV1::abi_decode(&data[3])?;
    suite.validate_terms(&terms)?;
    if suite.circuit_identity != CIRCUIT_IDENTITY {
        return Err("circuit identity".into());
    }
    let light = ProverClient::builder().light().build().await;
    let cpk = light.setup(Elf::from(data[0].clone())).await?;
    let rpk = light.setup(Elf::from(data[1].clone())).await?;
    let cvk = cpk.verifying_key();
    let rvk = rpk.verifying_key();
    for (role, vk) in [(Role::Chunk, cvk), (Role::Range, rvk)] {
        if pack31(&vk.hash_u32())? != suite.role_key(role)
            || hex::decode(vk.bytes32().trim_start_matches("0x"))? != suite.role_key(role)
        {
            return Err("fresh VK does not match suite".into());
        }
    }
    let input = fs::read(&a[3])?;
    let mut cursor = input.as_slice();
    let mut frames = Vec::new();
    while let Some(f) = read_frame(&mut cursor)? {
        frames.push(f);
    }
    let request = Request::decode(frames.first().ok_or("missing request")?)?;
    if request.terms != terms || request.suite != suite {
        return Err("range input differs from frozen plan".into());
    }
    let mut it = frames.iter().cloned();
    let pending = evaluate_frames(|| Ok(it.next()))?;
    let out = Path::new(&a[4]);
    fs::create_dir(out)?;
    let param_manifest = fs::read(&a[5])?;
    let source = fs::read(&a[6])?;
    if meta["files"]["source-manifest.json"]["sha256"].as_str() != Some(sha(&source).as_str()) {
        return Err("source manifest differs from frozen plan".into());
    }
    let mut m = json!({"release":env!("CARGO_PKG_VERSION"),"phase":a[1],"proofForm":"Groth16","sdkVersion":"6.7.0","circuitVersion":"v6.1.0","planSha256":sha(&pm),
        "sourceManifestSha256":sha(&source),"parameterManifestSha256":sha(&param_manifest),"guestElfSha256":sha(&data[1]),"programVKey":rvk.bytes32(),"programVkBincodeSha256":sha(&bincode::serialize(rvk)?),
        "inputSha256":sha(&input),"suiteHash":hex::encode(suite.suite_hash()?),"termsHash":hex::encode(terms.terms_hash()?),"publicValuesSha256":sha(&pending.journal),"publicValuesBytes":800,
        "coreVerifyIntermediates":true,"recursionVerifyIntermediates":true,"recursionVkVerification":true,"circuitMode":"release","cryptographicProofGenerated":false,"cryptographicProofVerified":false,"contextOrigin":meta["contextOrigin"].as_str().unwrap_or("diagnostic-synthetic"),"chainAcceptanceEstablished":false});
    fs::write(out.join("program-vk.bin"), bincode::serialize(rvk)?)?;
    fs::write(out.join("source-manifest.json"), source)?;
    save(out, &m)?;
    let proof;
    if a[1] == "prove" {
        let t = Instant::now();
        m["parameterCache"] = cache_gate(&param_manifest)?;
        m["parameterAuditSeconds"] = json!(t.elapsed().as_secs_f64());
        save(out, &m)?;
        if a[7..].len() != pending.children.len() {
            return Err("exact child proof count required".into());
        }
        let mut stdin = SP1Stdin::new();
        for f in frames {
            stdin.write_slice(&f);
        }
        let mut children = Vec::new();
        for (child, path) in pending.children.iter().zip(&a[7..]) {
            let vk = if child.role == Role::Chunk { cvk } else { rvk };
            let p = SP1ProofWithPublicValues::load(path)?;
            light.verify(&p, vk, Some(StatusCode::SUCCESS))?;
            if p.public_values.as_slice() != child.journal || vk.hash_u32() != child.vk_words {
                return Err("child journal/VK mismatch".into());
            }
            children.push(json!({"role":child.role as u8,"proofBundleSha256":sha(&fs::read(path)?),"publicValuesSha256":hex::encode(child.journal_sha256),"programVKey":vk.bytes32(),"sdkExplicitSuccess":"Ok(())"}));
            let SP1Proof::Compressed(p) = p.proof else {
                return Err("compressed child required".into());
            };
            stdin.write_proof(*p, vk.vk.clone());
        }
        let raw = bincode::serialize(&stdin)?;
        m["stdinBincodeSha256"] = json!(sha(&raw));
        m["children"] = json!(children);
        fs::write(out.join("stdin.bin"), raw)?;
        let t = Instant::now();
        let cpu = prover_backend::build_prover().await?;
        m["backend"] = json!(prover_backend::backend()?.prover_label());
        let pk = cpu.setup(Elf::from(data[1].clone())).await?;
        if bincode::serialize(pk.verifying_key())? != bincode::serialize(rvk)? {
            return Err("CPU/Light VK mismatch".into());
        }
        m["setupSeconds"] = json!(t.elapsed().as_secs_f64());
        save(out, &m)?;
        let t = Instant::now();
        proof = cpu
            .prove(&pk, stdin)
            .groth16()
            .expected_exit_code(StatusCode::SUCCESS)
            .await?;
        m["proveSeconds"] = json!(t.elapsed().as_secs_f64());
        proof.save(out.join("proof.bin"))?;
        m["cryptographicProofGenerated"] = json!(true);
        save(out, &m)?;
        cpu.verify(&proof, pk.verifying_key(), Some(StatusCode::SUCCESS))?;
    } else {
        proof = SP1ProofWithPublicValues::load(&a[7])?;
    }
    if !matches!(proof.proof, SP1Proof::Groth16(_))
        || proof.tee_proof.is_some()
        || proof.public_values.as_slice() != pending.journal
    {
        return Err("final form/journal/TEE mismatch".into());
    }
    let t = Instant::now();
    light.verify(&proof, rvk, Some(StatusCode::SUCCESS))?;
    light.verify(&proof, rvk, None)?;
    m["verificationSeconds"] = json!(t.elapsed().as_secs_f64());
    let mut bad = proof.clone();
    let mut pv = pending.journal;
    pv[799] ^= 1;
    bad.public_values = SP1PublicValues::from(pv.as_slice());
    m["mutatedPublicValuesRejected"] = json!(light
        .verify(&bad, rvk, None)
        .err()
        .ok_or("changed journal accepted")?
        .to_string());
    m["wrongRoleKeyRejected"] = json!(light
        .verify(&proof, cvk, None)
        .err()
        .ok_or("chunk VK accepted")?
        .to_string());
    m["wrongExpectedStatusRejected"] = json!(light
        .verify(&proof, rvk, StatusCode::new(1))
        .err()
        .ok_or("wrong status accepted")?
        .to_string());
    let encoded = proof.bytes();
    if encoded.len() != 356 || encoded[..4] != CIRCUIT_IDENTITY[..4] {
        return Err("unexpected pinned Groth16 encoding".into());
    }
    fs::write(
        out.join("public-values.bin"),
        proof.public_values.as_slice(),
    )?;
    fs::write(out.join("proof.bytes"), &encoded)?;
    m["proofBundleSha256"] = json!(sha(&bincode::serialize(&proof)?));
    m["proofBytesSha256"] = json!(sha(&encoded));
    m["proofBytesLength"] = json!(encoded.len());
    m["proofSelector"] = json!(hex::encode(&encoded[..4]));
    m["sdkExplicitSuccessResult"] = json!("Ok(())");
    m["sdkDefaultSuccessResult"] = json!("Ok(())");
    m["cryptographicProofVerified"] = json!(true);
    m["elapsedSeconds"] = json!(start.elapsed().as_secs_f64());
    m["status"] = json!("groth16-proof-sdk-verified");
    save(out, &m)?;
    println!("{m}");
    Ok(())
}
