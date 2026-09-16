// SPDX-License-Identifier: Apache-2.0
//! Honest CPU producer. Plans bind concrete ELF/VK/suite/terms; native evaluation is not proof evidence.
use kai_volume_chunk::{
    evaluate_frames as chunk_eval,
    framing::{decode_block, Context},
};
use kai_volume_core::{keccak256, parse_nitro_header, VolumeTermsV1};
use kai_volume_range::suite::{suite_domain, Role, VolumeProofSuiteV1, CIRCUIT_IDENTITY};
use serde_json::json;
use sp1_sdk::{
    Elf, ProveRequest, Prover, ProverClient, ProvingKey, SP1Proof, SP1ProofWithPublicValues,
    SP1PublicValues, StatusCode,
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
use plan::{
    file_frames, frames, record, role, role_name, runner_binding, safety, sha, vk_bytes32, vk_meta,
    Plan, CHUNK_ELF_SHA256,
};
/// Freeze supplied bytes without manufacturing a suite or changing any race terms.
/// On-chain approval/canonicality is checked separately by the public node.
async fn freeze_context(a: &[String]) -> Result<()> {
    if a.len() != 8 {
        return Err(
            "freeze-context CHUNK.elf RANGE.elf TERMS.abi SUITE.abi SOURCE-MANIFEST.json NEW-PLAN"
                .into(),
        );
    }
    let data = a[2..7]
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()?;
    if sha(&data[0]) != CHUNK_ELF_SHA256 {
        return Err("retained chunk ELF mismatch".into());
    }
    let terms = VolumeTermsV1::abi_decode(&data[2])?;
    let suite = VolumeProofSuiteV1::abi_decode(&data[3])?;
    suite.validate_terms(&terms)?;
    let light = ProverClient::builder().light().build().await;
    let mut keys = Vec::new();
    for (i, role) in [Role::Chunk, Role::Range].into_iter().enumerate() {
        let pk = light.setup(Elf::from(data[i].clone())).await?;
        if vk_bytes32(pk.verifying_key())? != suite.role_key(role) {
            return Err("supplied suite differs from fresh ELF-derived key".into());
        }
        keys.push(bincode::serialize(pk.verifying_key())?);
    }
    // Create outputs only after decoding and fresh key checks. The caller commits
    // this directory atomically as a stage; partial filesystem errors are not success.
    let out = Path::new(&a[7]);
    fs::create_dir(out)?;
    let mut files = json!({});
    for (name, bytes) in [
        "chunk.elf",
        "range.elf",
        "terms.abi",
        "suite.abi",
        "source-manifest.json",
    ]
    .into_iter()
    .zip(&data)
    {
        fs::write(out.join(name), bytes)?;
        files[name] = json!({"sha256":sha(bytes),"bytes":bytes.len()});
    }
    for (name, bytes) in ["chunk-vk.bin", "range-vk.bin"].into_iter().zip(&keys) {
        fs::write(out.join(name), bytes)?;
        files[name] = json!({"sha256":sha(bytes),"bytes":bytes.len()});
    }
    let m = json!({"release":env!("CARGO_PKG_VERSION"),"hostInterface":"freeze-context/v1",
        "sdkVersion":"6.7.0","circuitVersion":"v6.1.0","files":files,
        "contextOrigin":"supplied-immutable-bytes","chainAcceptanceEstablished":false,
        "suiteHash":hex::encode(suite.suite_hash()?),"termsHash":hex::encode(terms.terms_hash()?),
        "chunkProgramVKey":hex::encode(suite.chunk_program_vkey),
        "rangeProgramVKey":hex::encode(suite.range_program_vkey)});
    record(out, "plan.json", &m)?;
    println!("{m}");
    Ok(())
}

async fn freeze_diagnostic(a: &[String]) -> Result<()> {
    // Source manifest is provenance, not external approval. All admission terms remain synthetic.
    if a.len() != 9 {
        return Err("freeze-diagnostic CHUNK.elf RANGE.elf TEMPLATE.frames BLOCK0.frame BLOCK1.frame SOURCE-MANIFEST.json NEW-PLAN".into());
    }
    let chunk_elf = fs::read(&a[2])?;
    let range_elf = fs::read(&a[3])?;
    if sha(&chunk_elf) != CHUNK_ELF_SHA256 {
        return Err("retained chunk ELF mismatch".into());
    }
    let f = frames(&fs::read(&a[4])?)?;
    let template = Context::decode(f.first().ok_or("template")?)?;
    let blocks = [fs::read(&a[5])?, fs::read(&a[6])?];
    let mut headers = Vec::new();
    for b in &blocks {
        headers.push(parse_nitro_header(decode_block(b)?.0)?);
    }
    if headers[0].number != 117903561
        || headers[1].number != 117903562
        || headers[1].parent_hash != headers[0].hash
    {
        return Err("diagnostic must use adjacent captured blocks 117903561/2".into());
    }
    let light = ProverClient::builder().light().build().await;
    let chunk_pk = light.setup(Elf::from(chunk_elf.clone())).await?;
    let range_pk = light.setup(Elf::from(range_elf.clone())).await?;
    let mut terms = template.terms.clone();
    terms.start_block = headers[0].number - 1;
    terms.snapshot_block = headers[1].number;
    terms.betting_cutoff = terms.betting_cutoff.min(terms.snapshot_block);
    terms.circuit_identity = CIRCUIT_IDENTITY;
    let suite = VolumeProofSuiteV1 {
        domain: suite_domain(),
        chunk_program_vkey: vk_bytes32(chunk_pk.verifying_key())?,
        range_program_vkey: vk_bytes32(range_pk.verifying_key())?,
        sp1_verifier: terms.sp1_verifier,
        sp1_verifier_code_hash: terms.sp1_verifier_code_hash,
        circuit_identity: CIRCUIT_IDENTITY,
    };
    terms.proof_suite_hash = suite.suite_hash()?;
    suite.validate_terms(&terms)?;
    let out = Path::new(&a[8]);
    fs::create_dir(out)?;
    let mut identities = json!({});
    for (name, bytes) in [
        ("chunk.elf", chunk_elf),
        ("range.elf", range_elf),
        ("terms.abi", terms.abi_encode()?),
        ("suite.abi", suite.abi_encode()?.to_vec()),
        ("source-manifest.json", fs::read(&a[7])?),
    ] {
        fs::write(out.join(name), &bytes)?;
        identities[name] = json!({"sha256":sha(&bytes),"bytes":bytes.len()});
    }
    for (role, pk) in [(Role::Chunk, chunk_pk), (Role::Range, range_pk)] {
        fs::write(
            out.join(format!("{}-vk.bin", role_name(role))),
            bincode::serialize(pk.verifying_key())?,
        )?;
    }
    let mut diagnostics = Vec::new();
    for i in 0..2 {
        let h = &headers[i];
        let c = Context {
            terms: terms.clone(),
            beneficiary: template.beneficiary,
            coverage_mask: template.coverage_mask,
            from_exclusive: h.number - 1,
            to_inclusive: h.number,
            before_hash: h.parent_hash,
            end_hash: h.hash,
        };
        let f = vec![c.encode()?, blocks[i].clone()];
        let mut it = f.iter().cloned();
        let native = chunk_eval(|| Ok(it.next()))?;
        let input = file_frames(&f)?;
        fs::write(out.join(format!("chunk-{i}.frames")), &input)?;
        fs::write(out.join(format!("chunk-{i}.journal")), native.journal)?;
        diagnostics.push(json!({"block":h.number,"inputSha256":sha(&input),"publicValuesSha256":sha(&native.journal),"receipts":native.diagnostics.receipts,"logs":native.diagnostics.logs}));
    }
    let m = json!({"release":env!("CARGO_PKG_VERSION"),"sdkVersion":"6.7.0","circuitVersion":"v6.1.0","files":identities,
        "suiteHash":hex::encode(suite.suite_hash()?),"termsHash":hex::encode(terms.terms_hash()?),"chunkProgramVKey":hex::encode(suite.chunk_program_vkey),"rangeProgramVKey":hex::encode(suite.range_program_vkey),
        "syntheticTerms":true,"syntheticEntrantAdmission":true,"syntheticVerifierAddressAndRuntimeCodeHash":true,
        "actualFourEntrantRaceAcceptance":false,"liveDeployment":false,"diagnostics":diagnostics});
    record(out, "plan.json", &m)?;
    println!("{m}");
    Ok(())
}

async fn assemble(a: &[String]) -> Result<()> {
    if ![6, 8].contains(&a.len()) {
        return Err(
            "assemble PLAN NEW.frames chunk|range CHILD.proof [chunk|range CHILD.proof]".into(),
        );
    }
    let plan = Plan::load(Path::new(&a[2])).await?;
    let mut children = Vec::new();
    for pair in a[4..].chunks_exact(2) {
        children.push((plan::role(&pair[0])?, pair[1].clone()));
    }
    let (input, identities) = plan::assemble_frames(&plan, &children)?;
    let out = Path::new(&a[3]);
    // A new frame file only: the per-job phase never overwrites retained frames.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?;
    use std::io::Write;
    file.write_all(&input)?;
    let expected = plan.expected(Role::Range, &plan::frames(&input)?)?;
    fs::write(out.with_extension("journal"), expected)?;
    fs::write(
        out.with_extension("children.json"),
        serde_json::to_vec_pretty(&identities)?,
    )?;
    println!(
        "{}",
        json!({"inputSha256":sha(&input),"journalSha256":sha(&expected),"children":identities})
    );
    Ok(())
}

async fn run(a: &[String]) -> Result<()> {
    if a.len() < 6 {
        return Err("prove|execute|verify chunk|range PLAN INPUT.frames NEW-OUTPUT [CHILD.proof ... | VERIFIED.proof]".into());
    }
    let phase = a[1].as_str();
    if !["prove", "execute", "verify"].contains(&phase) {
        return Err("unknown phase".into());
    }
    if phase == "verify" && a.len() != 7 {
        return Err("verify expects one proof bundle".into());
    }
    let start = Instant::now();
    let r = role(&a[2])?;
    let plan = Plan::load(Path::new(&a[3])).await?;
    let input = fs::read(&a[4])?;
    let f = frames(&input)?;
    let expected = plan.expected(r, &f)?;
    let out = Path::new(&a[5]);
    fs::create_dir(out)?;
    fs::write(out.join("native-journal.bin"), expected)?;
    fs::write(out.join("program-vk.bin"), bincode::serialize(plan.vk(r))?)?;
    let mut m = json!({"release":env!("CARGO_PKG_VERSION"),"phase":phase,"role":role_name(r),"sdkVersion":"6.7.0","circuitVersion":"v6.1.0",
        "planSha256":plan.manifest_sha,"sourceManifestSha256":plan.source_sha,"guestElfSha256":sha(plan.elf(r)),"vk":vk_meta(plan.vk(r))?,
        "suiteHash":hex::encode(plan.suite.suite_hash()?),"termsHash":hex::encode(plan.terms.terms_hash()?),"inputSha256":sha(&input),"inputBytes":input.len(),
        "nativeJournalSha256":sha(&expected),"cryptographicProofGenerated":false,"cryptographicProofVerified":false,
        "contextOrigin":plan.context_origin,"deployedRaceEstablished":false,"actualFourEntrantRaceAcceptance":false,"resolvedWorkerConfig":safety()?});
    record(out, "metrics.json", &m)?;
    let proof;
    if phase == "verify" {
        proof = SP1ProofWithPublicValues::load(&a[6])?;
        if !matches!(proof.proof, SP1Proof::Compressed(_)) {
            return Err("expected compressed proof".into());
        }
        if proof.public_values.as_slice() != expected {
            return Err("proof journal differs from frozen native statement".into());
        }
        let t = Instant::now();
        plan.light
            .verify(&proof, plan.vk(r), Some(StatusCode::SUCCESS))?;
        plan.light.verify(&proof, plan.vk(r), None)?;
        m["verificationSeconds"] = json!(t.elapsed().as_secs_f64());
        m["sdkExplicitSuccessResult"] = json!("Ok(())");
        m["sdkDefaultSuccessResult"] = json!("Ok(())");
        let wrong_status = plan
            .light
            .verify(&proof, plan.vk(r), StatusCode::new(1))
            .err()
            .ok_or("nonzero expected status accepted")?;
        let mut changed = proof.clone();
        let mut b = expected;
        b[799] ^= 1;
        changed.public_values = SP1PublicValues::from(b.as_slice());
        let wrong_values = plan
            .light
            .verify(&changed, plan.vk(r), None)
            .err()
            .ok_or("mutated public values accepted")?;
        let other = if r == Role::Chunk {
            Role::Range
        } else {
            Role::Chunk
        };
        let wrong_key = plan
            .light
            .verify(&proof, plan.vk(other), None)
            .err()
            .ok_or("wrong role VK accepted")?;
        m["wrongStatusRejected"] = json!(wrong_status.to_string());
        m["mutatedPublicValuesRejected"] = json!(wrong_values.to_string());
        m["wrongRoleKeyRejected"] = json!(wrong_key.to_string());
        m["backend"] = json!("LightProver standard full SDK verification, fresh ELF-derived VKs");
    } else {
        let (stdin, child_records) = plan.stdin(r, &f, &a[6..])?;
        m["children"] = child_records;
        let stdin_bytes = bincode::serialize(&stdin)?;
        m["stdinBincodeSha256"] = json!(sha(&stdin_bytes));
        fs::write(out.join("stdin.bin"), stdin_bytes)?;
        record(out, "metrics.json", &m)?;
        if phase == "execute" {
            let t = Instant::now();
            let (pv, report) = plan
                .light
                .execute(Elf::from(plan.elf(r).to_vec()), stdin)
                .calculate_gas(true)
                .await?;
            if report.exit_code != 0 || pv.as_slice() != expected {
                return Err("guest execution exit/public mismatch".into());
            }
            fs::write(out.join("execution-report.txt"), format!("{report:?}"))?;
            fs::write(out.join("public-values.bin"), pv.as_slice())?;
            m["executeSeconds"] = json!(t.elapsed().as_secs_f64());
            m["instructions"] = json!(report.total_instruction_count());
            m["exitCode"] = json!(report.exit_code);
            m["status"] = json!("execution-only");
            m["publicValuesSha256"] = json!(sha(pv.as_slice()));
            record(out, "metrics.json", &m)?;
            println!("{m}");
            return Ok(());
        }
        let t = Instant::now();
        let cpu = prover_backend::build_prover().await?;
        let pk = cpu.setup(Elf::from(plan.elf(r).to_vec())).await?;
        if bincode::serialize(pk.verifying_key())? != bincode::serialize(plan.vk(r))? {
            return Err("CPU/Light fresh VK mismatch".into());
        }
        m["setupSeconds"] = json!(t.elapsed().as_secs_f64());
        m["status"] = json!("proof-starting");
        record(out, "metrics.json", &m)?;
        let t = Instant::now();
        proof = cpu
            .prove(&pk, stdin)
            .compressed()
            .expected_exit_code(StatusCode::SUCCESS)
            .await?;
        m["proveSeconds"] = json!(t.elapsed().as_secs_f64());
        if !matches!(proof.proof, SP1Proof::Compressed(_))
            || proof.public_values.as_slice() != expected
        {
            return Err("candidate form/public mismatch".into());
        }
        proof.save(out.join("proof.bin"))?;
        m["cryptographicProofGenerated"] = json!(true);
        m["status"] = json!("candidate-saved-verification-pending");
        record(out, "metrics.json", &m)?;
        let t = Instant::now();
        cpu.verify(&proof, pk.verifying_key(), Some(StatusCode::SUCCESS))?;
        m["verificationSeconds"] = json!(t.elapsed().as_secs_f64());
        m["sdkExplicitSuccessResult"] = json!("Ok(())");
        m["backend"] = json!("CpuProver");
    }
    let bundle = bincode::serialize(&proof)?;
    m["proofBundleSha256"] = json!(sha(&bundle));
    m["proofBundleBytes"] = json!(bundle.len());
    m["proofPayloadBincodeSha256"] = json!(sha(&bincode::serialize(&proof.proof)?));
    m["publicValuesSha256"] = json!(sha(proof.public_values.as_slice()));
    m["statementIdKeccak256"] = json!(hex::encode(keccak256(proof.public_values.as_slice())));
    m["publicValuesBytes"] = json!(proof.public_values.as_slice().len());
    fs::write(
        out.join("public-values.bin"),
        proof.public_values.as_slice(),
    )?;
    m["status"] = json!("compressed-proof-sdk-verified");
    m["cryptographicProofVerified"] = json!(true);
    m["elapsedSeconds"] = json!(start.elapsed().as_secs_f64());
    record(out, "metrics.json", &m)?;
    println!("{m}");
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    // An unknown PROVER_BACKEND must fail here, before any output or proving work.
    prover_backend::backend()?;
    runner_binding()?;
    safety()?;
    sp1_sdk::setup_logger();
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("freeze-context") => freeze_context(&a).await,
        Some("freeze-diagnostic") => freeze_diagnostic(&a).await,
        Some("assemble") => assemble(&a).await,
        Some("serve") => batch::serve(&a).await,
        _ => run(&a).await,
    }
}
