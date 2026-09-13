// SPDX-License-Identifier: Apache-2.0
//! Honest CPU producer. Plans bind concrete ELF/VK/suite/terms; native evaluation is not proof evidence.
use kai_volume_chunk::{
    evaluate_frames as chunk_eval,
    framing::{decode_block, read_frame, write_frame, Context},
};
use kai_volume_core::{keccak256, parse_nitro_header, VolumeJournalV1, VolumeTermsV1};
use kai_volume_range::{
    framing::{evaluate_frames as range_eval, Request},
    key::{decode_hash_bytes, pack31},
    suite::{suite_domain, Role, VolumeProofSuiteV1, CIRCUIT_IDENTITY},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    light::LightProver, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, RiscvAir,
    SP1Proof, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin, SP1VerifyingKey, StatusCode,
    SP1_CIRCUIT_VERSION,
};
use std::{error::Error, fs, path::Path, time::Instant};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const CHUNK_ELF_SHA256: &str = "d81a33578657f97389f32809739bd8b2a98246372d98ff30581515167762679c";
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn role(s: &str) -> Result<Role> {
    match s {
        "chunk" => Ok(Role::Chunk),
        "range" => Ok(Role::Range),
        _ => Err("role must be chunk or range".into()),
    }
}
fn role_name(r: Role) -> &'static str {
    match r {
        Role::Chunk => "chunk",
        Role::Range => "range",
    }
}
fn record(out: &Path, name: &str, v: &Value) -> Result<()> {
    fs::write(out.join(name), serde_json::to_vec_pretty(v)?)?;
    Ok(())
}
fn frames(b: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut c = b;
    let mut f = Vec::new();
    while let Some(v) = read_frame(&mut c)? {
        f.push(v);
    }
    Ok(f)
}
fn file_frames(f: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    for v in f {
        write_frame(&mut b, v)?;
    }
    Ok(b)
}
fn vk_bytes32(vk: &SP1VerifyingKey) -> Result<[u8; 32]> {
    let bytes: [u8; 32] = hex::decode(vk.bytes32().trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| "SDK VK width")?;
    if pack31(&vk.hash_u32())? != bytes || decode_hash_bytes(&vk.hash_bytes())? != vk.hash_u32() {
        return Err("SDK/canonical key conversion mismatch".into());
    }
    Ok(bytes)
}
fn vk_meta(vk: &SP1VerifyingKey) -> Result<Value> {
    Ok(
        json!({"bytes32":vk.bytes32(),"hashU32":vk.hash_u32(),"hashBytes":hex::encode(vk.hash_bytes()),"bincodeSha256":sha(&bincode::serialize(vk)?)}),
    )
}
fn safety() -> Result<Value> {
    if SP1_CIRCUIT_VERSION.trim() != "v6.1.0" {
        return Err("circuit version".into());
    }
    if std::env::var("WITHOUT_VK_VERIFICATION").is_ok_and(|v| v != "false") {
        return Err("recursion VK verification disabled".into());
    }
    let config = sp1_prover::worker::SP1WorkerConfig::new(RiscvAir::machine());
    let c = &config.prover_config.core_prover_config;
    let r = &config.prover_config.recursion_prover_config;
    if !c.verify_intermediates || !r.verify_intermediates {
        return Err("intermediate verification disabled".into());
    }
    Ok(
        json!({"coreVerifyIntermediates":c.verify_intermediates,"recursionVerifyIntermediates":r.verify_intermediates,
        "coreWorkers":c.num_core_workers,"coreBuffer":c.core_buffer_size,"setupWorkers":c.num_setup_workers,"setupBuffer":c.setup_buffer_size,
        "recursionExecutorWorkers":r.num_recursion_executor_workers,"recursionProverWorkers":r.num_recursion_prover_workers,
        "prepareReduceWorkers":r.num_prepare_reduce_workers,"recursionVkVerification":true}),
    )
}
struct Plan {
    light: LightProver,
    terms: VolumeTermsV1,
    suite: VolumeProofSuiteV1,
    chunk_elf: Vec<u8>,
    range_elf: Vec<u8>,
    chunk_vk: SP1VerifyingKey,
    range_vk: SP1VerifyingKey,
    manifest_sha: String,
    source_sha: String,
}
impl Plan {
    fn vk(&self, r: Role) -> &SP1VerifyingKey {
        match r {
            Role::Chunk => &self.chunk_vk,
            Role::Range => &self.range_vk,
        }
    }
    fn elf(&self, r: Role) -> &[u8] {
        match r {
            Role::Chunk => &self.chunk_elf,
            Role::Range => &self.range_elf,
        }
    }
    async fn load(path: &Path) -> Result<Self> {
        let raw = fs::read(path.join("plan.json"))?;
        let m: Value = serde_json::from_slice(&raw)?;
        let mut data = Vec::new();
        for name in [
            "chunk.elf",
            "range.elf",
            "terms.abi",
            "suite.abi",
            "source-manifest.json",
        ] {
            let b = fs::read(path.join(name))?;
            if m["files"][name]["sha256"].as_str() != Some(sha(&b).as_str()) {
                return Err(format!("frozen plan hash mismatch: {name}").into());
            }
            data.push(b);
        }
        if sha(&data[0]) != CHUNK_ELF_SHA256 {
            return Err("retained chunk ELF mismatch".into());
        }
        let terms = VolumeTermsV1::abi_decode(&data[2])?;
        let suite = VolumeProofSuiteV1::abi_decode(&data[3])?;
        suite.validate_terms(&terms)?;
        let light = ProverClient::builder().light().build().await;
        let chunk_pk = light.setup(Elf::from(data[0].clone())).await?;
        let range_pk = light.setup(Elf::from(data[1].clone())).await?;
        let chunk_vk = chunk_pk.verifying_key().clone();
        let range_vk = range_pk.verifying_key().clone();
        for (role, vk) in [(Role::Chunk, &chunk_vk), (Role::Range, &range_vk)] {
            if vk_bytes32(vk)? != suite.role_key(role) {
                return Err("fresh ELF-derived VK does not match suite".into());
            }
            if bincode::serialize(vk)?
                != fs::read(path.join(format!("{}-vk.bin", role_name(role))))?
            {
                return Err("fresh VK differs from frozen VK".into());
            }
        }
        Ok(Self {
            light,
            terms,
            suite,
            chunk_elf: data[0].clone(),
            range_elf: data[1].clone(),
            chunk_vk,
            range_vk,
            manifest_sha: sha(&raw),
            source_sha: sha(&data[4]),
        })
    }
    fn expected(&self, r: Role, f: &[Vec<u8>]) -> Result<[u8; 800]> {
        let first = f.first().ok_or("empty input")?;
        let mut it = f.iter().cloned();
        match r {
            Role::Chunk => {
                let c = Context::decode(first)?;
                if c.terms != self.terms {
                    return Err("chunk terms differ from frozen plan".into());
                }
                Ok(chunk_eval(|| Ok(it.next()))?.journal)
            }
            Role::Range => {
                let c = Request::decode(first)?;
                if c.terms != self.terms || c.suite != self.suite {
                    return Err("range terms/suite differ from frozen plan".into());
                }
                Ok(range_eval(|| Ok(it.next()))?.journal)
            }
        }
    }
    fn load_child(&self, r: Role, path: &str) -> Result<SP1ProofWithPublicValues> {
        let p = SP1ProofWithPublicValues::load(path)?;
        if !matches!(p.proof, SP1Proof::Compressed(_)) {
            return Err("child must be genuine compressed proof".into());
        }
        self.light
            .verify(&p, self.vk(r), Some(StatusCode::SUCCESS))?;
        VolumeJournalV1::abi_decode(p.public_values.as_slice(), &self.terms)?;
        Ok(p)
    }
    fn stdin(&self, r: Role, f: &[Vec<u8>], paths: &[String]) -> Result<(SP1Stdin, Value)> {
        let mut stdin = SP1Stdin::new();
        for v in f {
            stdin.write_slice(v);
        }
        let mut child_records = Vec::new();
        if r == Role::Chunk {
            if !paths.is_empty() {
                return Err("chunk has no child proof stream".into());
            }
        } else {
            let mut it = f.iter().cloned();
            let pending = range_eval(|| Ok(it.next()))?;
            if paths.len() != pending.children.len() {
                return Err("child proof stream arity mismatch".into());
            }
            for (child, path) in pending.children.iter().zip(paths) {
                let proof = self.load_child(child.role, path)?;
                if proof.public_values.as_slice() != child.journal
                    || self.vk(child.role).hash_u32() != child.vk_words
                {
                    return Err("child proof/context or key mismatch".into());
                }
                child_records.push(json!({"role":role_name(child.role),"proofBundleSha256":sha(&fs::read(path)?),"journalSha256":hex::encode(child.journal_sha256),"vk":vk_meta(self.vk(child.role))?,"sdkExplicitSuccess":"Ok(())"}));
                let SP1Proof::Compressed(p) = proof.proof else {
                    unreachable!()
                };
                stdin.write_proof(*p, self.vk(child.role).vk.clone());
            }
        }
        Ok((stdin, json!(child_records)))
    }
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
    let mut f = Vec::new();
    let mut identities = Vec::new();
    for pair in a[4..].chunks_exact(2) {
        let role = role(&pair[0])?;
        let p = plan.load_child(role, &pair[1])?;
        children.push(VolumeJournalV1::abi_decode(
            p.public_values.as_slice(),
            &plan.terms,
        )?);
        f.extend([
            vec![role as u8],
            plan.vk(role).hash_bytes().to_vec(),
            p.public_values.to_vec(),
        ]);
        identities.push(json!({"role":role_name(role),"proofSha256":sha(&fs::read(&pair[1])?)}));
    }
    let mut output = children[0].clone();
    let last = children.last().unwrap();
    output.to_inclusive = last.to_inclusive;
    output.end_hash = last.end_hash;
    output.volume_quote = Default::default();
    output.qualifying_swap_count = Default::default();
    let req = Request {
        terms: plan.terms.clone(),
        suite: plan.suite.clone(),
        child_count: children.len() as u8,
        output_context: output,
    };
    f.insert(0, req.encode()?);
    let expected = plan.expected(Role::Range, &f)?;
    let out = Path::new(&a[3]);
    let input = file_frames(&f)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?;
    use std::io::Write;
    file.write_all(&input)?;
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
        "syntheticTerms":true,"deployedRaceEstablished":false,"actualFourEntrantRaceAcceptance":false,"resolvedWorkerConfig":safety()?});
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
        let cpu = ProverClient::builder().cpu().build().await;
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
    safety()?;
    sp1_sdk::setup_logger();
    let a: Vec<_> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("freeze-diagnostic") => freeze_diagnostic(&a).await,
        Some("assemble") => assemble(&a).await,
        _ => run(&a).await,
    }
}
