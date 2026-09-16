// SPDX-License-Identifier: Apache-2.0
//! Shared plan, key and framing helpers for the volume hosts.
//!
//! Both host binaries include this module. The per-job phases and the batch
//! `serve` mode use the same code, so a job's input, expected journal and
//! artifacts do not depend on which mode produced them.
use kai_volume_chunk::{
    evaluate_frames as chunk_eval,
    framing::{read_frame, write_frame, Context},
};
use kai_volume_core::{VolumeJournalV1, VolumeTermsV1};
use kai_volume_range::{
    framing::{evaluate_frames as range_eval, ChildClaim, Request},
    key::{decode_hash_bytes, pack31},
    suite::{Role, VolumeProofSuiteV1},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    light::LightProver, Elf, HashableKey, Prover, ProverClient, ProvingKey, RiscvAir, SP1Proof,
    SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey, StatusCode, SP1_CIRCUIT_VERSION,
};
use std::{
    error::Error,
    fs,
    io::Read,
    path::{Path, PathBuf},
};
pub const CHUNK_ELF_SHA256: &str = "65f03aa5cb1a26e6640f4a100174e721020b13450a7ffe201c8fa3d3d5ed6fbd";
type Result<T> = std::result::Result<T, Box<dyn Error>>;

// SDK 6.7.0 embeds the runner override at BUILD time. A runtime environment
// variable cannot relocate it. Refuse a different path instead of silently
// executing an unpinned helper; public users build with their own pinned path.
pub fn runner_binding() -> Result<()> {
    let compiled = option_env!("SP1_CORE_RUNNER_OVERRIDE_BINARY")
        .ok_or("build host with an explicit pinned external runner")?;
    let selected = std::env::var("SP1_CORE_RUNNER_OVERRIDE_BINARY")?;
    if fs::canonicalize(compiled)? != fs::canonicalize(selected)? {
        return Err("runtime runner differs from SDK build-time binding; rebuild host at your own pinned path".into());
    }
    Ok(())
}
pub fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
pub fn role(s: &str) -> Result<Role> {
    match s {
        "chunk" => Ok(Role::Chunk),
        "range" => Ok(Role::Range),
        _ => Err("role must be chunk or range".into()),
    }
}
pub fn role_name(r: Role) -> &'static str {
    match r {
        Role::Chunk => "chunk",
        Role::Range => "range",
    }
}
pub fn record(out: &Path, name: &str, v: &Value) -> Result<()> {
    fs::write(out.join(name), serde_json::to_vec_pretty(v)?)?;
    Ok(())
}
pub fn frames(b: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut c = b;
    let mut f = Vec::new();
    while let Some(v) = read_frame(&mut c)? {
        f.push(v);
    }
    Ok(f)
}
pub fn file_frames(f: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    for v in f {
        write_frame(&mut b, v)?;
    }
    Ok(b)
}
pub fn vk_bytes32(vk: &SP1VerifyingKey) -> Result<[u8; 32]> {
    let bytes: [u8; 32] = hex::decode(vk.bytes32().trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| "SDK VK width")?;
    if pack31(&vk.hash_u32())? != bytes || decode_hash_bytes(&vk.hash_bytes())? != vk.hash_u32() {
        return Err("SDK/canonical key conversion mismatch".into());
    }
    Ok(bytes)
}
pub fn vk_meta(vk: &SP1VerifyingKey) -> Result<Value> {
    Ok(
        json!({"bytes32":vk.bytes32(),"hashU32":vk.hash_u32(),"hashBytes":hex::encode(vk.hash_bytes()),"bincodeSha256":sha(&bincode::serialize(vk)?)}),
    )
}
pub fn safety() -> Result<Value> {
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
pub struct Plan {
    pub dir: PathBuf,
    pub light: LightProver,
    pub terms: VolumeTermsV1,
    pub suite: VolumeProofSuiteV1,
    pub chunk_elf: Vec<u8>,
    pub range_elf: Vec<u8>,
    pub chunk_vk: SP1VerifyingKey,
    pub range_vk: SP1VerifyingKey,
    pub manifest_sha: String,
    pub source_sha: String,
    pub context_origin: String,
}

impl Plan {
    pub fn vk(&self, r: Role) -> &SP1VerifyingKey {
        match r {
            Role::Chunk => &self.chunk_vk,
            Role::Range => &self.range_vk,
        }
    }
    pub fn elf(&self, r: Role) -> &[u8] {
        match r {
            Role::Chunk => &self.chunk_elf,
            Role::Range => &self.range_elf,
        }
    }
    pub async fn load(path: &Path) -> Result<Self> {
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
            dir: path.to_path_buf(),
            light,
            terms,
            suite,
            chunk_elf: data[0].clone(),
            range_elf: data[1].clone(),
            chunk_vk,
            range_vk,
            manifest_sha: sha(&raw),
            source_sha: sha(&data[4]),
            context_origin: m["contextOrigin"]
                .as_str()
                .unwrap_or("diagnostic-synthetic")
                .to_owned(),
        })
    }
    pub fn expected(&self, r: Role, f: &[Vec<u8>]) -> Result<[u8; 800]> {
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
    pub fn load_child(&self, r: Role, path: &str) -> Result<SP1ProofWithPublicValues> {
        let p = SP1ProofWithPublicValues::load(path)?;
        if !matches!(p.proof, SP1Proof::Compressed(_)) {
            return Err("child must be genuine compressed proof".into());
        }
        self.light
            .verify(&p, self.vk(r), Some(StatusCode::SUCCESS))?;
        VolumeJournalV1::abi_decode(p.public_values.as_slice(), &self.terms)?;
        Ok(p)
    }
    pub fn stdin(&self, r: Role, f: &[Vec<u8>], paths: &[String]) -> Result<(SP1Stdin, Value)> {
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

/// The child claims of a range frame file, in frame order.
pub fn range_children(f: &[Vec<u8>]) -> Result<Vec<ChildClaim>> {
    let mut it = f.iter().cloned();
    Ok(range_eval(|| Ok(it.next()))?.children)
}

/// Builds the range request frames for a child list, exactly as the `assemble`
/// phase does. The batch runner uses this so a whole race can run in one
/// process. Returns the frame-file bytes and the child identity records.
pub fn assemble_frames(plan: &Plan, children: &[(Role, String)]) -> Result<(Vec<u8>, Value)> {
    if children.is_empty() || children.len() > 2 {
        return Err("range input takes one or two children".into());
    }
    let mut journals = Vec::new();
    let mut f = Vec::new();
    let mut identities = Vec::new();
    for (role, path) in children {
        let p = plan.load_child(*role, path)?;
        journals.push(VolumeJournalV1::abi_decode(
            p.public_values.as_slice(),
            &plan.terms,
        )?);
        f.extend([
            vec![*role as u8],
            plan.vk(*role).hash_bytes().to_vec(),
            p.public_values.to_vec(),
        ]);
        identities.push(json!({"role":role_name(*role),"proofSha256":sha(&fs::read(path)?)}));
    }
    let mut output = journals[0].clone();
    let last = journals.last().unwrap();
    output.to_inclusive = last.to_inclusive;
    output.end_hash = last.end_hash;
    output.volume_quote = Default::default();
    output.qualifying_swap_count = Default::default();
    let req = Request {
        terms: plan.terms.clone(),
        suite: plan.suite.clone(),
        child_count: journals.len() as u8,
        output_context: output,
    };
    f.insert(0, req.encode()?);
    // The expected journal is built here so a bad child list fails before any
    // proving work starts.
    plan.expected(Role::Range, &f)?;
    Ok((file_frames(&f)?, json!(identities)))
}

pub fn cache_gate(manifest: &[u8]) -> Result<Value> {
    let manifest: Value = serde_json::from_slice(manifest)?;
    let base = std::env::var("SP1_GROTH16_CIRCUIT_PATH")?;
    let dir = Path::new(&base).join("v6.1.0");
    if sp1_prover::build::groth16_circuit_artifacts_dir()? != dir
        || !dir.join(".complete").is_file()
    {
        return Err("existing complete v6.1.0 cache required; no install/download allowed".into());
    }
    let approved = [
        (
            "groth16_vk.bin",
            "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696",
        ),
        (
            "groth16_pk.bin",
            "c3760e0e3b58487f8704680d5b3ad32a9fbca9f3cb0749d69055c4f1271ca167",
        ),
        (
            "groth16_circuit.bin",
            "d6a66be2702206e2b1a20bebf7096142864feac9e399a309e5e6e00353264cbc",
        ),
    ];
    let files = manifest["files"]
        .as_array()
        .ok_or("parameter manifest files")?;
    for (name, digest) in approved {
        if !files
            .iter()
            .any(|f| f["file"] == name && f["sha256"] == digest)
        {
            return Err("manifest lacks approved parameter identity".into());
        }
    }
    let mut records = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for f in files {
        let name = f["file"].as_str().ok_or("parameter filename")?;
        if Path::new(name).components().count() != 1 || name == ".." || !names.insert(name) {
            return Err("parameter path/duplicate".into());
        }
        let mut file = fs::File::open(dir.join(name))?;
        let size = file.metadata()?.len();
        let mut h = Sha256::new();
        let mut b = [0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut b)?;
            if n == 0 {
                break;
            }
            h.update(&b[..n]);
        }
        let digest = hex::encode(h.finalize());
        if f["bytes"].as_u64() != Some(size) || f["sha256"].as_str() != Some(digest.as_str()) {
            return Err(format!("parameter integrity mismatch: {name}").into());
        }
        records.push(json!({"file":name,"bytes":size,"sha256":digest}));
    }
    Ok(json!({"verifiedFiles":records,"downloads":false,"ceremonyRegenerated":false}))
}
