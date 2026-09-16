// SPDX-License-Identifier: Apache-2.0
//! Persistent batch runner for the volume hosts.
//!
//! `serve --jobs LIST.json` initialises the plan, the prover and both program
//! keys once, then runs every job in the list in order: chunk proofs, then
//! range merges, then the Groth16 root. Per-job artifacts keep the names,
//! formats and metric keys of the per-job phases, so assemble/verify tooling is
//! unchanged.
//!
//! A job whose `proof.bin` already exists is loaded, SDK-verified against the
//! frozen statement and skipped. A crashed batch therefore resumes instead of
//! re-proving, and it never overwrites retained artifacts.
//!
//! All paths in the job list resolve against the directory of the list file.
use crate::plan::{self, Plan};
use crate::prover_backend;
use kai_volume_core::keccak256;
use kai_volume_range::suite::Role;
use serde_json::{json, Value};
use sp1_sdk::{
    env::EnvProvingKey, Elf, HashableKey, ProveRequest, Prover, ProvingKey,
    SP1ProofWithPublicValues, SP1Proof, SP1Stdin, StatusCode,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The accepted job-list schema tag.
pub const JOBLIST_KIND: &str = "kai-volume-range-batch/v1";

/// One scheduled job.
#[derive(Clone)]
struct Job {
    id: String,
    form: String,
    role: Option<Role>,
    frames: PathBuf,
    out: PathBuf,
    children: Vec<(Role, PathBuf)>,
    parameter_manifest: Option<PathBuf>,
    source_manifest: Option<PathBuf>,
    /// Optional GPU pin for the two-GPU coordinator. `None` means balanced.
    gpu: Option<u32>,
}

/// `serve --jobs LIST.json [--gpus 0,1]`
///
/// Without `--gpus` one worker runs the whole list in order. With `--gpus` the
/// coordinator runs the independent jobs on one worker process per device and
/// then the dependent jobs (range merges, root) in one worker.
pub async fn serve(args: &[String]) -> Result<()> {
    let mut path: Option<String> = None;
    let mut gpus: Vec<u32> = Vec::new();
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--jobs" if path.is_none() => {
                path = Some(
                    args.get(index + 1)
                        .ok_or("serve --jobs LIST.json [--gpus 0,1]")?
                        .clone(),
                );
                index += 2;
            }
            "--gpus" if gpus.is_empty() => {
                let raw = args.get(index + 1).ok_or("serve --gpus 0,1")?;
                gpus = parse_gpus(raw)?;
                index += 2;
            }
            _ => return Err("serve --jobs LIST.json [--gpus 0,1]".into()),
        }
    }
    let path = path.ok_or("serve --jobs LIST.json [--gpus 0,1]")?;
    let summary = match gpus.len() {
        0 | 1 => run_jobs(Path::new(&path)).await?,
        _ => run_jobs_on_gpus(Path::new(&path), &gpus).await?,
    };
    println!("{summary}");
    Ok(())
}

/// Parses `--gpus 0,1`. Repeats are allowed, so `--gpus 0,0` runs two workers
/// on one device (the CPU-mode test uses this).
fn parse_gpus(raw: &str) -> Result<Vec<u32>> {
    if raw.is_empty() {
        return Err("--gpus needs a comma-separated device list, for example 0,1".into());
    }
    let mut gpus = Vec::new();
    for part in raw.split(',') {
        let device: u32 = part
            .trim()
            .parse()
            .map_err(|_| format!("--gpus: {part} is not a device index"))?;
        gpus.push(device);
    }
    Ok(gpus)
}

fn str_field(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("job list: missing string field {key}").into())
}

/// Rejects a job list that cannot run in order. Call it before the plan load, so
/// a bad list fails before any proving work.
///
/// Rules:
/// - every job id is unique;
/// - every output directory is unique, so no job overwrites another job's artifacts;
/// - every child is either an existing file or the output of an earlier job in
///   the same list, and no job consumes its own output;
/// - a `groth16` job consumes children.
fn validate_jobs(jobs: &[Job]) -> Result<()> {
    if jobs.is_empty() {
        return Err("job list: no jobs".into());
    }
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    let mut outs: BTreeSet<&Path> = BTreeSet::new();
    for job in jobs {
        if !ids.insert(job.id.as_str()) {
            return Err(format!("job list: duplicate job id {}", job.id).into());
        }
        if !outs.insert(job.out.as_path()) {
            return Err(format!(
                "job {}: output {} is used by another job",
                job.id,
                job.out.display()
            )
            .into());
        }
        if job.form == "groth16" && job.children.is_empty() {
            return Err(format!("job {}: a groth16 job needs children", job.id).into());
        }
    }
    // Which job produces which proof, so a child can name its producer.
    let producers: BTreeMap<PathBuf, &str> = jobs
        .iter()
        .map(|job| (job.out.join("proof.bin"), job.id.as_str()))
        .collect();
    for (index, job) in jobs.iter().enumerate() {
        for (role, path) in &job.children {
            if path == &job.out.join("proof.bin") {
                return Err(format!("job {}: it lists its own proof as a child", job.id).into());
            }
            match producers.get(path) {
                Some(producer) => {
                    let at = jobs
                        .iter()
                        .position(|candidate| candidate.id == *producer)
                        .unwrap_or(usize::MAX);
                    if at >= index {
                        return Err(format!(
                            "job {} ({} child): {} is produced later by job {}; move job {} before job {}",
                            job.id,
                            plan::role_name(*role),
                            path.display(),
                            producer,
                            producer,
                            job.id
                        )
                        .into());
                    }
                }
                None if !path.is_file() => {
                    return Err(format!(
                        "job {} ({} child): {} is not produced by an earlier job and does not exist",
                        job.id,
                        plan::role_name(*role),
                        path.display()
                    )
                    .into());
                }
                None => {}
            }
        }
    }
    Ok(())
}

fn parse_jobs(doc: &Value, base: &Path) -> Result<Vec<Job>> {
    let list = doc
        .get("jobs")
        .and_then(Value::as_array)
        .ok_or("job list: jobs array")?;
    let mut jobs = Vec::new();
    for entry in list {
        let id = str_field(entry, "id")?;
        let form = entry
            .get("form")
            .and_then(Value::as_str)
            .unwrap_or("compressed")
            .to_owned();
        if !matches!(form.as_str(), "compressed" | "groth16") {
            return Err(format!("job {id}: form must be compressed or groth16").into());
        }
        let role = match entry.get("role").and_then(Value::as_str) {
            None => None,
            Some(name) => Some(
                plan::role(name).map_err(|_| format!("job {id}: role must be chunk or range"))?,
            ),
        };
        let frames = base.join(str_field(entry, "frames")?);
        let out = base.join(str_field(entry, "out")?);
        let mut children = Vec::new();
        if let Some(raw) = entry.get("children") {
            let raw = raw
                .as_array()
                .ok_or_else(|| format!("job {id}: children must be an array"))?;
            for pair in raw {
                let pair = pair
                    .as_array()
                    .ok_or_else(|| format!("job {id}: child must be [role, path]"))?;
                if pair.len() != 2 {
                    return Err(format!("job {id}: child must be [role, path]").into());
                }
                let child_role = plan::role(pair[0].as_str().unwrap_or("chunk"))?;
                let child_path = pair[1]
                    .as_str()
                    .ok_or_else(|| format!("job {id}: child path"))?;
                children.push((child_role, base.join(child_path)));
            }
        }
        let gpu = match entry.get("gpu") {
            None => None,
            Some(value) => {
                let index = value
                    .as_u64()
                    .ok_or_else(|| format!("job {id}: gpu must be a device index"))?;
                Some(u32::try_from(index).map_err(|_| format!("job {id}: gpu index is too large"))?)
            }
        };
        let parameter_manifest = entry
            .get("parameterManifest")
            .and_then(Value::as_str)
            .map(|p| base.join(p));
        let source_manifest = entry
            .get("sourceManifest")
            .and_then(Value::as_str)
            .map(|p| base.join(p));
        jobs.push(Job {
            id,
            form,
            role,
            frames,
            out,
            children,
            parameter_manifest,
            source_manifest,
            gpu,
        });
    }
    Ok(jobs)
}

/// Reads one job list, checks its kind and resolves its plan directory.
fn read_list(list_path: &Path) -> Result<(Value, PathBuf, PathBuf, Vec<Job>)> {
    let raw = fs::read(list_path)?;
    let doc: Value = serde_json::from_slice(&raw)?;
    if doc.get("kind").and_then(Value::as_str) != Some(JOBLIST_KIND) {
        return Err(format!("job list kind must be {JOBLIST_KIND}").into());
    }
    let base = list_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let plan_dir = base.join(doc.get("plan").and_then(Value::as_str).ok_or("job list: plan")?);
    let jobs = parse_jobs(&doc, &base)?;
    // Fail before the plan load and any proving work.
    validate_jobs(&jobs)?;
    Ok((doc, base, plan_dir, jobs))
}

/// Runs one job list. Returns the batch summary.
pub async fn run_jobs(list_path: &Path) -> Result<Value> {
    let (_doc, _base, plan_dir, jobs) = read_list(list_path)?;
    run_parsed(plan_dir, &jobs).await
}

/// Runs the given jobs with one plan load, one prover and one key set.
async fn run_parsed(plan_dir: PathBuf, jobs: &[Job]) -> Result<Value> {
    let t0 = Instant::now();
    let plan = Plan::load(&plan_dir).await?;
    let plan_seconds = t0.elapsed().as_secs_f64();
    // One prover for the whole batch. On the CUDA path this is where the GPU
    // server starts, so it is paid once instead of once per job.
    let prover = prover_backend::build_prover().await?;
    let prover_seconds = t0.elapsed().as_secs_f64() - plan_seconds;
    let one_time_seconds = t0.elapsed().as_secs_f64();
    let backend = prover_backend::backend()?.prover_label();

    let mut keys: BTreeMap<&'static str, EnvProvingKey> = BTreeMap::new();
    let mut key_seconds: BTreeMap<&'static str, f64> = BTreeMap::new();
    let mut records = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        let started = Instant::now();
        let record = match job.form.as_str() {
            "compressed" => {
                run_compressed(
                    &plan, &prover, &mut keys, &mut key_seconds, job, index, one_time_seconds,
                    plan_seconds, prover_seconds, backend, started,
                )
                .await?
            }
            "groth16" => {
                #[cfg(feature = "groth16-native")]
                {
                    run_groth16(
                        &plan, &prover, &mut keys, &mut key_seconds, job, index,
                        one_time_seconds, plan_seconds, prover_seconds, backend, started,
                    )
                    .await?
                }
                #[cfg(not(feature = "groth16-native"))]
                {
                    return Err(format!(
                        "job {}: this host has no groth16-native feature; build that binary or run the root with volume-range-groth16",
                        job.id
                    )
                    .into())
                }
            }
            other => return Err(format!("job {}: unknown form {other}", job.id).into()),
        };
        let mut record = record;
        record["seconds"] = json!(started.elapsed().as_secs_f64());
        records.push(record);
    }

    let mut summary = json!({
        "kind": "kai-volume-range-batch-result/v1",
        "plan": plan_dir,
        "planSha256": plan.manifest_sha,
        "backend": backend,
        "jobCount": jobs.len(),
        "jobs": records,
        "planLoadSeconds": plan_seconds,
        "proverInitSeconds": prover_seconds,
        "oneTimeSetupSeconds": one_time_seconds,
        "keySetupSecondsByRole": key_seconds,
        "batchWallSeconds": t0.elapsed().as_secs_f64(),
    });
    // A worker reports the device the coordinator gave it.
    if let Ok(gpu) = std::env::var("KAI_BATCH_GPU") {
        if let Ok(index) = gpu.parse::<u32>() {
            summary["gpu"] = json!(index);
        }
    }
    Ok(summary)
}

/// The weight used to balance the parallel jobs: the frame bytes on disk.
/// A missing file weighs 1, so the split still runs and the job reports the
/// read error itself.
fn job_weight(job: &Job) -> u64 {
    fs::metadata(&job.frames).map(|meta| meta.len()).unwrap_or(1)
}

/// Splits the list into the jobs that can run in parallel and the jobs that
/// depend on them. A job is parallel when it consumes no child: a chunk proof
/// does not depend on another chunk, even when a later range merge consumes it.
/// The dependent jobs keep list order, so the range merges and the root still
/// run after every chunk exists. `validate_jobs` already refused a list whose
/// dependent job appears before its children.
fn parallel_and_tail(jobs: &[Job]) -> (Vec<usize>, Vec<usize>) {
    let mut parallel = Vec::new();
    let mut tail = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        if job.children.is_empty() {
            parallel.push(index);
        } else {
            tail.push(index);
        }
    }
    (parallel, tail)
}

/// Assigns the parallel jobs to the given devices. A pinned job goes to its
/// device; the rest use longest-processing-time-first on `job_weight`, so the
/// heaviest frames are placed first onto the least loaded device.
fn assign_jobs(jobs: &[Job], parallel: &[usize], gpus: &[u32]) -> Result<Vec<Vec<usize>>> {
    if gpus.is_empty() {
        return Err("--gpus needs at least one device".into());
    }
    let mut slices: Vec<Vec<usize>> = vec![Vec::new(); gpus.len()];
    let mut load: Vec<u64> = vec![0; gpus.len()];
    let mut loose: Vec<usize> = Vec::new();
    for index in parallel {
        match jobs[*index].gpu {
            None => loose.push(*index),
            Some(device) => {
                let at = gpus.iter().position(|entry| *entry == device).ok_or_else(|| {
                    format!(
                        "job {}: gpu {device} is not in --gpus {}",
                        jobs[*index].id,
                        gpus.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
                    )
                })?;
                load[at] += job_weight(&jobs[*index]);
                slices[at].push(*index);
            }
        }
    }
    loose.sort_by_key(|index| std::cmp::Reverse(job_weight(&jobs[*index])));
    for index in loose {
        let at = load
            .iter()
            .enumerate()
            .min_by_key(|(_, weight)| **weight)
            .map(|(at, _)| at)
            .unwrap_or(0);
        load[at] += job_weight(&jobs[index]);
        slices[at].push(index);
    }
    // Keep list order inside a slice, so a slice log reads like the full list.
    for slice in slices.iter_mut() {
        slice.sort_unstable();
    }
    Ok(slices)
}

/// Runs the parallel jobs on one worker process per device, then the dependent
/// jobs in this process. A failed worker stops the run and leaves the other
/// worker's artifacts on disk.
pub async fn run_jobs_on_gpus(list_path: &Path, gpus: &[u32]) -> Result<Value> {
    let (doc, base, plan_dir, jobs) = read_list(list_path)?;
    let entries = doc
        .get("jobs")
        .and_then(Value::as_array)
        .cloned()
        .ok_or("job list: jobs array")?;
    let (parallel, tail) = parallel_and_tail(&jobs);
    if parallel.is_empty() || gpus.len() < 2 {
        return run_parsed(plan_dir, &jobs).await;
    }
    let slices = assign_jobs(&jobs, &parallel, gpus)?;
    let plan_ref = doc
        .get("plan")
        .cloned()
        .ok_or("job list: plan")?;
    let binary = match std::env::var("KAI_BATCH_WORKER_BIN") {
        Ok(path) => PathBuf::from(path),
        Err(_) => std::env::current_exe()?,
    };

    let started = Instant::now();
    let mut spawned = Vec::new();
    for (at, device) in gpus.iter().enumerate() {
        if slices[at].is_empty() {
            continue;
        }
        let ids: Vec<String> = slices[at].iter().map(|index| jobs[*index].id.clone()).collect();
        // Name the slice by worker position: `--gpus 0,0` runs two workers on
        // one device, so a device-derived name would collide.
        let slice_path = base.join(format!("jobs.worker{at}.json"));
        let slice = json!({
            "kind": JOBLIST_KIND,
            "plan": plan_ref,
            "jobs": slices[at].iter().map(|index| entries[*index].clone()).collect::<Vec<_>>(),
        });
        fs::write(&slice_path, serde_json::to_vec_pretty(&slice)?)?;
        // A private TMPDIR per worker: the SP1 GPU prover extracts its helper
        // binary and uses temporary files there, so concurrent workers must not
        // share one directory.
        let worker_tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
        let worker_tmp = PathBuf::from(worker_tmp).join(format!("worker-{at}"));
        fs::create_dir_all(&worker_tmp)?;
        let child = Command::new(&binary)
            .arg("serve")
            .arg("--jobs")
            .arg(&slice_path)
            .env("CUDA_VISIBLE_DEVICES", device.to_string())
            .env("KAI_BATCH_GPU", device.to_string())
            .env("TMPDIR", worker_tmp)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("gpu {device} worker did not start: {error}"))?;
        eprintln!(
            "batch: gpu {device} worker started, {} job(s): {}",
            ids.len(),
            ids.join(",")
        );
        spawned.push((*device, ids, child));
    }

    let mut workers = Vec::new();
    let mut failed: Option<String> = None;
    for (device, ids, child) in spawned {
        let output = child
            .wait_with_output()
            .map_err(|error| format!("gpu {device} worker did not finish: {error}"))?;
        if !output.status.success() {
            failed = Some(format!(
                "gpu {device} worker failed with {}; its jobs were {}; the other workers' artifacts are on disk",
                output.status,
                ids.join(",")
            ));
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let summary: Value = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .last()
            .ok_or_else(|| format!("gpu {device} worker printed no summary"))
            .and_then(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("gpu {device} worker summary is not JSON: {error}"))
            })?;
        workers.push(json!({
            "gpu": device,
            "jobs": ids,
            "seconds": summary["batchWallSeconds"],
            "planLoadSeconds": summary["planLoadSeconds"],
            "proverInitSeconds": summary["proverInitSeconds"],
            "oneTimeSetupSeconds": summary["oneTimeSetupSeconds"],
            "jobs_detail": summary["jobs"],
        }));
    }
    if let Some(reason) = failed {
        return Err(reason.into());
    }
    let parallel_seconds = started.elapsed().as_secs_f64();

    // The dependent jobs run in this process. The retained chunk proofs make
    // this a verify-and-skip pass for the chunks and real work for the merges.
    let tail_started = Instant::now();
    let tail_jobs: Vec<Job> = tail.iter().map(|index| jobs[*index].clone()).collect();
    let tail_summary = run_parsed(plan_dir, &tail_jobs).await?;
    let tail_seconds = tail_started.elapsed().as_secs_f64();

    // Merge the per-job records in list order.
    let mut records: Vec<Value> = Vec::with_capacity(jobs.len());
    for (index, job) in jobs.iter().enumerate() {
        let found = if tail.contains(&index) {
            tail_summary["jobs"]
                .as_array()
                .and_then(|all| all.iter().find(|record| record["id"].as_str() == Some(&job.id)))
                .cloned()
        } else {
            workers
                .iter()
                .find(|worker| {
                    worker["jobs"]
                        .as_array()
                        .map(|ids| ids.iter().any(|id| id.as_str() == Some(&job.id)))
                        .unwrap_or(false)
                })
                .and_then(|worker| {
                    worker["jobs_detail"]
                        .as_array()
                        .and_then(|all| all.iter().find(|record| record["id"].as_str() == Some(&job.id)))
                        .cloned()
                })
        };
        records.push(found.ok_or_else(|| format!("job {}: no record from a worker", job.id))?);
    }

    let worker_setup: f64 = workers
        .iter()
        .map(|worker| worker["oneTimeSetupSeconds"].as_f64().unwrap_or(0.0))
        .sum();
    Ok(json!({
        "kind": "kai-volume-range-batch-result/v1",
        "plan": tail_summary["plan"],
        "planSha256": tail_summary["planSha256"],
        "backend": tail_summary["backend"],
        "gpuCount": gpus.len(),
        "jobCount": jobs.len(),
        "jobs": records,
        "workers": workers,
        "parallelJobCount": parallel.len(),
        "parallelWallSeconds": parallel_seconds,
        "tailSeconds": tail_seconds,
        "planLoadSeconds": tail_summary["planLoadSeconds"],
        "proverInitSeconds": tail_summary["proverInitSeconds"],
        "oneTimeSetupSeconds": tail_summary["oneTimeSetupSeconds"],
        "oneTimeSetupSecondsTotal": worker_setup + tail_summary["oneTimeSetupSeconds"].as_f64().unwrap_or(0.0),
        "keySetupSecondsByRole": tail_summary["keySetupSecondsByRole"],
        "batchWallSeconds": started.elapsed().as_secs_f64(),
    }))
}

fn role_name(role: Role) -> &'static str {
    plan::role_name(role)
}

/// The frame builder takes owned path strings; the job list keeps PathBuf.
fn child_argument(children: &[(Role, PathBuf)]) -> Vec<(Role, String)> {
    children
        .iter()
        .map(|(role, path)| (*role, path.to_string_lossy().into_owned()))
        .collect()
}

/// The metrics object shared by both forms, with the per-job keys of the
/// per-job phases.
#[allow(clippy::too_many_arguments)]
fn base_metrics(
    plan: &Plan,
    role: Role,
    input: &[u8],
    expected: &[u8],
    job: &Job,
    index: usize,
    one_time_seconds: f64,
    plan_seconds: f64,
    prover_seconds: f64,
    key_seconds: &BTreeMap<&'static str, f64>,
    backend: &str,
) -> Result<Value> {
    Ok(json!({
        "release": env!("CARGO_PKG_VERSION"),
        "phase": "prove",
        "role": role_name(role),
        "sdkVersion": "6.7.0",
        "circuitVersion": "v6.1.0",
        "planSha256": plan.manifest_sha,
        "sourceManifestSha256": plan.source_sha,
        "guestElfSha256": plan::sha(plan.elf(role)),
        "vk": plan::vk_meta(plan.vk(role))?,
        "suiteHash": hex::encode(plan.suite.suite_hash()?),
        "termsHash": hex::encode(plan.terms.terms_hash()?),
        "inputSha256": plan::sha(input),
        "inputBytes": input.len(),
        "nativeJournalSha256": plan::sha(expected),
        "cryptographicProofGenerated": false,
        "cryptographicProofVerified": false,
        "contextOrigin": plan.context_origin,
        "deployedRaceEstablished": false,
        "actualFourEntrantRaceAcceptance": false,
        "resolvedWorkerConfig": plan::safety()?,
        "backend": backend,
        "batch": {
            "jobId": job.id,
            "jobIndex": index,
            "form": job.form,
            "planLoadSeconds": plan_seconds,
            "proverInitSeconds": prover_seconds,
            "oneTimeSetupSeconds": one_time_seconds,
            "keySetupSecondsByRole": key_seconds,
            "resumed": false,
        },
    }))
}

/// Enough of the per-job metrics to identify the statement before any proving
/// work starts. The per-job phases write the same keys.
fn save_early(job: &Job, m: &Value, expected: &[u8], plan: &Plan, role: Role) -> Result<()> {
    fs::create_dir_all(&job.out)?;
    fs::write(job.out.join("native-journal.bin"), expected)?;
    fs::write(
        job.out.join("program-vk.bin"),
        bincode::serialize(plan.vk(role))?,
    )?;
    plan::record(&job.out, "metrics.json", m)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_compressed(
    plan: &Plan,
    prover: &sp1_sdk::env::EnvProver,
    keys: &mut BTreeMap<&'static str, EnvProvingKey>,
    key_seconds: &mut BTreeMap<&'static str, f64>,
    job: &Job,
    index: usize,
    one_time_seconds: f64,
    plan_seconds: f64,
    prover_seconds: f64,
    backend: &str,
    job_started: Instant,
) -> Result<Value> {
    let role = job
        .role
        .ok_or_else(|| format!("job {}: compressed job needs a role", job.id))?;
    // Build the range input from the children when the frame file is absent.
    let input = match fs::read(&job.frames) {
        Ok(bytes) => bytes,
        Err(_) if !job.children.is_empty() => {
            let (bytes, _identities) = plan::assemble_frames(plan, &child_argument(&job.children))?;
            if let Some(dir) = job.frames.parent() {
                fs::create_dir_all(dir)?;
            }
            fs::write(&job.frames, &bytes)?;
            bytes
        }
        Err(error) => {
            return Err(format!(
                "job {}: cannot read frames {}: {error}",
                job.id,
                job.frames.display()
            )
            .into())
        }
    };
    let f = plan::frames(&input)?;
    let expected = plan.expected(role, &f)?;
    let child_paths: Vec<String> = job
        .children
        .iter()
        .map(|(_, p)| p.to_string_lossy().into_owned())
        .collect();
    let mut m = base_metrics(
        plan, role, &input, &expected, job, index, one_time_seconds, plan_seconds, prover_seconds,
        key_seconds, backend,
    )?;
    let proof_path = job.out.join("proof.bin");
    // Resume: verify the retained proof instead of re-proving it.
    if proof_path.is_file() {
        let retained = SP1ProofWithPublicValues::load(&proof_path)?;
        if !matches!(retained.proof, SP1Proof::Compressed(_)) {
            return Err(format!("job {}: retained proof is not compressed", job.id).into());
        }
        plan.light
            .verify(&retained, plan.vk(role), Some(StatusCode::SUCCESS))?;
        if retained.public_values.as_slice() != expected {
            return Err(format!(
                "job {}: retained proof journal differs from the frozen statement",
                job.id
            )
            .into());
        }
        return Ok(json!({
            "id": job.id,
            "role": role_name(role),
            "status": "compressed-proof-sdk-verified",
            "resumed": true,
            "proofBundleSha256": plan::sha(&fs::read(&proof_path)?),
            "publicValuesSha256": plan::sha(retained.public_values.as_slice()),
        }));
    }
    save_early(job, &m, &expected, plan, role)?;

    let (stdin, child_records) = plan.stdin(role, &f, &child_paths)?;
    m["children"] = child_records;
    let stdin_bytes = bincode::serialize(&stdin)?;
    m["stdinBincodeSha256"] = json!(plan::sha(&stdin_bytes));
    fs::write(job.out.join("stdin.bin"), stdin_bytes)?;

    // The program key is built once per role and reused by every later job.
    let name = role_name(role);
    let mut setup_here = 0.0_f64;
    if !keys.contains_key(name) {
        let t = Instant::now();
        let pk = prover.setup(Elf::from(plan.elf(role).to_vec())).await?;
        if bincode::serialize(pk.verifying_key())? != bincode::serialize(plan.vk(role))? {
            return Err("prover key differs from the frozen plan VK".into());
        }
        setup_here = t.elapsed().as_secs_f64();
        key_seconds.insert(name, setup_here);
        keys.insert(name, pk);
    }
    m["setupSeconds"] = json!(setup_here);
    m["status"] = json!("proof-starting");
    plan::record(&job.out, "metrics.json", &m)?;
    let pk = keys.get(name).ok_or("prover key missing")?;

    let t = Instant::now();
    let proof = prover
        .prove(pk, stdin)
        .compressed()
        .expected_exit_code(StatusCode::SUCCESS)
        .await?;
    m["proveSeconds"] = json!(t.elapsed().as_secs_f64());
    if !matches!(proof.proof, SP1Proof::Compressed(_))
        || proof.public_values.as_slice() != expected
    {
        return Err(format!("job {}: candidate form/public mismatch", job.id).into());
    }
    proof.save(&proof_path)?;
    m["cryptographicProofGenerated"] = json!(true);
    m["status"] = json!("candidate-saved-verification-pending");
    plan::record(&job.out, "metrics.json", &m)?;
    let t = Instant::now();
    prover.verify(&proof, pk.verifying_key(), Some(StatusCode::SUCCESS))?;
    m["verificationSeconds"] = json!(t.elapsed().as_secs_f64());
    m["sdkExplicitSuccessResult"] = json!("Ok(())");

    let bundle = bincode::serialize(&proof)?;
    m["proofBundleSha256"] = json!(plan::sha(&bundle));
    m["proofBundleBytes"] = json!(bundle.len());
    m["proofPayloadBincodeSha256"] = json!(plan::sha(&bincode::serialize(&proof.proof)?));
    m["publicValuesSha256"] = json!(plan::sha(proof.public_values.as_slice()));
    m["statementIdKeccak256"] = json!(hex::encode(keccak256(proof.public_values.as_slice())));
    m["publicValuesBytes"] = json!(proof.public_values.as_slice().len());
    fs::write(
        job.out.join("public-values.bin"),
        proof.public_values.as_slice(),
    )?;
    m["status"] = json!("compressed-proof-sdk-verified");
    m["cryptographicProofVerified"] = json!(true);
    m["elapsedSeconds"] = json!(job_started.elapsed().as_secs_f64());
    plan::record(&job.out, "metrics.json", &m)?;
    Ok(json!({
        "id": job.id,
        "role": role_name(role),
        "status": "compressed-proof-sdk-verified",
        "resumed": false,
        "setupSeconds": setup_here,
        "proveSeconds": m["proveSeconds"],
        "verificationSeconds": m["verificationSeconds"],
        "proofBundleSha256": m["proofBundleSha256"],
        "publicValuesSha256": m["publicValuesSha256"],
    }))
}

#[cfg(feature = "groth16-native")]
#[allow(clippy::too_many_arguments)]
async fn run_groth16(
    plan: &Plan,
    prover: &sp1_sdk::env::EnvProver,
    keys: &mut BTreeMap<&'static str, EnvProvingKey>,
    key_seconds: &mut BTreeMap<&'static str, f64>,
    job: &Job,
    index: usize,
    one_time_seconds: f64,
    plan_seconds: f64,
    prover_seconds: f64,
    backend: &str,
    job_started: Instant,
) -> Result<Value> {
    if job.children.is_empty() {
        return Err(format!("job {}: groth16 job needs children", job.id).into());
    }
    let input = match fs::read(&job.frames) {
        Ok(bytes) => bytes,
        Err(error) => {
            let (bytes, _identities) = plan::assemble_frames(plan, &child_argument(&job.children))
                .map_err(|build| {
                    format!(
                        "job {}: cannot read frames {} ({error}) and cannot build them from children: {build}",
                        job.id,
                        job.frames.display()
                    )
                })?;
            if let Some(dir) = job.frames.parent() {
                fs::create_dir_all(dir)?;
            }
            fs::write(&job.frames, &bytes)?;
            bytes
        }
    };
    let f = plan::frames(&input)?;
    let expected = plan.expected(Role::Range, &f)?;
    let parameter_manifest = job
        .parameter_manifest
        .clone()
        .ok_or_else(|| format!("job {}: groth16 job needs parameterManifest", job.id))?;
    let source_manifest = match &job.source_manifest {
        Some(p) => p.clone(),
        None => plan.dir.join("source-manifest.json"),
    };
    let param_bytes = fs::read(&parameter_manifest)?;
    let source_bytes = fs::read(&source_manifest)?;
    if plan::sha(&source_bytes) != plan.source_sha {
        return Err(format!("job {}: source manifest differs from the frozen plan", job.id).into());
    }
    let mut m = json!({
        "release": env!("CARGO_PKG_VERSION"),
        "phase": "prove",
        "proofForm": "Groth16",
        "role": "range",
        "sdkVersion": "6.7.0",
        "circuitVersion": "v6.1.0",
        "planSha256": plan.manifest_sha,
        "sourceManifestSha256": plan::sha(&source_bytes),
        "parameterManifestSha256": plan::sha(&param_bytes),
        "guestElfSha256": plan::sha(plan.elf(Role::Range)),
        "programVKey": plan.vk(Role::Range).bytes32(),
        "programVkBincodeSha256": plan::sha(&bincode::serialize(plan.vk(Role::Range))?),
        "inputSha256": plan::sha(&input),
        "suiteHash": hex::encode(plan.suite.suite_hash()?),
        "termsHash": hex::encode(plan.terms.terms_hash()?),
        "publicValuesSha256": plan::sha(&expected),
        "publicValuesBytes": 800,
        "coreVerifyIntermediates": true,
        "recursionVerifyIntermediates": true,
        "recursionVkVerification": true,
        "circuitMode": "release",
        "cryptographicProofGenerated": false,
        "cryptographicProofVerified": false,
        "contextOrigin": plan.context_origin,
        "chainAcceptanceEstablished": false,
        "backend": backend,
        "batch": {
            "jobId": job.id,
            "jobIndex": index,
            "form": job.form,
            "planLoadSeconds": plan_seconds,
            "proverInitSeconds": prover_seconds,
            "oneTimeSetupSeconds": one_time_seconds,
            "keySetupSecondsByRole": key_seconds,
            "resumed": false,
        },
    });
    let proof_path = job.out.join("proof.bin");
    fs::create_dir_all(&job.out)?;
    fs::write(
        job.out.join("program-vk.bin"),
        bincode::serialize(plan.vk(Role::Range))?,
    )?;
    fs::write(job.out.join("source-manifest.json"), &source_bytes)?;
    if proof_path.is_file() {
        let retained = SP1ProofWithPublicValues::load(&proof_path)?;
        if !matches!(retained.proof, SP1Proof::Groth16(_)) {
            return Err(format!("job {}: retained proof is not Groth16", job.id).into());
        }
        plan.light
            .verify(&retained, plan.vk(Role::Range), Some(StatusCode::SUCCESS))?;
        if retained.public_values.as_slice() != expected {
            return Err(format!(
                "job {}: retained proof journal differs from the frozen statement",
                job.id
            )
            .into());
        }
        return Ok(json!({
            "id": job.id,
            "role": "range",
            "form": "groth16",
            "status": "groth16-proof-sdk-verified",
            "resumed": true,
            "proofBundleSha256": plan::sha(&fs::read(&proof_path)?),
            "publicValuesSha256": plan::sha(retained.public_values.as_slice()),
        }));
    }
    let t = Instant::now();
    m["parameterCache"] = plan::cache_gate(&param_bytes)?;
    m["parameterAuditSeconds"] = json!(t.elapsed().as_secs_f64());
    plan::record(&job.out, "metrics.json", &m)?;

    // The range program key: reuse the batch key when the compressed range
    // proofs already built it, otherwise build it once here.
    let name = role_name(Role::Range);
    let mut setup_here = 0.0_f64;
    if !keys.contains_key(name) {
        let t = Instant::now();
        let pk = prover
            .setup(Elf::from(plan.elf(Role::Range).to_vec()))
            .await?;
        if bincode::serialize(pk.verifying_key())? != bincode::serialize(plan.vk(Role::Range))? {
            return Err("prover key differs from the frozen plan VK".into());
        }
        setup_here = t.elapsed().as_secs_f64();
        key_seconds.insert(name, setup_here);
        keys.insert(name, pk);
    }
    let pk = keys.get(name).ok_or("prover key missing")?;

    let mut stdin = SP1Stdin::new();
    for frame in &f {
        stdin.write_slice(frame);
    }
    let mut children = Vec::new();
    for ((role, path), child) in job.children.iter().zip(plan::range_children(&f)?) {
        let proof = plan.load_child(*role, &path.to_string_lossy())?;
        if proof.public_values.as_slice() != child.journal
            || plan.vk(*role).hash_u32() != child.vk_words
        {
            return Err(format!("job {}: child journal/VK mismatch", job.id).into());
        }
        children.push(json!({
            "role": child.role as u8,
            "proofBundleSha256": plan::sha(&fs::read(path)?),
            "publicValuesSha256": hex::encode(child.journal_sha256),
            "programVKey": plan.vk(*role).bytes32(),
            "sdkExplicitSuccess": "Ok(())",
        }));
        let SP1Proof::Compressed(inner) = proof.proof else {
            return Err("compressed child required".into());
        };
        stdin.write_proof(*inner, plan.vk(*role).vk.clone());
    }
    let raw = bincode::serialize(&stdin)?;
    m["stdinBincodeSha256"] = json!(plan::sha(&raw));
    m["children"] = json!(children);
    fs::write(job.out.join("stdin.bin"), raw)?;
    m["setupSeconds"] = json!(setup_here);
    plan::record(&job.out, "metrics.json", &m)?;

    let t = Instant::now();
    let proof = prover
        .prove(pk, stdin)
        .groth16()
        .expected_exit_code(StatusCode::SUCCESS)
        .await?;
    m["proveSeconds"] = json!(t.elapsed().as_secs_f64());
    proof.save(&proof_path)?;
    m["cryptographicProofGenerated"] = json!(true);
    plan::record(&job.out, "metrics.json", &m)?;
    plan.light
        .verify(&proof, plan.vk(Role::Range), Some(StatusCode::SUCCESS))?;
    plan.light.verify(&proof, plan.vk(Role::Range), None)?;

    let t = Instant::now();
    let mut bad = proof.clone();
    let mut public_values = expected;
    public_values[799] ^= 1;
    bad.public_values = sp1_sdk::SP1PublicValues::from(public_values.as_slice());
    m["mutatedPublicValuesRejected"] = json!(plan
        .light
        .verify(&bad, plan.vk(Role::Range), None)
        .err()
        .ok_or("changed journal accepted")?
        .to_string());
    m["wrongRoleKeyRejected"] = json!(plan
        .light
        .verify(&proof, plan.vk(Role::Chunk), None)
        .err()
        .ok_or("chunk VK accepted")?
        .to_string());
    m["wrongExpectedStatusRejected"] = json!(plan
        .light
        .verify(&proof, plan.vk(Role::Range), StatusCode::new(1))
        .err()
        .ok_or("wrong status accepted")?
        .to_string());
    m["verificationSeconds"] = json!(t.elapsed().as_secs_f64());
    let encoded = proof.bytes();
    if encoded.len() != 356 || encoded[..4] != kai_volume_range::suite::CIRCUIT_IDENTITY[..4] {
        return Err("unexpected pinned Groth16 encoding".into());
    }
    fs::write(
        job.out.join("public-values.bin"),
        proof.public_values.as_slice(),
    )?;
    fs::write(job.out.join("proof.bytes"), &encoded)?;
    m["proofBundleSha256"] = json!(plan::sha(&bincode::serialize(&proof)?));
    m["proofBytesSha256"] = json!(plan::sha(&encoded));
    m["proofBytesLength"] = json!(encoded.len());
    m["proofSelector"] = json!(hex::encode(&encoded[..4]));
    m["sdkExplicitSuccessResult"] = json!("Ok(())");
    m["sdkDefaultSuccessResult"] = json!("Ok(())");
    m["cryptographicProofVerified"] = json!(true);
    m["status"] = json!("groth16-proof-sdk-verified");
    m["elapsedSeconds"] = json!(job_started.elapsed().as_secs_f64());
    plan::record(&job.out, "metrics.json", &m)?;
    Ok(json!({
        "id": job.id,
        "role": "range",
        "form": "groth16",
        "status": "groth16-proof-sdk-verified",
        "resumed": false,
        "setupSeconds": setup_here,
        "proveSeconds": m["proveSeconds"],
        "verificationSeconds": m["verificationSeconds"],
        "proofBytesSha256": m["proofBytesSha256"],
        "publicValuesSha256": m["publicValuesSha256"],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str, form: &str, out: &str, children: &[(&str, &str)]) -> Job {
        Job {
            id: id.to_string(),
            form: form.to_string(),
            role: Some(if form == "groth16" { Role::Range } else { Role::Chunk }),
            frames: PathBuf::from("/frames/x.frames"),
            out: PathBuf::from(out),
            children: children
                .iter()
                .map(|(role, path)| (plan::role(role).unwrap(), PathBuf::from(path)))
                .collect(),
            parameter_manifest: None,
            source_manifest: None,
            gpu: None,
        }
    }

    fn weighted(id: &str, out: &str, bytes: usize, gpu: Option<u32>) -> Job {
        // Unique per (process, id, size): the two balancer tests run in parallel
        // and must not write the same frame file.
        let dir = std::env::temp_dir().join(format!("batch-weight-{}-{id}-{bytes}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let frames = dir.join("frames.bin");
        std::fs::write(&frames, vec![0u8; bytes]).unwrap();
        let mut entry = job(id, "compressed", out, &[]);
        entry.frames = frames;
        entry.gpu = gpu;
        entry
    }

    #[test]
    fn splits_parallel_jobs_from_dependent_jobs() {
        let jobs = vec![
            job("chunk-0", "compressed", "/out/chunk-0", &[]),
            job("chunk-1", "compressed", "/out/chunk-1", &[]),
            job("range", "compressed", "/out/range", &[("chunk", "/out/chunk-0/proof.bin"), ("chunk", "/out/chunk-1/proof.bin")]),
            job("root", "groth16", "/out/root", &[("range", "/out/range/proof.bin")]),
        ];
        let (parallel, tail) = parallel_and_tail(&jobs);
        assert_eq!(parallel, vec![0, 1]);
        assert_eq!(tail, vec![2, 3]);
    }

    #[test]
    fn balances_parallel_jobs_by_frame_bytes() {
        let jobs = vec![
            weighted("chunk-0", "/out/c0", 4_000, None),
            weighted("chunk-1", "/out/c1", 3_000, None),
            weighted("chunk-2", "/out/c2", 2_000, None),
            weighted("chunk-3", "/out/c3", 1_000, None),
        ];
        let slices = assign_jobs(&jobs, &[0, 1, 2, 3], &[0, 1]).expect("assign");
        // Heaviest first onto the least loaded device: 4000+1000 and 3000+2000.
        let weights: Vec<u64> = jobs.iter().map(job_weight).collect();
        assert_eq!(slices[0], vec![0, 3], "weights {weights:?} slices {slices:?}");
        assert_eq!(slices[1], vec![1, 2]);
        let total = |slice: &Vec<usize>| slice.iter().map(|index| job_weight(&jobs[*index])).sum::<u64>();
        assert_eq!(total(&slices[0]), total(&slices[1]));
    }

    #[test]
    fn honours_a_pinned_device_and_refuses_an_unknown_one() {
        let jobs = vec![
            weighted("chunk-0", "/out/c0", 9_000, Some(1)),
            weighted("chunk-1", "/out/c1", 100, None),
        ];
        let slices = assign_jobs(&jobs, &[0, 1], &[0, 1]).expect("assign");
        assert_eq!(slices[1], vec![0]);
        assert_eq!(slices[0], vec![1]);
        let error = assign_jobs(&jobs, &[0, 1], &[0]).expect_err("unknown device").to_string();
        assert!(error.contains("gpu 1 is not in --gpus 0"), "{error}");
    }

    #[test]
    fn weighs_a_missing_frame_file_as_one() {
        let mut entry = job("chunk-0", "compressed", "/out/c0", &[]);
        entry.frames = PathBuf::from("/definitely/absent.frames");
        assert_eq!(job_weight(&entry), 1);
    }

    #[test]
    fn parses_a_device_list_and_repeats() {
        assert_eq!(parse_gpus("0,1").unwrap(), vec![0, 1]);
        assert_eq!(parse_gpus("0,0").unwrap(), vec![0, 0]);
        assert!(parse_gpus("").is_err());
        assert!(parse_gpus("gpu0").is_err());
    }

    #[test]
    fn accepts_an_ordered_list() {
        let jobs = vec![
            job("chunk-0", "compressed", "/out/chunk-0", &[]),
            job("chunk-1", "compressed", "/out/chunk-1", &[]),
            job("range", "compressed", "/out/range", &[("chunk", "/out/chunk-0/proof.bin"), ("chunk", "/out/chunk-1/proof.bin")]),
        ];
        assert!(validate_jobs(&jobs).is_ok());
    }

    #[test]
    fn rejects_a_child_that_is_produced_later() {
        let jobs = vec![
            job("range", "compressed", "/out/range", &[("chunk", "/out/chunk-0/proof.bin")]),
            job("chunk-0", "compressed", "/out/chunk-0", &[]),
        ];
        let error = validate_jobs(&jobs).expect_err("must reject").to_string();
        assert!(error.contains("job range"), "{error}");
        assert!(error.contains("produced later by job chunk-0"), "{error}");
    }

    #[test]
    fn rejects_a_child_that_no_job_produces_and_that_is_missing() {
        let jobs = vec![job("range", "compressed", "/out/range", &[("chunk", "/out/absent/proof.bin")])];
        let error = validate_jobs(&jobs).expect_err("must reject").to_string();
        assert!(error.contains("job range (chunk child)"), "{error}");
        assert!(error.contains("does not exist"), "{error}");
    }

    #[test]
    fn rejects_a_self_child() {
        let jobs = vec![job("range", "compressed", "/out/range", &[("range", "/out/range/proof.bin")])];
        let error = validate_jobs(&jobs).expect_err("must reject").to_string();
        assert!(error.contains("its own proof"), "{error}");
    }

    #[test]
    fn rejects_duplicate_ids_and_outputs() {
        let jobs = vec![
            job("chunk-0", "compressed", "/out/a", &[]),
            job("chunk-0", "compressed", "/out/b", &[]),
        ];
        assert!(validate_jobs(&jobs).expect_err("duplicate id").to_string().contains("duplicate job id"));
        let jobs = vec![
            job("chunk-0", "compressed", "/out/a", &[]),
            job("chunk-1", "compressed", "/out/a", &[]),
        ];
        assert!(validate_jobs(&jobs).expect_err("duplicate out").to_string().contains("used by another job"));
    }

    #[test]
    fn rejects_an_empty_list_and_a_groth16_job_without_children() {
        assert!(validate_jobs(&[]).expect_err("empty").to_string().contains("no jobs"));
        let jobs = vec![job("root", "groth16", "/out/root", &[])];
        assert!(validate_jobs(&jobs).expect_err("no children").to_string().contains("needs children"));
    }

    #[test]
    fn accepts_a_child_that_exists_on_disk() {
        let dir = std::env::temp_dir().join(format!("batch-validate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let proof = dir.join("proof.bin");
        std::fs::write(&proof, b"retained").unwrap();
        let jobs = vec![job("range", "compressed", "/out/range", &[("chunk", proof.to_str().unwrap())])];
        assert!(validate_jobs(&jobs).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
