// SPDX-License-Identifier: Apache-2.0
//! Batch / per-job equivalence on real captured frames.
//!
//! The test needs captured chain input, so it is gated by environment
//! variables and reports a skip when they are unset:
//!
//! - `BATCH_TEST_PLAN`   plan directory (plan.json, chunk.elf, range.elf, ...)
//! - `BATCH_TEST_FRAMES` directory with exactly two adjacent chunk frame files
//! - `BATCH_TEST_WORK`   writable work directory
//!
//! Example, in the pinned image with the runner and golden frames mounted:
//!
//! ```text
//! BATCH_TEST_PLAN=/plan BATCH_TEST_FRAMES=/frames BATCH_TEST_WORK=/work \
//! cargo test --offline --locked --release -p volume-chunk-host \
//!   --bin volume-range-proof --features groth16-native --test batch_equivalence
//! ```
//!
//! Set `BATCH_TEST_ASSERT_PROOF_BYTES=1` to require byte-equal `proof.bin`
//! between the two modes. SP1 compressed proofs are randomised, so that is off
//! by default; the proof bytes are compared and reported when the flag is on.
use serde_json::Value;
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Deterministic metric keys: the two modes must agree on all of them.
const SHARED_KEYS: &[&str] = &[
    "release",
    "phase",
    "role",
    "sdkVersion",
    "circuitVersion",
    "planSha256",
    "sourceManifestSha256",
    "guestElfSha256",
    "vk",
    "suiteHash",
    "termsHash",
    "inputSha256",
    "inputBytes",
    "nativeJournalSha256",
    "publicValuesSha256",
    "publicValuesBytes",
    "statementIdKeccak256",
    "contextOrigin",
    "status",
];

fn bin(name: &str) -> PathBuf {
    let key = format!("CARGO_BIN_EXE_{name}");
    PathBuf::from(env::var(&key).unwrap_or_else(|_| panic!("cargo sets {key}")))
}

fn run(exe: &Path, args: &[String], extra: &[(&str, String)]) -> (bool, String) {
    let mut command = Command::new(exe);
    command.args(args);
    for (key, value) in extra {
        command.env(key, value);
    }
    let out = command.output().expect("spawn host binary");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn metrics(path: &Path) -> Value {
    serde_json::from_slice(&read(path)).expect("metrics.json")
}

#[test]
fn batch_matches_per_job_mode_on_golden_frames() {
    let (plan, frames_dir, work) = match (
        env::var("BATCH_TEST_PLAN"),
        env::var("BATCH_TEST_FRAMES"),
        env::var("BATCH_TEST_WORK"),
    ) {
        (Ok(plan), Ok(frames), Ok(work)) => (PathBuf::from(plan), PathBuf::from(frames), PathBuf::from(work)),
        _ => {
            eprintln!(
                "batch_equivalence: skipped; set BATCH_TEST_PLAN, BATCH_TEST_FRAMES and BATCH_TEST_WORK"
            );
            return;
        }
    };
    let assert_proof_bytes = env::var("BATCH_TEST_ASSERT_PROOF_BYTES").is_ok();

    let mut frames: Vec<PathBuf> = fs::read_dir(&frames_dir)
        .expect("frames dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "frames").unwrap_or(false))
        .collect();
    frames.sort();
    assert_eq!(
        frames.len(),
        2,
        "BATCH_TEST_FRAMES needs exactly two adjacent chunk frame files"
    );

    let per = work.join("per-job");
    let batch = work.join("batch");
    let tmp = work.join("tmp");
    for dir in [&per, &batch, &tmp] {
        fs::create_dir_all(dir).expect("work dir");
    }
    // The batch directory is always proven fresh so its timings are comparable.
    let _ = fs::remove_dir_all(&batch);
    fs::create_dir_all(&batch).expect("batch dir");
    let proven = |out: &Path| out.join("proof.bin").is_file() && out.join("metrics.json").is_file();
    let exe = bin("volume-range-proof");
    let common: Vec<(&str, String)> = vec![
        ("PROVER_BACKEND", "cpu".to_string()),
        ("SP1_PROVER", "cpu".to_string()),
        ("TMPDIR", tmp.to_string_lossy().into_owned()),
        ("HOME", tmp.to_string_lossy().into_owned()),
    ];
    let plan_arg = plan.to_string_lossy().into_owned();

    // ---- per-job mode: two chunk proofs and one range merge ----
    let mut children = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let out = per.join(format!("chunk-{index}"));
        let args = vec![
            "prove".to_string(),
            "chunk".to_string(),
            plan_arg.clone(),
            frame.to_string_lossy().into_owned(),
            out.to_string_lossy().into_owned(),
        ];
        if !proven(&out) {
            let (ok, log) = run(&exe, &args, &common);
            assert!(ok, "per-job chunk {index} failed: {log}");
        } else {
            eprintln!("per-job chunk {index}: retained, skipped");
        }
        children.push(out.join("proof.bin"));
    }
    let per_frames = per.join("range.frames");
    let mut assemble = vec![
        "assemble".to_string(),
        plan_arg.clone(),
        per_frames.to_string_lossy().into_owned(),
    ];
    for child in &children {
        assemble.push("chunk".to_string());
        assemble.push(child.to_string_lossy().into_owned());
    }
    if !per_frames.is_file() {
        let (ok, log) = run(&exe, &assemble, &common);
        assert!(ok, "assemble failed: {log}");
    } else {
        eprintln!("per-job range frames: retained, skipped");
    }
    let per_range = per.join("range");
    let mut prove_range = vec![
        "prove".to_string(),
        "range".to_string(),
        plan_arg.clone(),
        per_frames.to_string_lossy().into_owned(),
        per_range.to_string_lossy().into_owned(),
    ];
    for child in &children {
        prove_range.push(child.to_string_lossy().into_owned());
    }
    if !proven(&per_range) {
        let (ok, log) = run(&exe, &prove_range, &common);
        assert!(ok, "per-job range failed: {log}");
    } else {
        eprintln!("per-job range: retained, skipped");
    }

    // ---- batch mode: the same three jobs in one process ----
    let batch_frames = batch.join("range.frames");
    let batch_children: Vec<Vec<String>> = (0..2)
        .map(|i| {
            vec![
                "chunk".to_string(),
                batch.join(format!("chunk-{i}/proof.bin")).to_string_lossy().into_owned(),
            ]
        })
        .collect();
    let job_list = serde_json::json!({
        "kind": "kai-volume-range-batch/v1",
        "plan": plan_arg,
        "jobs": [
            {"id": "chunk-0", "form": "compressed", "role": "chunk",
             "frames": frames[0].to_string_lossy(), "out": batch.join("chunk-0").to_string_lossy()},
            {"id": "chunk-1", "form": "compressed", "role": "chunk",
             "frames": frames[1].to_string_lossy(), "out": batch.join("chunk-1").to_string_lossy()},
            {"id": "range", "form": "compressed", "role": "range",
             "frames": batch_frames.to_string_lossy(), "out": batch.join("range").to_string_lossy(),
             "children": batch_children}
        ]
    });
    let job_list_path = batch.join("jobs.json");
    fs::write(&job_list_path, serde_json::to_vec_pretty(&job_list).unwrap()).expect("write job list");
    let args = vec![
        "serve".to_string(),
        "--jobs".to_string(),
        job_list_path.to_string_lossy().into_owned(),
    ];
    let (ok, log) = run(&exe, &args, &common);
    assert!(ok, "batch serve failed: {log}");
    let summary: Value = serde_json::from_str(log.trim().lines().last().unwrap_or("{}"))
        .unwrap_or_else(|e| panic!("batch summary is not JSON ({e}): {log}"));

    // One prover, one key set, three jobs.
    assert_eq!(summary["jobCount"], 3);
    assert_eq!(summary["backend"], "CpuProver");
    assert!(summary["oneTimeSetupSeconds"].as_f64().unwrap_or(0.0) > 0.0);
    let key_seconds = summary["keySetupSecondsByRole"].as_object().expect("key setup map");
    assert!(key_seconds.contains_key("chunk"), "chunk key is built once: {key_seconds:?}");
    assert!(key_seconds.contains_key("range"), "range key is built once: {key_seconds:?}");
    for job in summary["jobs"].as_array().expect("jobs") {
        assert_eq!(job["resumed"], false, "fresh run must not report a resume");
    }

    // The batch builds the range input itself; it must equal the assemble phase.
    assert_eq!(
        read(&per_frames),
        read(&batch_frames),
        "batch-built range frames differ from the assemble phase"
    );

    // ---- equivalence ----
    let pairs = [
        ("chunk-0", per.join("chunk-0"), batch.join("chunk-0")),
        ("chunk-1", per.join("chunk-1"), batch.join("chunk-1")),
        ("range", per_range.clone(), batch.join("range")),
    ];
    for (name, per_out, batch_out) in &pairs {
        assert_eq!(
            read(&per_out.join("public-values.bin")),
            read(&batch_out.join("public-values.bin")),
            "{name}: public values differ"
        );
        assert_eq!(
            read(&per_out.join("native-journal.bin")),
            read(&batch_out.join("native-journal.bin")),
            "{name}: native journals differ"
        );
        let a = metrics(&per_out.join("metrics.json"));
        let b = metrics(&batch_out.join("metrics.json"));
        let a_keys: BTreeSet<&String> = a.as_object().unwrap().keys().collect();
        let b_keys: BTreeSet<&String> = b.as_object().unwrap().keys().collect();
        let missing: Vec<_> = a_keys.difference(&b_keys).collect();
        assert!(missing.is_empty(), "{name}: batch metrics lack keys {missing:?}");
        for key in SHARED_KEYS {
            assert_eq!(a[*key], b[*key], "{name}: metrics {key} differ");
        }
        // Child records differ only in the randomised child proof bytes.
        let a_children = a["children"].as_array().cloned().unwrap_or_default();
        let b_children = b["children"].as_array().cloned().unwrap_or_default();
        assert_eq!(a_children.len(), b_children.len(), "{name}: child count");
        for (x, y) in a_children.iter().zip(&b_children) {
            for key in ["role", "journalSha256", "vk", "sdkExplicitSuccess"] {
                assert_eq!(x[key], y[key], "{name}: child {key} differs");
            }
        }
        // Both proofs must verify under the role VK in a separate process.
        let role = if *name == "range" { "range" } else { "chunk" };
        let input = if *name == "range" {
            batch_frames.clone()
        } else {
            frames[usize::from(*name == "chunk-1")].clone()
        };
        let verify_out = work.join(format!("verify-{name}"));
        let _ = fs::remove_dir_all(&verify_out);
        let verify = vec![
            "verify".to_string(),
            role.to_string(),
            plan_arg.clone(),
            input.to_string_lossy().into_owned(),
            verify_out.to_string_lossy().into_owned(),
            batch_out.join("proof.bin").to_string_lossy().into_owned(),
        ];
        let (ok, log) = run(&exe, &verify, &common);
        assert!(ok, "{name}: batch proof did not verify: {log}");

        let equal_bytes = read(&per_out.join("proof.bin")) == read(&batch_out.join("proof.bin"));
        eprintln!("{name}: proof.bin byte-equal = {equal_bytes}");
        if assert_proof_bytes {
            assert!(equal_bytes, "{name}: proof.bin differs between the two modes");
        }
    }
}
