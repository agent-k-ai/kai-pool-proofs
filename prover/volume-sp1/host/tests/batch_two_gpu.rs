// SPDX-License-Identifier: Apache-2.0
//! Two-worker batch equivalence on real captured frames.
//!
//! The coordinator runs the independent jobs on one worker process per device
//! and then the dependent jobs in one worker. On the CPU path the devices are
//! the same, so the test proves the split, the merge and the resume/skip path
//! without a GPU:
//!
//! - the two-worker run produces the same public values and the same frozen
//!   statement per job as the single-worker run;
//! - the workers own disjoint job sets;
//! - the dependent job (the range merge) runs once, after both chunks exist.
//!
//! Gated by environment variables; the test reports a skip when they are unset:
//!
//! - `BATCH_TEST_PLAN`   plan directory (plan.json, chunk.elf, range.elf, ...)
//! - `BATCH_TEST_FRAMES` directory with exactly two adjacent chunk frame files
//! - `BATCH_TEST_WORK`   writable work directory
use serde_json::Value;
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn bin() -> PathBuf {
    PathBuf::from(env::var("CARGO_BIN_EXE_volume-range-proof").expect("cargo sets CARGO_BIN_EXE_*"))
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

/// The summary line. Worker progress lines share the stream, so scan for the
/// JSON object instead of assuming it is last.
fn summary(text: &str) -> Value {
    for line in text.lines().rev() {
        let line = line.trim();
        if line.starts_with('{') {
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                return value;
            }
        }
    }
    panic!("no batch summary in the output: {text}");
}

fn job_list(plan: &str, frames: &[PathBuf], out: &Path, range_frames: &Path) -> Value {
    serde_json::json!({
        "kind": "kai-volume-range-batch/v1",
        "plan": plan,
        "jobs": [
            {"id": "chunk-0", "form": "compressed", "role": "chunk",
             "frames": frames[0].to_string_lossy(), "out": out.join("chunk-0").to_string_lossy()},
            {"id": "chunk-1", "form": "compressed", "role": "chunk",
             "frames": frames[1].to_string_lossy(), "out": out.join("chunk-1").to_string_lossy()},
            {"id": "range", "form": "compressed", "role": "range",
             "frames": range_frames.to_string_lossy(), "out": out.join("range").to_string_lossy(),
             "children": [["chunk", out.join("chunk-0/proof.bin").to_string_lossy()],
                          ["chunk", out.join("chunk-1/proof.bin").to_string_lossy()]]}
        ]
    })
}

/// Public values per job id, the value the statement binds and the only proof
/// field a randomised compressed proof keeps stable.
fn public_values(log: &str) -> Vec<(String, String)> {
    let parsed = summary(log);
    let mut rows: Vec<(String, String)> = parsed["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .map(|job| {
            (
                job["id"].as_str().expect("id").to_string(),
                job["publicValuesSha256"].as_str().expect("publicValuesSha256").to_string(),
            )
        })
        .collect();
    rows.sort();
    rows
}

#[test]
fn two_worker_batch_matches_the_single_worker_batch() {
    let (plan, frames_dir, work) = match (
        env::var("BATCH_TEST_PLAN"),
        env::var("BATCH_TEST_FRAMES"),
        env::var("BATCH_TEST_WORK"),
    ) {
        (Ok(plan), Ok(frames), Ok(work)) => (plan, PathBuf::from(frames), PathBuf::from(work)),
        _ => {
            eprintln!("batch_two_gpu: skipped; set BATCH_TEST_PLAN, BATCH_TEST_FRAMES and BATCH_TEST_WORK");
            return;
        }
    };
    let mut frames: Vec<PathBuf> = fs::read_dir(&frames_dir)
        .expect("frames dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().map(|e| e == "frames").unwrap_or(false))
        .collect();
    frames.sort();
    assert_eq!(frames.len(), 2, "BATCH_TEST_FRAMES needs exactly two adjacent chunk frame files");

    let root = work.join("two-gpu");
    let _ = fs::remove_dir_all(&root);
    let single_out = root.join("single");
    let two_out = root.join("two");
    for dir in [&single_out, &two_out, &root.join("tmp")] {
        fs::create_dir_all(dir).expect("work dir");
    }
    let tmp = root.join("tmp");
    let common: Vec<(&str, String)> = vec![
        ("PROVER_BACKEND", "cpu".to_string()),
        ("SP1_PROVER", "cpu".to_string()),
        ("TMPDIR", tmp.to_string_lossy().into_owned()),
        ("HOME", tmp.to_string_lossy().into_owned()),
        // The coordinator runs worker processes; in a test the current
        // executable is the test harness, so name the host binary.
        (
            "KAI_BATCH_WORKER_BIN",
            bin().to_string_lossy().into_owned(),
        ),
    ];
    let exe = bin();
    let single_list = root.join("single.json");
    fs::write(
        &single_list,
        serde_json::to_vec_pretty(&job_list(&plan, &frames, &single_out, &root.join("single-range.frames"))).unwrap(),
    )
    .expect("write the single list");
    let two_list = root.join("two.json");
    fs::write(
        &two_list,
        serde_json::to_vec_pretty(&job_list(&plan, &frames, &two_out, &root.join("two-range.frames"))).unwrap(),
    )
    .expect("write the two-worker list");

    // ---- one worker ----
    let (ok, log) = run(
        &exe,
        &["serve".to_string(), "--jobs".to_string(), single_list.to_string_lossy().into_owned()],
        &common,
    );
    assert!(ok, "single-worker batch failed: {log}");
    let single = summary(&log);
    assert_eq!(single["jobCount"], 3);
    let expected = public_values(&log);

    // ---- two workers ----
    let (ok, log) = run(
        &exe,
        &[
            "serve".to_string(),
            "--jobs".to_string(),
            two_list.to_string_lossy().into_owned(),
            "--gpus".to_string(),
            "0,0".to_string(),
        ],
        &common,
    );
    assert!(ok, "two-worker batch failed: {log}");
    let two = summary(&log);
    assert_eq!(two["gpuCount"], 2);
    assert_eq!(two["jobCount"], 3);
    assert_eq!(two["parallelJobCount"], 2);
    let workers = two["workers"].as_array().expect("workers");
    assert_eq!(workers.len(), 2, "two workers must report: {log}");

    // Disjoint workers, and the dependent merge stays out of the split.
    let mut owned: Vec<String> = Vec::new();
    for worker in workers {
        for id in worker["jobs"].as_array().expect("worker jobs") {
            owned.push(id.as_str().expect("id").to_string());
        }
    }
    let unique: BTreeSet<&String> = owned.iter().collect();
    assert_eq!(unique.len(), owned.len(), "workers must not share a job: {owned:?}");
    assert_eq!(
        unique.iter().map(|id| id.as_str()).collect::<BTreeSet<&str>>(),
        BTreeSet::from(["chunk-0", "chunk-1"]),
        "the split must own both chunks and nothing else"
    );

    // The same statement per job: public values do not change with the split.
    assert_eq!(public_values(&log), expected, "the split changed a job result");
    for job in two["jobs"].as_array().expect("merged jobs") {
        assert_eq!(job["status"], "compressed-proof-sdk-verified", "job {job}");
    }
    // The merge ran once, after both chunks, in the coordinator.
    let range = two["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .find(|job| job["id"] == "range")
        .expect("range record");
    assert_eq!(range["resumed"], false);
    assert!(
        two["tailSeconds"].as_f64().unwrap_or(0.0) > 0.0,
        "the coordinator must run the dependent job: {log}"
    );
}
