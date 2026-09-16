// SPDX-License-Identifier: Apache-2.0
//! Batch resume, rejection and mid-batch failure behaviour on real captured frames.
//!
//! Gated by environment variables; the test reports a skip when they are unset:
//!
//! - `BATCH_TEST_PLAN`   plan directory (plan.json, chunk.elf, range.elf, ...)
//! - `BATCH_TEST_FRAMES` directory with exactly two adjacent chunk frame files
//! - `BATCH_TEST_WORK`   writable work directory
//!
//! ```text
//! BATCH_TEST_PLAN=/plan BATCH_TEST_FRAMES=/frames BATCH_TEST_WORK=/work \
//! cargo test --offline --locked --release -p volume-chunk-host \
//!   --bin volume-range-proof --features groth16-native --test batch_resume
//! ```
use serde_json::Value;
use std::{
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

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn summary(text: &str) -> Value {
    serde_json::from_str(text.trim().lines().last().unwrap_or("{}"))
        .unwrap_or_else(|e| panic!("batch summary is not JSON ({e}): {text}"))
}

/// Builds a job list for the two golden chunks plus one range merge.
fn job_list(plan: &str, frames: &[PathBuf], out: &Path, range_frames: &Path, fail_second: bool) -> Value {
    let second = if fail_second {
        out.join("missing.frames").to_string_lossy().into_owned()
    } else {
        frames[1].to_string_lossy().into_owned()
    };
    serde_json::json!({
        "kind": "kai-volume-range-batch/v1",
        "plan": plan,
        "jobs": [
            {"id": "chunk-0", "form": "compressed", "role": "chunk",
             "frames": frames[0].to_string_lossy(), "out": out.join("chunk-0").to_string_lossy()},
            {"id": "chunk-1", "form": "compressed", "role": "chunk",
             "frames": second, "out": out.join("chunk-1").to_string_lossy()},
            {"id": "range", "form": "compressed", "role": "range",
             "frames": range_frames.to_string_lossy(), "out": out.join("range").to_string_lossy(),
             "children": [["chunk", out.join("chunk-0/proof.bin").to_string_lossy()],
                          ["chunk", out.join("chunk-1/proof.bin").to_string_lossy()]]}
        ]
    })
}

fn write_list(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).expect("write job list");
}

#[test]
fn batch_validates_resumes_and_rejects_bad_proofs() {
    let (plan, frames_dir, work) = match (
        env::var("BATCH_TEST_PLAN"),
        env::var("BATCH_TEST_FRAMES"),
        env::var("BATCH_TEST_WORK"),
    ) {
        (Ok(plan), Ok(frames), Ok(work)) => (plan, PathBuf::from(frames), PathBuf::from(work)),
        _ => {
            eprintln!("batch_resume: skipped; set BATCH_TEST_PLAN, BATCH_TEST_FRAMES and BATCH_TEST_WORK");
            return;
        }
    };
    let mut frames: Vec<PathBuf> = fs::read_dir(&frames_dir)
        .expect("frames dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "frames").unwrap_or(false))
        .collect();
    frames.sort();
    assert_eq!(frames.len(), 2, "BATCH_TEST_FRAMES needs exactly two adjacent chunk frame files");

    let out = work.join("batch");
    let tmp = work.join("tmp");
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).expect("out dir");
    fs::create_dir_all(&tmp).expect("tmp dir");
    let range_frames = out.join("range.frames");
    let list = out.join("jobs.json");
    let common: Vec<(&str, String)> = vec![
        ("PROVER_BACKEND", "cpu".to_string()),
        ("SP1_PROVER", "cpu".to_string()),
        ("TMPDIR", tmp.to_string_lossy().into_owned()),
        ("HOME", tmp.to_string_lossy().into_owned()),
    ];
    let exe = bin();
    let serve = |list: &Path| {
        let args = vec!["serve".to_string(), "--jobs".to_string(), list.to_string_lossy().into_owned()];
        run(&exe, &args, &common)
    };

    // ---- a job list that consumes a proof produced later must fail before proving ----
    let mut wrong = job_list(&plan, &frames, &out, &range_frames, false);
    wrong["jobs"] = serde_json::json!([wrong["jobs"][2].clone(), wrong["jobs"][0].clone(), wrong["jobs"][1].clone()]);
    let wrong_list = out.join("jobs-wrong-order.json");
    write_list(&wrong_list, &wrong);
    let (ok, log) = serve(&wrong_list);
    assert!(!ok, "an out-of-order child must fail the list: {log}");
    assert!(log.contains("produced later by job"), "the error must name the producer: {log}");
    assert!(!out.join("chunk-0/proof.bin").exists(), "validation must run before any proving");

    // ---- fresh batch ----
    write_list(&list, &job_list(&plan, &frames, &out, &range_frames, false));
    let (ok, log) = serve(&list);
    assert!(ok, "fresh batch failed: {log}");
    let first = summary(&log);
    assert_eq!(first["jobCount"], 3);
    for job in first["jobs"].as_array().expect("jobs") {
        assert_eq!(job["resumed"], false, "a fresh run must not report a resume");
        assert_eq!(job["status"], "compressed-proof-sdk-verified");
    }
    let artifacts: Vec<PathBuf> = ["chunk-0", "chunk-1", "range"]
        .iter()
        .flat_map(|name| [out.join(format!("{name}/proof.bin")), out.join(format!("{name}/public-values.bin"))])
        .collect();
    let before: Vec<Vec<u8>> = artifacts.iter().map(|p| read(p)).collect();

    // ---- second run: every job is verified and skipped, nothing is rewritten ----
    let (ok, log) = serve(&list);
    assert!(ok, "resume run failed: {log}");
    let second = summary(&log);
    for job in second["jobs"].as_array().expect("jobs") {
        assert_eq!(job["resumed"], true, "a retained job must be reported as resumed: {job}");
    }
    for (path, was) in artifacts.iter().zip(&before) {
        assert_eq!(&read(path), was, "{} was rewritten by the resume run", path.display());
    }

    // ---- a foreign proof: correct form, wrong statement ----
    let chunk0 = out.join("chunk-0/proof.bin");
    let backup = out.join("chunk-0/proof.bin.backup");
    fs::copy(&chunk0, &backup).expect("backup chunk-0");
    fs::copy(out.join("chunk-1/proof.bin"), &chunk0).expect("install the foreign proof");
    let (ok, log) = serve(&list);
    assert!(!ok, "a foreign proof must be rejected: {log}");
    assert!(
        log.contains("journal differs") || log.contains("does not verify") || log.contains("verification"),
        "the error must explain the rejection: {log}"
    );
    fs::rename(&backup, &chunk0).expect("restore chunk-0");

    // ---- a corrupt proof: the file must stay untouched and the run must fail ----
    let range_proof = out.join("range/proof.bin");
    let range_backup = out.join("range/proof.bin.backup");
    fs::copy(&range_proof, &range_backup).expect("backup the range proof");
    let mut corrupt = read(&range_proof);
    // Damage the middle of the bincode payload: a trailing byte can sit in an
    // unchecked field, the payload cannot.
    let middle = corrupt.len() / 2;
    for byte in &mut corrupt[middle..middle + 8] {
        *byte ^= 0xff;
    }
    fs::write(&range_proof, &corrupt).expect("corrupt the range proof");
    let (ok, log) = serve(&list);
    assert!(!ok, "a corrupt proof must be rejected: {log}");
    assert_eq!(read(&range_proof), corrupt, "the batch must not rewrite a retained proof");
    fs::rename(&range_backup, &range_proof).expect("restore the range proof");
    assert!(serve(&list).0, "the restored list must pass again");

    // ---- mid-batch failure: the first job is retained, the second cannot read its frames ----
    let broken = out.join("jobs-broken.json");
    write_list(&broken, &job_list(&plan, &frames, &out, &range_frames, true));
    let (ok, log) = serve(&broken);
    assert!(!ok, "a job with missing frames must fail: {log}");
    assert!(log.contains("missing.frames"), "the error must name the failing input: {log}");
    assert_eq!(&read(&out.join("chunk-0/proof.bin")), &before[0], "the retained job must be untouched");

    // ---- the corrected list resumes and completes ----
    let (ok, log) = serve(&list);
    assert!(ok, "the corrected list must complete: {log}");
    let third = summary(&log);
    for job in third["jobs"].as_array().expect("jobs") {
        assert_eq!(job["resumed"], true, "every job was retained: {job}");
    }
}
