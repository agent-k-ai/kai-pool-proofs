#!/usr/bin/env python3
"""Split a batch job list into two GPU slice lists and the dependent tail list.

Usage:
    split-two-container-jobs.py JOBS.json FRAMES_DIR OUT_DIR [PREFIX]

The parallel set is the jobs that consume no child. The tail set is the jobs that consume a child
(range merges, then the root); those run after both slices finish. Each parallel job goes to the
slice with the least frame bytes so far (LPT, heaviest first). The job order inside a slice is the
heaviest-first order.

Writes OUT_DIR/<PREFIX>slice-a.json, <PREFIX>slice-b.json and <PREFIX>tail.json. PREFIX defaults to
"". A missing or empty frame file weighs 1 byte, so an unusual job list still splits.
"""
from __future__ import annotations

import json
import pathlib
import sys

DEFAULT_PREFIX = ""


def frame_weight(frames_dir: pathlib.Path, job: dict) -> int:
    """Return the frame-file size in bytes, or 1 when the file is absent."""
    local = frames_dir / pathlib.Path(str(job.get("frames", ""))).name
    return local.stat().st_size if local.is_file() else 1


def split(jobs: list[dict], frames_dir: pathlib.Path) -> tuple[list[dict], list[dict], list[list[dict]]]:
    """Return (parallel, tail, two slices). The slices hold every parallel job."""
    parallel = [job for job in jobs if not job.get("children")]
    tail = [job for job in jobs if job.get("children")]
    load = [0, 0]
    slices: list[list[dict]] = [[], []]
    for job in sorted(parallel, key=lambda item: -frame_weight(frames_dir, item)):
        at = load.index(min(load))
        load[at] += frame_weight(frames_dir, job)
        slices[at].append(job)
    return parallel, tail, slices


def main(argv: list[str]) -> int:
    """Write the three job lists and print one line for each."""
    if len(argv) not in (4, 5):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    jobs_path, frames_dir, out_dir = pathlib.Path(argv[1]), pathlib.Path(argv[2]), pathlib.Path(argv[3])
    prefix = argv[4] if len(argv) == 5 else DEFAULT_PREFIX
    doc = json.loads(jobs_path.read_text())
    jobs = doc["jobs"]
    parallel, tail, slices = split(jobs, frames_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, slice_jobs in (("a", slices[0]), ("b", slices[1])):
        payload = {"kind": doc.get("kind"), "plan": doc.get("plan"), "jobs": slice_jobs}
        (out_dir / f"{prefix}slice-{name}.json").write_text(json.dumps(payload, indent=2) + "\n")
        print(f"{prefix}slice-{name} bytes={sum(frame_weight(frames_dir, j) for j in slice_jobs)} "
              f"jobs={[j['id'] for j in slice_jobs]}")
    tail_payload = {"kind": doc.get("kind"), "plan": doc.get("plan"), "jobs": tail}
    (out_dir / f"{prefix}tail.json").write_text(json.dumps(tail_payload, indent=2) + "\n")
    print(f"{prefix}tail jobs={[j['id'] for j in tail]} parallel={len(parallel)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
