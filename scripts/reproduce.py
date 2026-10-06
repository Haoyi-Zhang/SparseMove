#!/usr/bin/env python3
"""Run bounded validation chunks and compare all non-timing scientific fields.

No network, external solver, GPU, model, or installed Python package is used.
Existing output directories are refused. All children run sequentially.
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ["structured", "grid", "cycle", "format", "graph-free", "graph-nm", "random-0", "random-1", "random-2"]
SCALING = ["equal-small", "equal-large", "orders", "cliques"]
SPECIAL = ["reduction", "certificates"]
TIMING = {
    "cpu_seconds", "wall_seconds", "peak_rss_kib",
    "producer_cpu_seconds", "producer_wall_seconds",
    "checker_cpu_seconds", "checker_wall_seconds",
}


def scientific(value):
    if isinstance(value, dict):
        return {key: scientific(item) for key, item in value.items() if key not in TIMING}
    if isinstance(value, list):
        return [scientific(item) for item in value]
    return value


def compare_json(observed_path: Path, expected_path: Path, label: str) -> dict:
    observed = json.loads(observed_path.read_text(encoding="utf-8"))
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    if scientific(observed) != scientific(expected):
        raise RuntimeError(f"{label} scientific result differs; never suppress a changed status")
    return observed


def run_logged(command: list[str], label: str, output: Path, env: dict) -> subprocess.CompletedProcess:
    """Keep captured output even on timeout; never turn a timeout into success."""
    log = output / (label + ".log")
    try:
        result = subprocess.run(
            command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=240, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # TimeoutExpired may hold bytes even when subprocess.run uses text=True.
        # Preserve those bytes rather than losing or silently re-decoding them.
        partial = exc.stdout or b""
        if isinstance(partial, bytes):
            log.write_bytes(partial)
        else:
            log.write_text(partial, encoding="utf-8")
        raise
    log.write_text(result.stdout, encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--parts", nargs="+", choices=CAMPAIGN + SCALING + SPECIAL, default=CAMPAIGN + SCALING + SPECIAL)
    args = parser.parse_args()
    output = args.output.resolve()
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (42, 44))
    if output.exists():
        parser.error("output must not exist; reference results are never overwritten")
    output.mkdir(parents=True)
    (output / "results").mkdir()
    (output / "inputs").mkdir()
    env = dict(
        os.environ,
        PYTHONPATH=str(ROOT / "src"),
        PYTHONDONTWRITEBYTECODE="1",
        OMP_NUM_THREADS="1",
        OPENBLAS_NUM_THREADS="1",
    )
    start = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    records = []
    validation = {}
    checks = []
    commands = [
        ("artifact-audit", [sys.executable, str(ROOT / "scripts" / "verify_artifact.py")]),
        ("unit-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("optimized-unit-tests", [sys.executable, "-O", "-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("standalone-oracle", [sys.executable, str(ROOT / "scripts" / "standalone_oracle.py"), "--output", str(output / "results" / "standalone-oracle.json")]),
        ("adversarial-crosscheck", [sys.executable, str(ROOT / "scripts" / "adversarial_crosscheck.py"), "--output", str(output / "results" / "adversarial-crosscheck.json")]),
        ("reviewer-stress", [sys.executable, str(ROOT / "scripts" / "reviewer_stress.py"), "--output", str(output / "results" / "reviewer-stress.json")]),
    ]
    for part in args.parts:
        if part in CAMPAIGN:
            command = [sys.executable, str(ROOT / "scripts" / "campaign.py"), part, "--out", str(output / "results"), "--inputs", str(output / "inputs")]
        elif part in SCALING:
            command = [sys.executable, str(ROOT / "scripts" / "scaling.py"), part, "--out", str(output / "results")]
        elif part == "reduction":
            command = [sys.executable, str(ROOT / "scripts" / "reduction.py"), "--out", str(output / "results"), "--inputs", str(output / "inputs")]
        else:
            command = [sys.executable, str(ROOT / "scripts" / "certificate_benchmark.py"), "--out", str(output / "results")]
        commands.append((part, command))
    status = "failed"
    try:
        for label, command in commands:
            print("Running " + label, flush=True)
            result = run_logged(command, label, output, env)
            if result.returncode:
                raise RuntimeError(label + " failed with exit " + str(result.returncode))
            if label in {"standalone-oracle", "adversarial-crosscheck", "reviewer-stress"}:
                observed = compare_json(
                    output / "results" / f"{label}.json",
                    ROOT / "results" / f"{label}.json",
                    label,
                )
                validation[label.replace("-", "_")] = {"scientific_fields_match": True, **observed}
            elif label in CAMPAIGN + SCALING + SPECIAL:
                observed = compare_json(
                    output / "results" / f"{label}.json",
                    ROOT / "results" / f"{label}.json",
                    label,
                )
                if observed.get("swap_events") != 0:
                    raise RuntimeError(label + " observed swap events")
                if label in CAMPAIGN + ["reduction"]:
                    if (output / "inputs" / f"{label}.jsonl").read_bytes() != (ROOT / "inputs" / f"{label}.jsonl").read_bytes():
                        raise RuntimeError(label + " regenerated inputs differ")
                if label == "certificates":
                    if (output / "results" / "certificates.csv").read_bytes() == (ROOT / "results" / "certificates.csv").read_bytes():
                        pass
                    else:
                        observed_rows = json.loads((output / "results" / "certificates.json").read_text())["rows"]
                        expected_rows = json.loads((ROOT / "results" / "certificates.json").read_text())["rows"]
                        if scientific(observed_rows) != scientific(expected_rows):
                            raise RuntimeError("certificates.csv differs in non-timing fields")
                records.append({
                    "part": label,
                    "scientific_fields_match": True,
                    "cpu_seconds": observed["cpu_seconds"],
                    "wall_seconds": observed["wall_seconds"],
                    "peak_rss_kib": observed["peak_rss_kib"],
                    "swap_events": observed["swap_events"],
                })
            else:
                checks.append({"check": label, "status": "passed"})
        status = "passed"
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        (output / "failure.txt").write_text(str(exc) + "\n", encoding="utf-8")
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        report = {
            "status": status,
            "checks": checks,
            "validation": validation,
            "parts": records,
            "wall_seconds": time.monotonic() - start,
            "child_cpu_seconds": after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
        }
        (output / "reproduction.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
