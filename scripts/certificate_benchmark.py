#!/usr/bin/env python3
"""Measure deterministic certificate structure and producer/checker costs.

The scientific fields are the bound, serialized proof size, and state statistics.
CPU and wall times are descriptive observations and are excluded from exact
reproduction comparison.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dataflow.checker import check_upper
from dataflow.generate import cut_graph, structured
from dataflow.producer import prove_upper


def cases():
    for groups in (1, 4, 8, 16, 32):
        pair = structured(groups)
        yield f"structured-{groups}-grouped", "structured", groups, list(range(4 * groups)), pair
    groups = 8
    pair = structured(groups)
    order = [4 * block + position for position in range(4) for block in range(groups)]
    yield "structured-8-interleaved", "structured", groups, order, pair
    for vertices in (4, 8, 12):
        edges = list(itertools.combinations(range(vertices), 2))
        pair = cut_graph(vertices, edges)
        yield f"clique-{vertices}", "clique", vertices, None, pair


def compact_bytes(proof: dict) -> int:
    return len((json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode())


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = list(rows[0])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "results")
    args = parser.parse_args()
    if hasattr(os, "sched_getaffinity"):
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (42, 44))
    args.out.mkdir(parents=True, exist_ok=True)
    begin_wall = time.monotonic()
    begin_cpu = time.process_time()
    rows = []
    for name, family, size, order, pair in cases():
        producer_wall = time.monotonic()
        producer_cpu = time.process_time()
        proof = prove_upper(pair, order=order, max_layer=100_000, max_total=300_000, seconds=30)
        producer_cpu_seconds = time.process_time() - producer_cpu
        producer_wall_seconds = time.monotonic() - producer_wall
        checker_wall = time.monotonic()
        checker_cpu = time.process_time()
        checked = check_upper(
            pair, proof, 0, proof["bound"],
            max_layer=100_000, max_total=300_000, seconds=30,
        )
        checker_cpu_seconds = time.process_time() - checker_cpu
        checker_wall_seconds = time.monotonic() - checker_wall
        if not checked["accepted"] or not checked["exact"]:
            raise AssertionError((name, checked))
        rows.append({
            "case": name,
            "family": family,
            "size": size,
            "guards": pair["kernel"]["guards"],
            "bound_bytes": proof["bound"],
            "signature_terms": proof["statistics"]["terms"],
            "frontier_width": proof["statistics"]["frontier_width"],
            "open_count_blocks": proof["statistics"]["open_count_blocks"],
            "total_states": proof["statistics"]["total_states"],
            "peak_states": proof["statistics"]["peak_states"],
            "certificate_bytes": compact_bytes(proof),
            "producer_cpu_seconds": producer_cpu_seconds,
            "producer_wall_seconds": producer_wall_seconds,
            "checker_cpu_seconds": checker_cpu_seconds,
            "checker_wall_seconds": checker_wall_seconds,
        })
    use = resource.getrusage(resource.RUSAGE_SELF)
    report = {
        "part": "certificates",
        "case_count": len(rows),
        "cpu_seconds": time.process_time() - begin_cpu,
        "wall_seconds": time.monotonic() - begin_wall,
        "peak_rss_kib": use.ru_maxrss,
        "swap_events": use.ru_nswap,
        "workers": 1,
        "rows": rows,
    }
    (args.out / "certificates.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_csv(args.out / "certificates.csv", rows)
    print(json.dumps({key: value for key, value in report.items() if key != "rows"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
