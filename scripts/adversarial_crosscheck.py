#!/usr/bin/env python3
"""Deterministic small-instance cross-oracle checks for the formal artifact.

The script generates fresh, seeded instances and compares production algorithms
against direct exhaustive calculations.  It uses only the Python standard
library and the local ``dataflow`` package.  It is finite validation, not a
machine-checked proof or an independent external review.
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dataflow.checker import check_equal, check_upper  # noqa: E402
from dataflow.generate import (  # noqa: E402
    cut_threshold,
    event,
    hierarchy,
    kernel,
    mapping,
    pair,
)
from dataflow.literal import execute, execute_resident, masks, traffic  # noqa: E402
from dataflow.model import Invalid, difference, eval_difference, validate_pair  # noqa: E402
from dataflow.moment import Budget, Counter  # noqa: E402
from dataflow.producer import prove_upper  # noqa: E402

SEED = 20260919
EXPECTED_COUNTS = {
    "counter_random_cases": 350,
    "frontier_exact_checks": 58,
    "literal_signature_mask_checks": 1074,
    "mapping_random_cases": 90,
    "reduction_mask_checks": 16720,
    "reduction_random_cases": 80,
    "resident_codec_checks": 566,
}


def legal_masks_from_blocks(guard_count: int, blocks: list[dict]) -> list[int]:
    """Direct block-promise oracle that does not call ``support_ok``."""
    return [
        mask
        for mask in range(1 << guard_count)
        if all(
            block["count"] is None
            or sum((mask >> guard) & 1 for guard in block["ids"])
            == block["count"]
            for block in blocks
        )
    ]


def random_partition(rng: random.Random, items) -> list[list[int]]:
    remaining = list(items)
    rng.shuffle(remaining)
    groups: list[list[int]] = []
    while remaining:
        take = rng.randint(1, min(4, len(remaining)))
        groups.append(remaining[:take])
        del remaining[:take]
    return groups


def random_pair(rng: random.Random, guard_count: int) -> dict:
    events = []
    for guard in range(guard_count):
        events.append(event(guard, guard, rng.randrange(3), rng.randrange(2)))
        if rng.random() < 0.7:
            events.append(event(guard, guard, rng.randrange(3), rng.randrange(2)))
    if rng.random() < 0.25:
        events.append(event(-1, guard_count, rng.randrange(3), rng.randrange(2)))

    blocks = []
    first = 0
    while first < guard_count:
        size = rng.randint(1, min(4, guard_count - first))
        ids = list(range(first, first + size))
        first += size
        blocks.append(
            {
                "ids": ids,
                "count": None if rng.random() < 0.4 else rng.randint(0, size),
            }
        )

    shared_kernel = kernel(
        guard_count,
        events,
        guard_count + 1,
        3,
        outputs=2,
        support=list(range(guard_count)) + [-1],
    )
    shared_kernel["blocks"] = blocks
    mappings = []
    for _ in range(2):
        order = list(range(len(events)))
        rng.shuffle(order)
        level_zero = random_partition(rng, range(len(events)))
        level_one = random_partition(rng, range(len(events)))
        packet_format = rng.choice(["dense", "bitmap", "coordinate"])
        mappings.append(
            mapping(
                shared_kernel,
                order,
                [level_zero, level_one],
                formats=(packet_format, "dense"),
                extents=(rng.choice(["hull", "full"]), "hull"),
            )
        )
    candidate = pair(shared_kernel, mappings[0], mappings[1])
    if rng.random() < 0.35:
        candidate = hierarchy(
            candidate, root_format=rng.choice(["dense", "bitmap", "coordinate"])
        )
    return candidate


def run() -> dict:
    rng = random.Random(SEED)
    report: dict[str, int | str] = {"status": "passed", "seed": SEED}

    # 1. Exact squared counting and constructive witnesses against a direct sum.
    counter_cases = 0
    for _ in range(EXPECTED_COUNTS["counter_random_cases"]):
        guard_count = rng.randint(1, 9)
        ids = list(range(guard_count))
        rng.shuffle(ids)
        blocks = []
        position = 0
        while position < guard_count:
            size = rng.randint(1, min(4, guard_count - position))
            group = sorted(ids[position : position + size])
            position += size
            blocks.append(
                {
                    "ids": group,
                    "count": None if rng.random() < 0.45 else rng.randint(0, size),
                }
            )
        support_kernel = {"guards": guard_count, "blocks": blocks}
        counter = Counter(support_kernel)
        coefficient_by_guard_set: dict[int, int] = {}
        for _ in range(rng.randint(0, 14)):
            guard_set = rng.randint(1, (1 << guard_count) - 1)
            coefficient_by_guard_set[guard_set] = (
                coefficient_by_guard_set.get(guard_set, 0) + rng.randint(-12, 12)
            )
        terms = sorted(
            (guard_set, weight)
            for guard_set, weight in coefficient_by_guard_set.items()
            if weight
        )
        constant = rng.randint(-20, 20)
        legal = legal_masks_from_blocks(guard_count, blocks)
        brute_square = sum(
            eval_difference(constant, terms, mask) ** 2 for mask in legal
        )
        counted_square = counter.square(
            constant,
            terms,
            budget=Budget(operations=10**9, seconds=30),
        )
        if counted_square != brute_square:
            raise AssertionError(
                (guard_count, blocks, constant, terms, counted_square, brute_square)
            )
        witness = counter.witness(
            constant,
            terms,
            budget=Budget(operations=10**9, seconds=30),
        )
        if brute_square == 0:
            if witness is not None:
                raise AssertionError("zero square sum returned a witness")
        elif witness not in legal or eval_difference(constant, terms, witness) == 0:
            raise AssertionError("invalid separating witness")
        counter_cases += 1
    report["counter_random_cases"] = counter_cases

    # 2. Signature, literal traffic, equality, frontier optimum and resident codecs.
    mapping_cases = 0
    mask_checks = 0
    frontier_checks = 0
    codec_checks = 0
    for case_index in range(EXPECTED_COUNTS["mapping_random_cases"]):
        candidate = random_pair(rng, rng.randint(1, 7))
        validate_pair(candidate)
        legal = list(masks(candidate["kernel"], limit=1_000_000))
        values = [
            [rng.randrange(2**32) for _ in range(tensor["length"])]
            for tensor in candidate["kernel"]["tensors"]
        ]
        for level in range(len(candidate["architecture"]["capacity"])):
            constant, terms = difference(candidate, level)
            deltas = []
            for mask in legal:
                literal_delta = (
                    traffic(candidate, "target", mask)[level]
                    - traffic(candidate, "source", mask)[level]
                )
                signature_delta = eval_difference(constant, terms, mask)
                if literal_delta != signature_delta:
                    raise AssertionError(
                        (
                            case_index,
                            level,
                            mask,
                            literal_delta,
                            signature_delta,
                        )
                    )
                deltas.append(literal_delta)
                mask_checks += 1
            square_sum = Counter(candidate["kernel"]).square(
                constant,
                terms,
                budget=Budget(operations=10**9, seconds=30),
            )
            if square_sum != sum(delta * delta for delta in deltas):
                raise AssertionError("symbolic square sum disagrees with enumeration")
            equality_claim = {"kind": "equal", "level": level, "square_sum": 0}
            if all(delta == 0 for delta in deltas):
                if not check_equal(candidate, equality_claim, level)["accepted"]:
                    raise AssertionError("true equality was rejected")
            else:
                try:
                    check_equal(candidate, equality_claim, level)
                except Invalid:
                    pass
                else:
                    raise AssertionError("false equality was accepted")

            if case_index < 45:
                order = list(range(candidate["kernel"]["guards"]))
                rng.shuffle(order)
                proof = prove_upper(
                    candidate,
                    order=order,
                    level=level,
                    max_layer=100_000,
                    max_total=300_000,
                    seconds=30,
                )
                checked = check_upper(
                    candidate,
                    proof,
                    level,
                    proof["bound"],
                    max_layer=100_000,
                    max_total=300_000,
                    seconds=30,
                )
                if not checked["accepted"] or not checked["exact"]:
                    raise AssertionError("generated upper certificate was rejected")
                if proof["bound"] != max(deltas):
                    raise AssertionError(
                        (case_index, level, proof["bound"], max(deltas))
                    )
                if (
                    proof["witness"] not in legal
                    or eval_difference(constant, terms, proof["witness"])
                    != max(deltas)
                ):
                    raise AssertionError("upper-bound witness is not tight")
                frontier_checks += 1

        for mask in legal[: min(5, len(legal))]:
            expected = execute(candidate["kernel"], candidate["source"], mask, values)
            for mapping_name in ("source", "target"):
                observed, resident_cost = execute_resident(
                    candidate, mapping_name, mask, values
                )
                if observed != expected:
                    raise AssertionError("resident execution changed kernel semantics")
                if resident_cost != traffic(candidate, mapping_name, mask):
                    raise AssertionError("resident codec cost disagrees with literal traffic")
                codec_checks += 1
        mapping_cases += 1

    report.update(
        mapping_random_cases=mapping_cases,
        literal_signature_mask_checks=mask_checks,
        frontier_exact_checks=frontier_checks,
        resident_codec_checks=codec_checks,
    )

    # 3. Fixed-zero reduction against direct cut enumeration for fresh graphs.
    reduction_cases = 0
    reduction_masks = 0
    for vertex_count in range(2, 7):
        possible_edges = list(itertools.combinations(range(vertex_count), 2))
        for _ in range(10):
            edges = [edge for edge in possible_edges if rng.random() < 0.45]
            if not edges:
                edges = [rng.choice(possible_edges)]
            threshold = rng.randint(1, len(edges))
            promises = ("free", "nm") if vertex_count <= 4 else ("free",)
            for promise in promises:
                candidate = cut_threshold(vertex_count, edges, threshold, promise)
                constant, terms = difference(candidate)
                for mask in masks(candidate["kernel"], limit=200_000):
                    selected = [
                        (mask >> (4 * vertex if promise == "nm" else vertex)) & 1
                        for vertex in range(vertex_count)
                    ]
                    cut_size = sum(selected[left] ^ selected[right] for left, right in edges)
                    expected = 4 * (cut_size - (threshold - 1))
                    if eval_difference(constant, terms, mask) != expected:
                        raise AssertionError("reduction signature disagrees with cut form")
                    if (
                        traffic(candidate, "target", mask)[0]
                        - traffic(candidate, "source", mask)[0]
                        != expected
                    ):
                        raise AssertionError("reduction literal traffic disagrees with cut form")
                    reduction_masks += 1
                if candidate["architecture"]["capacity"] != [8]:
                    raise AssertionError("fixed-payload reduction lost its 8-byte capacity")
                reduction_cases += 1

    report.update(
        reduction_random_cases=reduction_cases,
        reduction_mask_checks=reduction_masks,
    )
    observed_counts = {key: report[key] for key in EXPECTED_COUNTS}
    if observed_counts != EXPECTED_COUNTS:
        raise AssertionError((observed_counts, EXPECTED_COUNTS))
    return report


def publish(path: Path, report: dict) -> None:
    path = path.resolve()
    if path.exists():
        raise FileExistsError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="optional new JSON path; an existing path is refused",
    )
    args = parser.parse_args()
    report = run()
    if args.output is not None:
        publish(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
