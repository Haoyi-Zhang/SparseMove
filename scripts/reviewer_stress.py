#!/usr/bin/env python3
"""Post-freeze stress and metamorphic validation through a separate generator.

The production analyses are exercised on fresh, deterministic pairs emitted by a
code path that does not call ``dataflow.generate``.  A local literal interpreter
and exhaustive masks provide the oracle.  This is a post-freeze stress suite, not
a statistically held-out workload sample and not external validation.
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import os
import random
import resource
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dataflow.checker import check_equal, check_upper
from dataflow.literal import traffic
from dataflow.model import difference, eval_difference, validate_pair
from dataflow.moment import Counter
from dataflow.producer import prove_upper
from dataflow.transformation_check import check_transformation

SEED = 20260921
CASE_COUNT = 144
PROOF_CASES = 72


def reservation(scope: dict) -> int:
    extent = scope["hi"] - scope["lo"]
    return 8 + 8 * extent if scope["format"] == "coordinate" else 4 * extent


def legal_masks(kernel: dict):
    rows = []
    for block in kernel["blocks"]:
        ids = block["ids"]
        sizes = range(len(ids) + 1) if block["count"] is None else (block["count"],)
        rows.append([
            sum(1 << guard for guard in selected)
            for size in sizes for selected in itertools.combinations(ids, size)
        ])
    for pieces in itertools.product(*rows):
        yield sum(pieces)


def present(kernel: dict, tensor: int, address: int, mask: int) -> bool:
    support = kernel["tensors"][tensor]["support"]
    if support is None:
        return True
    guard = support[address]
    return guard < 0 or bool(mask & (1 << guard))


def packet_bytes(kernel: dict, scope: dict, mask: int) -> int:
    extent = scope["hi"] - scope["lo"]
    if scope["format"] == "dense":
        return 4 * extent
    active = sum(
        present(kernel, scope["tensor"], address, mask)
        for address in range(scope["lo"], scope["hi"])
    )
    return 4 * active if scope["format"] == "bitmap" else 8 + 8 * active


def local_traffic(pair: dict, which: str, mask: int) -> list[int]:
    kernel = pair["kernel"]
    mapping = pair[which]
    costs = [(kernel["guards"] + 7) // 8 + 4 * kernel["outputs"]]
    costs.extend(0 for _ in pair["architecture"]["capacity"][1:])
    loaded = set()
    for position, event_id in enumerate(mapping["order"]):
        event = kernel["events"][event_id]
        if event["guard"] >= 0 and not (mask & (1 << event["guard"])):
            continue
        for scope_id in mapping["bindings"][event_id]:
            chain = []
            while scope_id >= 0:
                chain.append(scope_id)
                scope_id = mapping["scopes"][scope_id]["parent"]
            for scope_id in reversed(chain):
                scope = mapping["scopes"][scope_id]
                if not (scope["begin"] <= position < scope["end"]):
                    raise AssertionError("local lifetime mismatch")
                if scope_id not in loaded:
                    loaded.add(scope_id)
                    costs[scope["level"]] += packet_bytes(kernel, scope, mask)
    return costs


def blocks(rng: random.Random, guards: int) -> list[dict]:
    ids = list(range(guards))
    rng.shuffle(ids)
    answer = []
    cursor = 0
    while cursor < guards:
        size = min(guards - cursor, rng.randint(1, 4))
        selected = sorted(ids[cursor:cursor + size])
        cursor += size
        if size == 1 and rng.random() < 0.65:
            count = rng.randint(0, 1)
        elif rng.random() < 0.55:
            count = rng.randint(0, size)
        else:
            count = None
        answer.append({"ids": selected, "count": count})
    return answer


def chunks(rng: random.Random, order: list[int]) -> list[list[int]]:
    answer = []
    cursor = 0
    while cursor < len(order):
        width = rng.randint(1, min(5, len(order) - cursor))
        answer.append(order[cursor:cursor + width])
        cursor += width
    return answer


def mapping(kernel: dict, rng: random.Random, hierarchy: bool) -> dict:
    event_count = len(kernel["events"])
    order = list(range(event_count))
    rng.shuffle(order)
    scopes = []
    bindings = [[-1, -1] for _ in kernel["events"]]
    formats = [rng.choice(("dense", "bitmap", "coordinate")), "dense"]
    for operand in (0, 1):
        for group in chunks(rng, order):
            tensor = kernel["events"][group[0]]["reads"][operand][0]
            addresses = [kernel["events"][event_id]["reads"][operand][1] for event_id in group]
            if operand == 0 and rng.random() < 0.35:
                lo, hi = 0, kernel["tensors"][tensor]["length"]
            else:
                lo, hi = min(addresses), max(addresses) + 1
            positions = [order.index(event_id) for event_id in group]
            scope_id = len(scopes)
            scopes.append({
                "tensor": tensor, "lo": lo, "hi": hi,
                "level": 1 if hierarchy else 0,
                "begin": min(positions), "end": max(positions) + 1,
                "parent": -1, "format": formats[operand],
            })
            for event_id in group:
                bindings[event_id][operand] = scope_id
    if hierarchy:
        child_count = len(scopes)
        for scope in scopes:
            scope["parent"] = child_count + scope["tensor"]
        for tensor, spec in enumerate(kernel["tensors"]):
            scopes.append({
                "tensor": tensor, "lo": 0, "hi": spec["length"],
                "level": 0, "begin": 0, "end": event_count,
                "parent": -1,
                "format": rng.choice(("dense", "bitmap", "coordinate")) if spec["support"] is not None else "dense",
            })
    return {"order": order, "scopes": scopes, "bindings": bindings}


def capacity(mappings: list[dict]) -> list[int]:
    levels = 1 + max(scope["level"] for mapping in mappings for scope in mapping["scopes"])
    answer = [0] * levels
    for mapping in mappings:
        for level in range(levels):
            changes = []
            for scope in mapping["scopes"]:
                if scope["level"] == level:
                    size = reservation(scope)
                    changes.extend(((scope["begin"], size), (scope["end"], -size)))
            live = 0
            for _, delta in sorted(changes):
                live += delta
                answer[level] = max(answer[level], live)
    return answer


def fresh_pair(rng: random.Random, index: int) -> dict:
    guards = rng.randint(1, 8)
    support = []
    addresses_by_guard = defaultdict(list)
    for guard in range(guards):
        repetitions = 1 + rng.randrange(3)
        for _ in range(repetitions):
            addresses_by_guard[guard].append(len(support))
            support.append(guard)
    always_addresses = []
    for _ in range(1 + rng.randrange(3)):
        always_addresses.append(len(support))
        support.append(-1)
    dense_length = rng.randint(2, 9)
    output_count = rng.randint(1, 3)
    event_count = rng.randint(max(guards, 2), 4 * guards + 8)
    events = []
    for event_index in range(event_count):
        if event_index < guards:
            guard = event_index
        else:
            guard = -1 if rng.random() < 0.16 else rng.randrange(guards)
        address = rng.choice(always_addresses if guard < 0 else addresses_by_guard[guard])
        events.append({
            "guard": guard,
            "output": rng.randrange(output_count),
            "reads": [[0, address], [1, rng.randrange(dense_length)]],
        })
    kernel = {
        "guards": guards,
        "blocks": blocks(rng, guards),
        "tensors": [
            {"length": len(support), "bytes": 4, "support": support},
            {"length": dense_length, "bytes": 4, "support": None},
        ],
        "outputs": output_count,
        "events": events,
        "arithmetic": "mod32",
    }
    hierarchy = index % 3 == 0
    source = mapping(kernel, rng, hierarchy)
    target = mapping(kernel, rng, hierarchy)
    pair = {
        "kernel": kernel,
        "architecture": {
            "capacity": capacity([source, target]),
            "control_capacity": (guards + 7) // 8 + 4 * output_count,
        },
        "source": source,
        "target": target,
    }
    validate_pair(pair)
    return pair


def rename_guards(pair: dict, permutation: list[int]) -> dict:
    renamed = copy.deepcopy(pair)
    kernel = renamed["kernel"]
    for block in kernel["blocks"]:
        block["ids"] = [permutation[guard] for guard in block["ids"]]
    for tensor in kernel["tensors"]:
        if tensor["support"] is not None:
            tensor["support"] = [permutation[guard] if guard >= 0 else -1 for guard in tensor["support"]]
    for event in kernel["events"]:
        if event["guard"] >= 0:
            event["guard"] = permutation[event["guard"]]
    validate_pair(renamed)
    return renamed


def rename_mask(mask: int, permutation: list[int]) -> int:
    answer = 0
    for old, new in enumerate(permutation):
        if mask & (1 << old):
            answer |= 1 << new
    return answer


def run() -> dict:
    rng = random.Random(SEED)
    mask_checks = level_checks = proof_checks = equal_identity_checks = 0
    swap_checks = rename_checks = self_equality_checks = 0
    positive_cases = negative_cases = equal_cases = mixed_cases = 0
    maximum_terms = maximum_masks = maximum_states = 0
    for index in range(CASE_COUNT):
        pair = fresh_pair(rng, index)
        masks = list(legal_masks(pair["kernel"]))
        maximum_masks = max(maximum_masks, len(masks))
        levels = len(pair["architecture"]["capacity"])
        deltas_by_level = [[] for _ in range(levels)]
        for mask in masks:
            source_local = local_traffic(pair, "source", mask)
            target_local = local_traffic(pair, "target", mask)
            source_production = traffic(pair, "source", mask)
            target_production = traffic(pair, "target", mask)
            if source_local != source_production or target_local != target_production:
                raise AssertionError((index, mask, "literal oracle"))
            for level in range(levels):
                constant, terms = difference(pair, level)
                delta = target_local[level] - source_local[level]
                if eval_difference(constant, terms, mask) != delta:
                    raise AssertionError((index, level, mask, "signature"))
                deltas_by_level[level].append(delta)
                maximum_terms = max(maximum_terms, len(terms))
                level_checks += 1
            mask_checks += 1
        swapped = copy.deepcopy(pair)
        swapped["source"], swapped["target"] = swapped["target"], swapped["source"]
        validate_pair(swapped)
        permutation = list(range(pair["kernel"]["guards"]))
        rng.shuffle(permutation)
        renamed = rename_guards(pair, permutation)
        for mask in masks:
            renamed_mask = rename_mask(mask, permutation)
            source_values = local_traffic(pair, "source", mask)
            target_values = local_traffic(pair, "target", mask)
            check_transformation(swapped, mask, target_values, source_values)
            check_transformation(renamed, renamed_mask, source_values, target_values)
            for level in range(levels):
                old_source = local_traffic(pair, "source", mask)[level]
                old_target = local_traffic(pair, "target", mask)[level]
                if local_traffic(swapped, "target", mask)[level] - local_traffic(swapped, "source", mask)[level] != -(old_target - old_source):
                    raise AssertionError((index, level, mask, "swap"))
                if local_traffic(renamed, "source", renamed_mask)[level] != old_source or local_traffic(renamed, "target", renamed_mask)[level] != old_target:
                    raise AssertionError((index, level, mask, "rename"))
                swap_checks += 1
                rename_checks += 1
        same = copy.deepcopy(pair)
        same["target"] = copy.deepcopy(same["source"])
        validate_pair(same)
        for level in range(levels):
            constant, terms = difference(pair, level)
            counter = Counter(pair["kernel"])
            square = counter.square(constant, terms)
            brute_square = sum(delta * delta for delta in deltas_by_level[level])
            if square != brute_square:
                raise AssertionError((index, level, "square"))
            equal_claim = {"kind": "equal", "level": level, "square_sum": 0}
            if brute_square == 0:
                if not check_equal(pair, equal_claim, level)["accepted"]:
                    raise AssertionError((index, level, "true equality"))
            else:
                try:
                    check_equal(pair, equal_claim, level)
                except ValueError:
                    pass
                else:
                    raise AssertionError((index, level, "false equality"))
            if not check_equal(same, equal_claim, level)["accepted"]:
                raise AssertionError((index, level, "self equality"))
            self_equality_checks += 1
            equal_identity_checks += 1
            values = deltas_by_level[level]
            has_positive = any(value > 0 for value in values)
            has_negative = any(value < 0 for value in values)
            if not has_positive and not has_negative:
                equal_cases += 1
            elif has_positive and has_negative:
                mixed_cases += 1
            elif has_positive:
                positive_cases += 1
            else:
                negative_cases += 1
            if index < PROOF_CASES:
                proof = prove_upper(pair, level=level, max_layer=200_000, max_total=500_000, seconds=20)
                checked = check_upper(pair, proof, level, proof["bound"], max_layer=200_000, max_total=500_000, seconds=20)
                if not checked["accepted"] or not checked["exact"] or proof["bound"] != max(values):
                    raise AssertionError((index, level, "upper"))
                maximum_states = max(maximum_states, proof["statistics"]["total_states"])
                proof_checks += 1
    return {
        "status": "passed",
        "seed": SEED,
        "cases": CASE_COUNT,
        "proof_cases": PROOF_CASES,
        "mask_checks": mask_checks,
        "level_mask_checks": level_checks,
        "exact_square_checks": equal_identity_checks,
        "upper_certificate_checks": proof_checks,
        "source_target_swap_checks": swap_checks,
        "guard_renaming_checks": rename_checks,
        "self_equality_checks": self_equality_checks,
        "sign_classes": {
            "equal": equal_cases,
            "positive_only": positive_cases,
            "negative_only": negative_cases,
            "mixed": mixed_cases,
        },
        "maximum_legal_masks_per_case": maximum_masks,
        "maximum_signature_terms": maximum_terms,
        "maximum_certificate_states": maximum_states,
    }


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
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    begin = time.monotonic()
    cpu = time.process_time()
    report = run()
    use = resource.getrusage(resource.RUSAGE_SELF)
    report.update(
        cpu_seconds=time.process_time() - cpu,
        wall_seconds=time.monotonic() - begin,
        peak_rss_kib=use.ru_maxrss,
        swap_events=use.ru_nswap,
    )
    if args.output is not None:
        publish(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
