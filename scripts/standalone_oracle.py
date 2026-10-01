#!/usr/bin/env python3
"""Standalone finite oracle for the frozen artifact.

This program intentionally does not import the production ``dataflow`` package.
It re-parses the frozen JSON inputs, independently enumerates the declared support
families, interprets load-once traffic, reconstructs signed-OR expressions, checks
the avoidance-count square identity, and exercises packet bytes and modular
execution.  It is still project-authored validation, not external review or a
proof assistant.
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import math
import os
import resource
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Iterator

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "inputs"
RESULTS = ROOT / "results"
CAMPAIGN = [
    "structured", "grid", "cycle", "format", "graph-free", "graph-nm",
    "random-0", "random-1", "random-2",
]
MASK_LIMIT = 1_000_000
MOD = 1 << 32
MAX_GUARDS = 4096
MAX_EVENTS = 65536
MAX_SCOPES = 131072
MAX_LEVELS = 4


class AdmissionError(ValueError):
    """Malformed or inadmissible finite-IR input in the standalone path."""


def fail(message: object) -> None:
    raise AssertionError(message)


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise AssertionError(f"{path}:{line_no}: {exc}") from exc
    return rows


def reject(message: str) -> None:
    raise AdmissionError(message)


def exact_object(value, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        reject(f"{label}: unexpected or missing fields")
    return value


def bounded_list(value, maximum: int, label: str) -> list:
    if type(value) is not list or len(value) > maximum:
        reject(f"{label}: expected bounded list")
    return value


def bounded_int(value, lower: int, upper: int, label: str) -> int:
    if type(value) is not int or not lower <= value <= upper:
        reject(f"{label}: expected integer in [{lower}, {upper}]")
    return value


def reserved_bytes(scope: dict) -> int:
    extent = scope["hi"] - scope["lo"]
    return 8 + 8 * extent if scope["format"] == "coordinate" else 4 * extent


def admit_pair(pair: dict) -> dict:
    """Independently admit the documented finite IR without production imports.

    This duplicates the prose contract in a separately written parser/validator:
    exact fields and integer types, support/operand compatibility, event
    permutations, hierarchy containment, half-open lifetimes, leaf bindings, and
    payload/control capacity are all checked before any standalone interpretation.
    """
    exact_object(pair, {"kernel", "architecture", "source", "target"}, "pair")
    kernel = exact_object(
        pair["kernel"],
        {"guards", "blocks", "tensors", "outputs", "events", "arithmetic"},
        "kernel",
    )
    architecture = exact_object(pair["architecture"], {"capacity", "control_capacity"}, "architecture")

    guards = bounded_int(kernel["guards"], 1, MAX_GUARDS, "guards")
    if kernel["arithmetic"] != "mod32":
        reject("arithmetic: only mod32 is implemented")
    outputs = bounded_int(kernel["outputs"], 1, MAX_EVENTS, "outputs")

    tensors = bounded_list(kernel["tensors"], 64, "tensors")
    if not tensors:
        reject("no tensors")
    for tensor in tensors:
        exact_object(tensor, {"length", "bytes", "support"}, "tensor")
        length = bounded_int(tensor["length"], 1, 2**31 - 1, "tensor length")
        if type(tensor["bytes"]) is not int or tensor["bytes"] != 4:
            reject("mod32 tensor slots must have exactly 4 bytes")
        if tensor["support"] is not None:
            support = bounded_list(tensor["support"], MAX_EVENTS, "tensor support")
            if len(support) != length:
                reject("tensor support/length mismatch")
            for guard in support:
                bounded_int(guard, -1, guards - 1, "tensor support guard")

    events = bounded_list(kernel["events"], MAX_EVENTS, "events")
    if not events:
        reject("empty kernel not in executable fragment")
    for event_row in events:
        exact_object(event_row, {"guard", "output", "reads"}, "event")
        event_guard = bounded_int(event_row["guard"], -1, guards - 1, "event guard")
        bounded_int(event_row["output"], 0, outputs - 1, "event output")
        reads = bounded_list(event_row["reads"], 8, "event reads")
        if not reads:
            reject("empty product not in executable fragment")
        for read in reads:
            if type(read) is not list or len(read) != 2:
                reject("read shape")
            tensor_id = bounded_int(read[0], 0, len(tensors) - 1, "tensor index")
            address = bounded_int(read[1], 0, tensors[tensor_id]["length"] - 1, "tensor address")
            support = tensors[tensor_id]["support"]
            if support is not None and support[address] >= 0 and support[address] != event_guard:
                reject("event guard does not imply sparse operand presence")

    blocks = bounded_list(kernel["blocks"], guards, "support blocks")
    covered: set[int] = set()
    for block in blocks:
        exact_object(block, {"ids", "count"}, "support block")
        ids = bounded_list(block["ids"], guards, "block ids")
        if not ids:
            reject("empty support block")
        for guard in ids:
            bounded_int(guard, 0, guards - 1, "block guard")
            if guard in covered:
                reject("overlapping or repeated block guard")
            covered.add(guard)
        if block["count"] is not None:
            bounded_int(block["count"], 0, len(ids), "block count")
    if covered != set(range(guards)):
        reject("support blocks must partition all guards")

    capacities = bounded_list(architecture["capacity"], MAX_LEVELS, "capacity")
    if not capacities:
        reject("no hierarchy levels")
    for capacity in capacities:
        bounded_int(capacity, 1, 2**40, "payload capacity")
    control_capacity = bounded_int(architecture["control_capacity"], 1, 2**40, "control capacity")
    if control_capacity < (guards + 7) // 8 + 4 * outputs:
        reject("bitmap plus output accumulator reservation")

    def admit_mapping(mapping: dict, label: str) -> dict:
        exact_object(mapping, {"order", "scopes", "bindings"}, label)
        event_count = len(events)
        order = bounded_list(mapping["order"], event_count, f"{label} order")
        if len(order) != event_count:
            reject(f"{label}: event omission")
        for event_id in order:
            bounded_int(event_id, 0, event_count - 1, f"{label} order event")
        if len(set(order)) != event_count:
            reject(f"{label}: order is not an event permutation")
        positions = [0] * event_count
        for position, event_id in enumerate(order):
            positions[event_id] = position

        scopes = bounded_list(mapping["scopes"], MAX_SCOPES, f"{label} scopes")
        if not scopes:
            reject(f"{label}: no input residency")
        changes: list[list[tuple[int, int]]] = [[] for _ in capacities]
        packed_extent = 0
        for scope in scopes:
            exact_object(
                scope,
                {"tensor", "lo", "hi", "level", "begin", "end", "parent", "format"},
                f"{label} scope",
            )
            tensor_id = bounded_int(scope["tensor"], 0, len(tensors) - 1, "scope tensor")
            low = bounded_int(scope["lo"], 0, tensors[tensor_id]["length"] - 1, "scope lo")
            bounded_int(scope["hi"], low + 1, tensors[tensor_id]["length"], "scope hi")
            level = bounded_int(scope["level"], 0, len(capacities) - 1, "scope level")
            begin = bounded_int(scope["begin"], 0, event_count - 1, "scope begin")
            end = bounded_int(scope["end"], begin + 1, event_count, "scope end")
            parent = bounded_int(scope["parent"], -1, len(scopes) - 1, "scope parent")
            if (level == 0) != (parent == -1):
                reject(f"{label}: root/parent mismatch")
            if scope["format"] not in {"dense", "bitmap", "coordinate"}:
                reject(f"{label}: unsupported tile format")
            if scope["format"] != "dense" and tensors[tensor_id]["support"] is None:
                reject(f"{label}: packed format requires an explicit support map")
            if scope["format"] != "dense":
                packed_extent += scope["hi"] - scope["lo"]
            reservation = reserved_bytes(scope)
            changes[level].append((begin, reservation))
            changes[level].append((end, -reservation))
        if packed_extent > 200_000:
            reject(f"{label}: packed-record expansion admission limit")

        for scope in scopes:
            if scope["parent"] < 0:
                continue
            parent = scopes[scope["parent"]]
            if parent["level"] != scope["level"] - 1:
                reject(f"{label}: parent must be at the previous level")
            if parent["tensor"] != scope["tensor"] or not (
                parent["lo"] <= scope["lo"] < scope["hi"] <= parent["hi"]
            ):
                reject(f"{label}: parent tile does not contain child")
            if not (parent["begin"] <= scope["begin"] < scope["end"] <= parent["end"]):
                reject(f"{label}: parent lifetime does not contain child")

        peak_payload = []
        for level, level_changes in enumerate(changes):
            live = high = 0
            for _, delta in sorted(level_changes, key=lambda item: (item[0], 0 if item[1] < 0 else 1)):
                live += delta
                if live < 0:
                    reject(f"{label}: negative residency accounting")
                high = max(high, live)
            if live != 0:
                reject(f"{label}: unreleased residency")
            if high > capacities[level]:
                reject(f"{label}: payload capacity exceeded")
            peak_payload.append(high)

        bindings = bounded_list(mapping["bindings"], event_count, f"{label} bindings")
        if len(bindings) != event_count:
            reject(f"{label}: binding/event mismatch")
        for event_id, event_row in enumerate(events):
            row = bounded_list(bindings[event_id], 8, f"{label} operand bindings")
            if len(row) != len(event_row["reads"]):
                reject(f"{label}: binding/operand mismatch")
            for read, scope_id in zip(event_row["reads"], row):
                bounded_int(scope_id, 0, len(scopes) - 1, f"{label} binding scope")
                scope = scopes[scope_id]
                if scope["level"] != len(capacities) - 1 or scope["tensor"] != read[0] or not (
                    scope["lo"] <= read[1] < scope["hi"]
                ):
                    reject(f"{label}: binding does not provide declared operand")
                if not (scope["begin"] <= positions[event_id] < scope["end"]):
                    reject(f"{label}: use outside lifetime")
        return {
            "peak_payload_bytes": peak_payload,
            "event_count": event_count,
            "scope_count": len(scopes),
        }

    return {
        "source": admit_mapping(pair["source"], "source mapping"),
        "target": admit_mapping(pair["target"], "target mapping"),
    }


def check_admission_mutations() -> dict:
    """Exercise the independently implemented admission boundary on known faults."""
    base = load_json(ROOT / "examples" / "structured.json")
    if base["architecture"]["capacity"] != [48] or base["architecture"]["control_capacity"] != 9:
        fail("structured admission fixture no longer has the audited 48-byte payload / 9-byte control limits")
    admitted = admit_pair(base)
    if admitted["source"]["peak_payload_bytes"] != [48] or admitted["target"]["peak_payload_bytes"] != [48]:
        fail("structured admission fixture no longer reaches the audited 48-byte payload peak")

    def set_payload_47(pair):
        pair["architecture"]["capacity"][0] = 47

    def set_control_8(pair):
        pair["architecture"]["control_capacity"] = 8

    def break_permutation(pair):
        pair["source"]["order"][0] = pair["source"]["order"][1]

    def break_parent(pair):
        pair["source"]["scopes"][0]["parent"] = 1

    def break_guard_operand(pair):
        pair["kernel"]["events"][0]["guard"] = 1

    def break_binding_operand(pair):
        pair["source"]["bindings"][0][0] = 1

    def break_type(pair):
        pair["target"]["order"][0] = False

    mutations = [
        ("payload-capacity-48-to-47", set_payload_47, "payload capacity exceeded"),
        ("control-capacity-9-to-8", set_control_8, "bitmap plus output accumulator reservation"),
        ("event-order-permutation", break_permutation, "not an event permutation"),
        ("parent-relation", break_parent, "root/parent mismatch"),
        ("guard-operand", break_guard_operand, "event guard does not imply sparse operand presence"),
        ("binding-operand", break_binding_operand, "binding does not provide declared operand"),
        ("strict-integer-type", break_type, "expected integer"),
    ]
    rejected = []
    for name, mutate, expected_reason in mutations:
        candidate = copy.deepcopy(base)
        mutate(candidate)
        try:
            admit_pair(candidate)
        except AdmissionError as exc:
            if expected_reason not in str(exc):
                fail(("standalone admission rejected mutation for the wrong obligation", name, str(exc)))
            rejected.append(name)
        else:
            fail(("standalone admission accepted mutation", name))
    return {
        "structured_source_peak_payload": admitted["source"]["peak_payload_bytes"],
        "structured_target_peak_payload": admitted["target"]["peak_payload_bytes"],
        "admission_mutations_rejected": len(rejected),
        "admission_mutation_names": rejected,
    }


def legal_masks(kernel: dict, limit: int = MASK_LIMIT) -> Iterator[int]:
    options: list[list[int]] = []
    count = 1
    for block in kernel["blocks"]:
        ids = list(block["ids"])
        want = block["count"]
        sizes: Iterable[int] = range(len(ids) + 1) if want is None else (want,)
        row = []
        for size in sizes:
            for selected in itertools.combinations(ids, size):
                row.append(sum(1 << guard for guard in selected))
        count *= len(row)
        if count > limit:
            raise AssertionError("standalone mask limit exceeded")
        options.append(row)
    for selected_blocks in itertools.product(*options):
        yield sum(selected_blocks)


def support_ok(kernel: dict, mask: int) -> bool:
    if type(mask) is not int or mask < 0 or mask >> kernel["guards"]:
        return False
    for block in kernel["blocks"]:
        want = block["count"]
        if want is not None and sum((mask >> guard) & 1 for guard in block["ids"]) != want:
            return False
    return True


def present(kernel: dict, tensor: int, address: int, mask: int) -> bool:
    support = kernel["tensors"][tensor]["support"]
    if support is None:
        return True
    guard = support[address]
    return guard < 0 or bool((mask >> guard) & 1)


def packet_bytes(kernel: dict, scope: dict, mask: int) -> int:
    extent = scope["hi"] - scope["lo"]
    if scope["format"] == "dense":
        return 4 * extent
    selected = sum(
        present(kernel, scope["tensor"], address, mask)
        for address in range(scope["lo"], scope["hi"])
    )
    if scope["format"] == "bitmap":
        return 4 * selected
    if scope["format"] == "coordinate":
        return 8 + 8 * selected
    fail(("unknown format", scope["format"]))
    return 0


def direct_traffic(pair: dict, which: str, mask: int) -> list[int]:
    kernel = pair["kernel"]
    mapping = pair[which]
    if not support_ok(kernel, mask):
        fail("illegal mask")
    costs = [(kernel["guards"] + 7) // 8 + 4 * kernel["outputs"]]
    costs.extend(0 for _ in pair["architecture"]["capacity"][1:])
    loaded: set[int] = set()
    for position, event_id in enumerate(mapping["order"]):
        event = kernel["events"][event_id]
        if event["guard"] >= 0 and not ((mask >> event["guard"]) & 1):
            continue
        for scope_id in mapping["bindings"][event_id]:
            chain = []
            while scope_id >= 0:
                chain.append(scope_id)
                scope_id = mapping["scopes"][scope_id]["parent"]
            for scope_id in reversed(chain):
                scope = mapping["scopes"][scope_id]
                if not (scope["begin"] <= position < scope["end"]):
                    fail(("use outside lifetime", which, event_id, scope_id))
                if scope_id not in loaded:
                    costs[scope["level"]] += packet_bytes(kernel, scope, mask)
                    loaded.add(scope_id)
    return costs


def packet_linear(kernel: dict, scope: dict) -> tuple[int, dict[int, int]]:
    extent = scope["hi"] - scope["lo"]
    if scope["format"] == "dense":
        return 4 * extent, {}
    constant = 8 if scope["format"] == "coordinate" else 0
    per_position = 8 if scope["format"] == "coordinate" else 4
    coefficients: dict[int, int] = defaultdict(int)
    support = kernel["tensors"][scope["tensor"]]["support"]
    if support is None:
        fail("packed scope without support")
    for guard in support[scope["lo"]:scope["hi"]]:
        if guard < 0:
            constant += per_position
        else:
            coefficients[guard] += per_position
    return constant, dict(coefficients)


def mapping_signature(kernel: dict, mapping: dict, levels: int) -> tuple[list[int], list[dict[int, int]]]:
    scopes = mapping["scopes"]
    footprints = [0] * len(scopes)
    unconditional = [False] * len(scopes)
    for event_id, event in enumerate(kernel["events"]):
        for scope_id in mapping["bindings"][event_id]:
            while scope_id >= 0:
                if event["guard"] < 0:
                    unconditional[scope_id] = True
                else:
                    footprints[scope_id] |= 1 << event["guard"]
                scope_id = scopes[scope_id]["parent"]
    constants = [(kernel["guards"] + 7) // 8 + 4 * kernel["outputs"]]
    constants.extend(0 for _ in range(levels - 1))
    terms: list[dict[int, int]] = [defaultdict(int) for _ in range(levels)]
    for scope_id, scope in enumerate(scopes):
        constant, packets = packet_linear(kernel, scope)
        level = scope["level"]
        footprint = footprints[scope_id]
        if unconditional[scope_id]:
            constants[level] += constant
            for guard, weight in packets.items():
                terms[level][1 << guard] += weight
        elif footprint:
            terms[level][footprint] += constant
            for guard, weight in packets.items():
                singleton = 1 << guard
                terms[level][footprint] += weight
                terms[level][singleton] += weight
                terms[level][footprint | singleton] -= weight
    return constants, [dict((foot, weight) for foot, weight in table.items() if weight) for table in terms]


def difference(pair: dict, level: int) -> tuple[int, list[tuple[int, int]]]:
    levels = len(pair["architecture"]["capacity"])
    source_constant, source_terms = mapping_signature(pair["kernel"], pair["source"], levels)
    target_constant, target_terms = mapping_signature(pair["kernel"], pair["target"], levels)
    terms: dict[int, int] = defaultdict(int, target_terms[level])
    for footprint, weight in source_terms[level].items():
        terms[footprint] -= weight
    return target_constant[level] - source_constant[level], sorted(
        (footprint, weight) for footprint, weight in terms.items() if weight
    )


def evaluate(constant: int, terms: list[tuple[int, int]], mask: int) -> int:
    return constant + sum(weight for footprint, weight in terms if footprint & mask)


def avoid_count(kernel: dict, footprint: int) -> int:
    count = 1
    for block in kernel["blocks"]:
        ids = block["ids"]
        available = sum(not ((footprint >> guard) & 1) for guard in ids)
        want = block["count"]
        count *= 1 << available if want is None else math.comb(available, want) if available >= want else 0
    return count


def square_sum(kernel: dict, constant: int, terms: list[tuple[int, int]]) -> int:
    total_coefficient = constant + sum(weight for _, weight in terms)
    answer = total_coefficient * total_coefficient * avoid_count(kernel, 0)
    singles = [avoid_count(kernel, footprint) for footprint, _ in terms]
    answer -= 2 * total_coefficient * sum(
        weight * avoided for (_, weight), avoided in zip(terms, singles)
    )
    for i, (footprint, weight) in enumerate(terms):
        answer += weight * weight * singles[i]
        for other, other_weight in terms[:i]:
            answer += 2 * weight * other_weight * avoid_count(kernel, footprint | other)
    if answer < 0:
        fail(("negative square", answer))
    return answer


def word(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=False)


def read_word(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little", signed=False)


def encode(kernel: dict, scope: dict, mask: int, logical) -> bytes:
    records = []
    for address in range(scope["lo"], scope["hi"]):
        is_present = present(kernel, scope["tensor"], address, mask)
        value = logical[address] if is_present else 0
        if scope["format"] == "dense":
            records.append(word(value))
        elif is_present and scope["format"] == "bitmap":
            records.append(word(value))
        elif is_present and scope["format"] == "coordinate":
            records.append(word(address) + word(value))
    if scope["format"] == "coordinate":
        return word(scope["lo"]) + word(len(records)) + b"".join(records)
    return b"".join(records)


def decode(kernel: dict, scope: dict, mask: int, data: bytes) -> dict[int, int]:
    offset = 0
    expected_records = None
    if scope["format"] == "coordinate":
        if len(data) < 8 or read_word(data, 0) != scope["lo"]:
            fail("bad coordinate header")
        expected_records = read_word(data, 4)
        offset = 8
    answer: dict[int, int] = {}
    observed_records = 0
    for address in range(scope["lo"], scope["hi"]):
        is_present = present(kernel, scope["tensor"], address, mask)
        if scope["format"] == "dense" or is_present:
            if scope["format"] == "coordinate":
                if read_word(data, offset) != address:
                    fail("bad coordinate address")
                value = read_word(data, offset + 4)
                offset += 8
            else:
                value = read_word(data, offset)
                offset += 4
            observed_records += 1
            answer[address] = value
        else:
            answer[address] = 0
    if offset != len(data) or (expected_records is not None and expected_records != observed_records):
        fail("packet length mismatch")
    return answer


def direct_execute(kernel: dict, mapping: dict, mask: int, values: list[list[int]]) -> list[int]:
    outputs = [0] * kernel["outputs"]
    for event_id in mapping["order"]:
        event = kernel["events"][event_id]
        if event["guard"] >= 0 and not ((mask >> event["guard"]) & 1):
            continue
        product = 1
        for tensor, address in event["reads"]:
            product = (product * values[tensor][address]) % MOD
        outputs[event["output"]] = (outputs[event["output"]] + product) % MOD
    return outputs


def resident_execute(pair: dict, which: str, mask: int, values: list[list[int]]) -> tuple[list[int], list[int]]:
    kernel = pair["kernel"]
    mapping = pair[which]
    loaded: dict[int, dict[int, int]] = {}
    outputs = [0] * kernel["outputs"]
    costs = [(kernel["guards"] + 7) // 8 + 4 * kernel["outputs"]]
    costs.extend(0 for _ in pair["architecture"]["capacity"][1:])
    for position, event_id in enumerate(mapping["order"]):
        event = kernel["events"][event_id]
        if event["guard"] >= 0 and not ((mask >> event["guard"]) & 1):
            continue
        product = 1
        for (tensor, address), leaf in zip(event["reads"], mapping["bindings"][event_id]):
            chain = []
            scope_id = leaf
            while scope_id >= 0:
                chain.append(scope_id)
                scope_id = mapping["scopes"][scope_id]["parent"]
            for scope_id in reversed(chain):
                scope = mapping["scopes"][scope_id]
                if not (scope["begin"] <= position < scope["end"]):
                    fail("resident lifetime mismatch")
                if scope_id not in loaded:
                    parent = scope["parent"]
                    logical = values[tensor] if parent < 0 else loaded[parent]
                    raw = encode(kernel, scope, mask, logical)
                    if len(raw) != packet_bytes(kernel, scope, mask):
                        fail("independent codec size mismatch")
                    loaded[scope_id] = decode(kernel, scope, mask, raw)
                    costs[scope["level"]] += len(raw)
            product = (product * loaded[leaf][address]) % MOD
        outputs[event["output"]] = (outputs[event["output"]] + product) % MOD
    return outputs, costs


def check_campaign() -> dict:
    total_pairs = total_masks = total_numeric = total_levels = 0
    for part in CAMPAIGN:
        inputs = load_jsonl(INPUTS / f"{part}.jsonl")
        result = load_json(RESULTS / f"{part}.json")
        if len(inputs) != len(result["rows"]):
            fail((part, "input/result rows"))
        part_masks = part_numeric = 0
        for input_row, frozen in zip(inputs, result["rows"]):
            if input_row["case"] != frozen["case"]:
                fail((part, "case order"))
            pair = input_row["pair"]
            admit_pair(pair)
            kernel = pair["kernel"]
            masks = list(legal_masks(kernel))
            levels = len(pair["architecture"]["capacity"])
            independent_differences = [difference(pair, level) for level in range(levels)]
            observed = [[] for _ in range(levels)]
            values = [
                [((address * 2654435761 + tensor * 17 + 11) & 0xFFFFFFFF) for address in range(spec["length"])]
                for tensor, spec in enumerate(kernel["tensors"])
            ]
            numeric_limit = len(masks) if len(masks) <= 16 else min(8, len(masks))
            for index, mask in enumerate(masks):
                source = direct_traffic(pair, "source", mask)
                target = direct_traffic(pair, "target", mask)
                for level, (constant, terms) in enumerate(independent_differences):
                    delta = target[level] - source[level]
                    if evaluate(constant, terms, mask) != delta:
                        fail((part, frozen["case"], level, mask, "signature"))
                    observed[level].append(delta)
                if index < numeric_limit:
                    canonical = direct_execute(kernel, pair["source"], mask, values)
                    target_plain = direct_execute(kernel, pair["target"], mask, values)
                    source_out, source_cost = resident_execute(pair, "source", mask, values)
                    target_out, target_cost = resident_execute(pair, "target", mask, values)
                    if not (canonical == target_plain == source_out == target_out):
                        fail((part, frozen["case"], mask, "numeric output"))
                    if source_cost != source or target_cost != target:
                        fail((part, frozen["case"], mask, "numeric traffic"))
                    part_numeric += 1
            if len(masks) != frozen["enumerated_masks"]:
                fail((part, frozen["case"], "mask count"))
            if numeric_limit != frozen["resident_numeric_masks"]:
                fail((part, frozen["case"], "numeric count"))
            for level, values_by_mask in enumerate(observed):
                constant, terms = independent_differences[level]
                frozen_level = frozen["level_results"][level]
                square = sum(value * value for value in values_by_mask)
                if square != square_sum(kernel, constant, terms):
                    fail((part, frozen["case"], level, "square identity"))
                expected = {
                    "square_sum": square,
                    "min_delta": min(values_by_mask),
                    "max_delta": max(values_by_mask),
                    "positive_masks": sum(value > 0 for value in values_by_mask),
                    "negative_masks": sum(value < 0 for value in values_by_mask),
                    "terms": len(terms),
                }
                for key, value in expected.items():
                    if frozen_level[key] != value:
                        fail((part, frozen["case"], level, key, frozen_level[key], value))
                witness = frozen_level["attaining_mask"]
                if not support_ok(kernel, witness) or evaluate(constant, terms, witness) != max(values_by_mask):
                    fail((part, frozen["case"], level, "attaining mask"))
                total_levels += 1
            part_masks += len(masks)
        if result["case_count"] != len(inputs) or result["mask_count"] != part_masks or result["resident_numeric_masks"] != part_numeric:
            fail((part, "aggregate mismatch"))
        total_pairs += len(inputs)
        total_masks += part_masks
        total_numeric += part_numeric
    return {
        "campaign_pairs": total_pairs,
        "campaign_masks": total_masks,
        "campaign_levels": total_levels,
        "resident_codec_masks": total_numeric,
    }


def event(guard: int, address: int) -> dict:
    return {"guard": guard, "output": 0, "reads": [[0, address], [1, 0]]}


def make_mapping(kernel: dict, order: list[int], a_groups: list[list[int]], b_groups: list[list[int]]) -> dict:
    positions = {event_id: position for position, event_id in enumerate(order)}
    scopes = []
    bindings = [[-1, -1] for _ in kernel["events"]]
    for operand, groups in enumerate((a_groups, b_groups)):
        for group in groups:
            accesses = [kernel["events"][event_id]["reads"][operand] for event_id in group]
            tensor = accesses[0][0]
            lo = min(address for _, address in accesses)
            hi = max(address for _, address in accesses) + 1
            scope_id = len(scopes)
            scopes.append({
                "tensor": tensor, "lo": lo, "hi": hi, "level": 0,
                "begin": min(positions[event_id] for event_id in group),
                "end": max(positions[event_id] for event_id in group) + 1,
                "parent": -1, "format": "dense",
            })
            for event_id in group:
                bindings[event_id][operand] = scope_id
    return {"order": order, "scopes": scopes, "bindings": bindings}


def threshold_pair(vertices: int, edges: list[tuple[int, int]], threshold: int, promise: str) -> dict:
    structured = promise == "nm"
    guards = 4 * vertices if structured else vertices
    representative = [4 * vertex if structured else vertex for vertex in range(vertices)]
    events = []
    source_groups: list[list[int]] = []
    target_groups: list[list[int]] = []
    for left_vertex, right_vertex in edges:
        left = representative[left_vertex]
        right = representative[right_vertex]
        base = len(events)
        events.extend((event(left, left), event(left, left), event(right, right), event(right, right)))
        source_groups.extend(([base, base + 1], [base + 2, base + 3]))
        target_groups.extend(([base, base + 2], [base + 1, base + 3]))
    always_address = guards
    for _ in range(threshold - 1):
        base = len(events)
        events.extend((event(-1, always_address), event(-1, always_address)))
        source_groups.extend(([base], [base + 1]))
        target_groups.append([base, base + 1])
    if structured:
        for guard in range(guards):
            if guard % 4:
                event_id = len(events)
                events.append(event(guard, guard))
                source_groups.append([event_id])
                target_groups.append([event_id])
    used = {row["guard"] for row in events if row["guard"] >= 0}
    for guard in range(guards):
        if guard not in used:
            event_id = len(events)
            events.append(event(guard, guard))
            source_groups.append([event_id])
            target_groups.append([event_id])
    blocks = (
        [{"ids": list(range(start, start + 4)), "count": 2} for start in range(0, guards, 4)]
        if structured else [{"ids": list(range(guards)), "count": None}]
    )
    kernel = {
        "guards": guards,
        "blocks": blocks,
        "tensors": [
            {"length": guards + 1, "bytes": 4, "support": list(range(guards)) + [-1]},
            {"length": 1, "bytes": 4, "support": None},
        ],
        "outputs": 1,
        "events": events,
        "arithmetic": "mod32",
    }
    a_groups = [[event_id] for event_id in range(len(events))]
    source_order = [event_id for group in source_groups for event_id in group]
    target_order = [event_id for group in target_groups for event_id in group]
    return {
        "kernel": kernel,
        "architecture": {"capacity": [8], "control_capacity": (guards + 7) // 8 + 4},
        "source": make_mapping(kernel, source_order, a_groups, source_groups),
        "target": make_mapping(kernel, target_order, a_groups, target_groups),
    }


def check_reduction() -> dict:
    descriptors = load_jsonl(INPUTS / "reduction.jsonl")
    frozen = load_json(RESULTS / "reduction.json")
    pairs = masks_checked = true_cases = false_cases = 0
    max_events = 0
    for descriptor in descriptors:
        vertices = descriptor["vertices"]
        possible = list(itertools.combinations(range(vertices), 2))
        edges = [edge for index, edge in enumerate(possible) if (descriptor["graph_code"] >> index) & 1]
        threshold = descriptor["threshold"]
        promise = descriptor["promise"]
        pair = threshold_pair(vertices, edges, threshold, promise)
        admit_pair(pair)
        constant, terms = difference(pair, 0)
        deltas = []
        for mask in legal_masks(pair["kernel"]):
            selected = [
                (mask >> (4 * vertex if promise == "nm" else vertex)) & 1
                for vertex in range(vertices)
            ]
            cut = sum(selected[left] ^ selected[right] for left, right in edges)
            expected = 4 * (cut - (threshold - 1))
            literal = direct_traffic(pair, "target", mask)[0] - direct_traffic(pair, "source", mask)[0]
            if literal != expected or evaluate(constant, terms, mask) != expected:
                fail((descriptor, mask, literal, evaluate(constant, terms, mask), expected))
            deltas.append(literal)
        maxcut = max(
            sum(((assignment >> left) ^ (assignment >> right)) & 1 for left, right in edges)
            for assignment in range(1 << vertices)
        )
        universal = max(deltas) <= 0
        if universal != (maxcut < threshold):
            fail((descriptor, "universal"))
        true_cases += int(universal)
        false_cases += int(not universal)
        pairs += 1
        masks_checked += len(deltas)
        max_events = max(max_events, len(pair["kernel"]["events"]))
    expected = (frozen["pair_count"], frozen["mask_count"], frozen["zero_bound_true"], frozen["zero_bound_false"], frozen["max_events"])
    observed = (pairs, masks_checked, true_cases, false_cases, max_events)
    if observed != expected or frozen["capacity_bytes"] != 8:
        fail(("reduction aggregate", observed, expected))
    return {
        "reduction_pairs": pairs,
        "reduction_masks": masks_checked,
        "zero_bound_true": true_cases,
        "zero_bound_false": false_cases,
        "max_reduction_events": max_events,
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


def run() -> dict:
    begin_wall = time.monotonic()
    begin_cpu = time.process_time()
    admission = check_admission_mutations()
    campaign = check_campaign()
    reduction = check_reduction()
    use = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "status": "passed",
        "implementation_imports": [],
        **admission,
        **campaign,
        **reduction,
        "cpu_seconds": time.process_time() - begin_cpu,
        "wall_seconds": time.monotonic() - begin_wall,
        "peak_rss_kib": use.ru_maxrss,
        "swap_events": use.ru_nswap,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run()
    if args.output is not None:
        publish(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
