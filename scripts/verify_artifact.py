#!/usr/bin/env python3
"""Audit the frozen standalone artifact without rerunning scientific kernels.

The audit parses every machine-readable file, reconciles frozen inputs/results,
rebuilds derived tables in memory, checks evidence/reference ledgers, and enforces
source-hygiene and standard-library-only boundaries.  It never edits the
repository and uses no network access.
"""
from __future__ import annotations

import ast
import csv
import io
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
INPUTS = ROOT / "inputs"
CAMPAIGN = [
    "structured", "grid", "cycle", "format", "graph-free", "graph-nm",
    "random-0", "random-1", "random-2",
]
SCALING = ["equal-small", "equal-large", "orders", "cliques"]
SPECIAL = ["reduction", "certificates"]
SCIENTIFIC = CAMPAIGN + SCALING + SPECIAL
TIMING = {
    "cpu_seconds", "wall_seconds", "peak_rss_kib",
    "producer_cpu_seconds", "producer_wall_seconds",
    "checker_cpu_seconds", "checker_wall_seconds",
    "child_cpu_seconds",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{path}:{line_no}: {exc}") from exc
    return rows


def scientific(value):
    if isinstance(value, dict):
        return {key: scientific(item) for key, item in value.items() if key not in TIMING}
    if isinstance(value, list):
        return [scientific(item) for item in value]
    return value


def csv_bytes(fieldnames: list[str], rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def audit_derived_csvs() -> None:
    summary = [
        {key: value for key, value in load_json(RESULTS / f"{part}.json").items() if key != "rows"}
        for part in CAMPAIGN
    ]
    require(csv_bytes(list(summary[0]), summary) == (RESULTS / "summary.csv").read_bytes(),
            "summary.csv is stale")

    equality_rows: list[dict] = []
    for part in ["equal-small", "equal-large"]:
        equality_rows.extend(load_json(RESULTS / f"{part}.json")["rows"])
    aggregate = []
    for groups in sorted({row["groups"] for row in equality_rows}):
        selected = [row for row in equality_rows if row["groups"] == groups]
        first = selected[0]
        aggregate.append({
            "groups": groups,
            "guards": first["guards"],
            "terms": first["terms"],
            "legal_masks": first["legal_masks"],
            "status": first["status"],
            "median_seconds": statistics.median(row["wall_seconds"] for row in selected),
            "min_seconds": min(row["wall_seconds"] for row in selected),
            "max_seconds": max(row["wall_seconds"] for row in selected),
            "count_operation_charge": first["count_operation_charge"],
        })
    require(csv_bytes(list(aggregate[0]), aggregate) == (RESULTS / "equality.csv").read_bytes(),
            "equality.csv is stale")
    plotted = [row for row in aggregate if row["status"] == "equal"]
    require(csv_bytes(list(plotted[0]), plotted) == (RESULTS / "equality-plot.csv").read_bytes(),
            "equality-plot.csv is stale or includes an unresolved preflight")

    for part in ["orders", "cliques"]:
        source = load_json(RESULTS / f"{part}.json")["rows"]
        keys = list(dict.fromkeys(key for row in source for key in row if key != "guard_order"))
        rendered = [{key: row.get(key, "") for key in keys} for row in source]
        require(csv_bytes(keys, rendered) == (RESULTS / f"{part}.csv").read_bytes(),
                f"{part}.csv is stale")

    reduction = load_json(RESULTS / "reduction.json")["rows"]
    require(csv_bytes(list(reduction[0]), reduction) == (RESULTS / "reduction.csv").read_bytes(),
            "reduction.csv is stale")

    certificates = load_json(RESULTS / "certificates.json")["rows"]
    require(csv_bytes(list(certificates[0]), certificates) == (RESULTS / "certificates.csv").read_bytes(),
            "certificates.csv is stale")


def audit_ledgers() -> None:
    resources = read_csv(ROOT / "external_resources.csv")
    require(len(resources) == 78, "external_resources.csv must contain 78 unique scholarly records")
    resource_ids = [row["resource_id"] for row in resources]
    require(len(resource_ids) == len(set(resource_ids)), "duplicate external resource id")
    require(all(row["title"].strip() and row["authors_or_owner"].strip() for row in resources),
            "blank reference title/author metadata")
    require(all(row["year"].isdigit() and 1970 <= int(row["year"]) <= 2026 for row in resources),
            "invalid reference year")
    urls = [row["scholarly_or_official_url"].strip() for row in resources]
    require(len(urls) == len({url.casefold() for url in urls}), "duplicate scholarly identifier/URL")
    require(all(url.startswith("https://") for url in urls), "missing HTTPS resource URL")
    require(sum(url.startswith("https://doi.org/10.") for url in urls) == 76,
            "expected 76 DOI records")
    require(sum("usenix.org/conference/" in url for url in urls) == 2,
            "expected two official USENIX records")
    require(all(row["access_date"] in {"2026-09-19", "2026-09-21"} for row in resources),
            "unexpected resource access date")
    require(all(row["redistributed"] == "no" for row in resources),
            "a source is unexpectedly marked redistributed")

    verified = read_csv(ROOT / "reference_verification.csv")
    require(len(verified) == 78 and {row["resource_id"] for row in verified} == set(resource_ids),
            "reference verification/resource inventory mismatch")
    by_id = {row["resource_id"]: row for row in resources}
    require(all(row["metadata_source"] == by_id[row["resource_id"]]["scholarly_or_official_url"]
                for row in verified), "verification source/inventory URL mismatch")
    manuscript_ids = {row["resource_id"] for row in verified if row["bibliography_role"] == "manuscript-cited"}
    calibration_ids = {row["resource_id"] for row in verified if row["bibliography_role"] == "calibration-only"}
    require(len(manuscript_ids) == 73 and len(calibration_ids) == 5 and not manuscript_ids & calibration_ids,
            "expected 73 manuscript references and five calibration-only records")
    require(sum(row["substantive_scope_checked"].startswith("full paper") for row in verified) == 23,
            "expected 23 full-paper calibration records")
    allowed_status = {
        "official-record-checked",
        "doi-and-official-record-checked",
        "doi-and-institutional-record-checked",
        "doi-and-author-artifact-record-checked",
    }
    require(all(row["metadata_status"] in allowed_status for row in verified),
            "unrecognized metadata verification status")
    require(all(row["identifier"].strip() for row in verified), "blank verified identifier")
    require(len({row["identifier"].casefold() for row in verified}) == 78,
            "duplicate verified identifier")
    require(all(row["checked_date"] in {"2026-09-19", "2026-09-21"} for row in verified),
            "unexpected reference check date")

    contexts = read_csv(ROOT / "reference_context_audit.csv")
    require(len(contexts) == 73, "reference context audit must cover every manuscript reference")
    require({row["resource_id"] for row in contexts} == manuscript_ids,
            "reference context audit and manuscript bibliography differ")
    require(len({row["resource_id"] for row in contexts}) == len(contexts),
            "duplicate reference context row")
    require(all(row["citation_lines"].strip() and row["citation_context"].strip() for row in contexts),
            "blank citation-context evidence")
    require(all(row["scope_match"].startswith("checked:") for row in contexts),
            "unreviewed citation-context scope")
    require(all(row["checked_date"] == "2026-09-21" for row in contexts),
            "reference context audit is stale")

    claims = read_csv(ROOT / "claim_evidence_ledger.csv")
    require(len(claims) == 17 and len({row["claim_id"] for row in claims}) == 17,
            "claim ledger must contain 17 unique material claims")
    require({row["claim_id"] for row in claims} == {f"C{index}" for index in range(1, 18)},
            "claim ledger identifiers are incomplete")
    require(all(row["fresh_recheck"] == "2026-09-25" for row in claims),
            "claim ledger recheck dates are stale")
    require(all(all(row[field].strip() for field in row) for row in claims),
            "claim ledger contains a blank field")


def audit_python_sources() -> None:
    """Parse every Python source and enforce the executable boundary."""
    local_roots = {"dataflow"}
    forbidden_modules = {
        "socket", "urllib", "http", "ftplib", "telnetlib", "requests",
        "aiohttp", "paramiko", "torch", "tensorflow", "jax", "numpy",
    }
    forbidden_calls = {"eval", "exec", "compile", "__import__"}
    for path in sorted(ROOT.rglob("*.py")):
        relative = path.relative_to(ROOT)
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(relative))
        except SyntaxError as exc:
            raise RuntimeError(f"invalid Python source {relative}: {exc}") from exc
        if relative.parts[0] in {"src", "scripts"}:
            require(not any(isinstance(node, ast.Assert) for node in ast.walk(tree)),
                    f"optimization-sensitive assert statement in executable source: {relative}")
        production_imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [] if node.level else [((node.module or "").split(".", 1)[0])]
            else:
                modules = []
            for module in modules:
                require(module in sys.stdlib_module_names or module in local_roots,
                        f"non-standard dependency {module!r} in {relative}")
                require(module not in forbidden_modules,
                        f"network/model/third-party import {module!r} in {relative}")
                if module in local_roots:
                    production_imports.append(module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                require(node.func.id not in forbidden_calls,
                        f"dynamic execution call {node.func.id!r} in {relative}")
        if relative == Path("scripts/standalone_oracle.py"):
            require(not production_imports,
                    "standalone oracle imports the production dataflow package")
    test_tree = ast.parse((ROOT / "tests" / "test_contract.py").read_text(encoding="utf-8"))
    test_methods = sum(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
        for node in ast.walk(test_tree)
    )
    require(test_methods == 27, "expected 27 distinct unit-test methods")


def audit_content_hygiene() -> None:
    forbidden = [
        "/mnt" + "/data/", "/home" + "/oai/", "sandbox" + ":/",
        "anonymous.4open" + ".science", "github.com/" + "anonymous",
        "TO" + "DO", "T" + "BD",
    ]
    text_suffixes = {".py", ".md", ".csv", ".json", ".jsonl", ".txt"}
    archive_suffixes = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z"}
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        require(path.name != "__pycache__", f"Python bytecode cache in artifact: {relative}")
        if path.is_file():
            require(path.suffix not in {".pyc", ".pyo"}, f"Python bytecode in artifact: {relative}")
            require(path.suffix not in archive_suffixes, f"nested archive in artifact: {relative}")
        if not path.is_file() or path.suffix not in text_suffixes:
            continue
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            require(token not in text, f"forbidden private/placeholder token {token!r} in {relative}")


def audit_campaign() -> tuple[int, int, int]:
    cases = masks = numeric = 0
    for part in CAMPAIGN:
        result = load_json(RESULTS / f"{part}.json")
        inputs = jsonl(INPUTS / f"{part}.jsonl")
        require(result["part"] == part, f"{part}: wrong part label")
        require(result["case_count"] == len(result["rows"]) == len(inputs),
                f"{part}: case/input count mismatch")
        require(result["mask_count"] == sum(row["enumerated_masks"] for row in result["rows"]),
                f"{part}: mask total mismatch")
        require(result["resident_numeric_masks"] == sum(row["resident_numeric_masks"] for row in result["rows"]),
                f"{part}: numeric total mismatch")
        require(all(row["result"] == "passed" for row in result["rows"]),
                f"{part}: non-passing case")
        require(result["swap_events"] == 0 and result["workers"] == 1,
                f"{part}: resource contract mismatch")
        cases += result["case_count"]
        masks += result["mask_count"]
        numeric += result["resident_numeric_masks"]
    require((cases, masks, numeric) == (1730, 256074, 13997),
            "main campaign headline totals changed")
    return cases, masks, numeric


def audit_validation_results() -> None:
    adversarial = load_json(RESULTS / "adversarial-crosscheck.json")
    require(adversarial == {
        "counter_random_cases": 350,
        "frontier_exact_checks": 58,
        "literal_signature_mask_checks": 1074,
        "mapping_random_cases": 90,
        "reduction_mask_checks": 16720,
        "reduction_random_cases": 80,
        "resident_codec_checks": 566,
        "seed": 20260919,
        "status": "passed",
    }, "adversarial crosscheck result changed")

    standalone = scientific(load_json(RESULTS / "standalone-oracle.json"))
    require(standalone == {
        "admission_mutation_names": [
            "payload-capacity-48-to-47",
            "control-capacity-9-to-8",
            "event-order-permutation",
            "parent-relation",
            "guard-operand",
            "binding-operand",
            "strict-integer-type",
        ],
        "admission_mutations_rejected": 7,
        "campaign_levels": 1817,
        "campaign_masks": 256074,
        "campaign_pairs": 1730,
        "implementation_imports": [],
        "max_reduction_events": 34,
        "reduction_masks": 5800,
        "reduction_pairs": 218,
        "resident_codec_masks": 13997,
        "status": "passed",
        "structured_source_peak_payload": [48],
        "structured_target_peak_payload": [48],
        "swap_events": 0,
        "zero_bound_false": 192,
        "zero_bound_true": 26,
    }, "standalone oracle result changed")

    stress = scientific(load_json(RESULTS / "reviewer-stress.json"))
    require(stress == {
        "cases": 144,
        "exact_square_checks": 192,
        "guard_renaming_checks": 3219,
        "level_mask_checks": 3219,
        "mask_checks": 2562,
        "maximum_certificate_states": 86,
        "maximum_legal_masks_per_case": 256,
        "maximum_signature_terms": 68,
        "proof_cases": 72,
        "seed": 20260921,
        "self_equality_checks": 192,
        "sign_classes": {"equal": 23, "mixed": 52, "negative_only": 56, "positive_only": 61},
        "source_target_swap_checks": 3219,
        "status": "passed",
        "swap_events": 0,
        "upper_certificate_checks": 96,
    }, "reviewer stress result changed")


def audit_reduction_and_scaling() -> None:
    reduction = load_json(RESULTS / "reduction.json")
    reduction_inputs = jsonl(INPUTS / "reduction.jsonl")
    require((reduction["pair_count"], reduction["mask_count"], reduction["max_events"], reduction["capacity_bytes"])
            == (218, 5800, 34, 8), "reduction headline totals changed")
    require((reduction["zero_bound_true"], reduction["zero_bound_false"]) == (26, 192),
            "reduction decision-class totals changed")
    require(len(reduction_inputs) == 218, "reduction input count mismatch")
    require(sum(row["pair_count"] for row in reduction["rows"]) == 218,
            "reduction row pair total mismatch")
    require(sum(row["mask_count"] for row in reduction["rows"]) == 5800,
            "reduction row mask total mismatch")

    equal_large = load_json(RESULTS / "equal-large.json")["rows"]
    row128 = [row for row in equal_large if row["groups"] == 128]
    row256 = [row for row in equal_large if row["groups"] == 256]
    require(len(row128) == 3 and all(row["status"] == "equal" and row["square_sum"] == 0 for row in row128),
            "128-group equality control changed")
    require(len(row256) == 1 and row256[0]["status"] == "unresolved"
            and row256[0]["count_operation_charge"] == 211028097,
            "256-group unresolved control changed")

    orders = load_json(RESULTS / "orders.json")["rows"]
    require(any(row["status"] == "unresolved" for row in orders)
            and any(row["status"] == "certified" for row in orders),
            "ordering controls lost a status class")

    certificates = load_json(RESULTS / "certificates.json")
    require(certificates["part"] == "certificates" and certificates["case_count"] == 9,
            "certificate benchmark coverage changed")
    require(certificates["workers"] == 1 and certificates["swap_events"] == 0,
            "certificate benchmark resource contract changed")
    by_case = {row["case"]: row for row in certificates["rows"]}
    require(by_case["structured-8-grouped"]["total_states"] == 65
            and by_case["structured-8-grouped"]["certificate_bytes"] == 1052,
            "grouped certificate anchor changed")
    require(by_case["structured-8-interleaved"]["total_states"] == 32291
            and by_case["structured-8-interleaved"]["certificate_bytes"] == 924932,
            "interleaved certificate anchor changed")
    require(max(row["certificate_bytes"] for row in certificates["rows"]) == 924932,
            "maximum retained certificate size changed")
    require((ROOT / "examples" / "structured-zero-bound-certificate.json").is_file(),
            "shipped certificate example is missing")
    load_json(ROOT / "examples" / "structured-zero-bound-certificate.json")


def audit_reproduction() -> None:
    reproduction = load_json(RESULTS / "reproduction-validation.json")
    require(reproduction["status"] == "passed", "recorded clean reproduction did not pass")
    require(reproduction.get("checks") == [
        {"check": "artifact-audit", "status": "passed"},
        {"check": "unit-tests", "status": "passed"},
        {"check": "optimized-unit-tests", "status": "passed"},
    ], "recorded audit/test coverage changed")
    require([row["part"] for row in reproduction["parts"]] == SCIENTIFIC,
            "clean reproduction part order/coverage changed")
    require(all(row["scientific_fields_match"] and row["swap_events"] == 0
                for row in reproduction["parts"]), "clean reproduction mismatch/swap")
    validation = reproduction.get("validation", {})
    expected_validation = {
        "standalone_oracle": load_json(RESULTS / "standalone-oracle.json"),
        "adversarial_crosscheck": load_json(RESULTS / "adversarial-crosscheck.json"),
        "reviewer_stress": load_json(RESULTS / "reviewer-stress.json"),
    }
    require(set(validation) == set(expected_validation),
            "recorded reproduction validation-path coverage changed")
    for key, expected in expected_validation.items():
        observed = dict(validation[key])
        require(observed.pop("scientific_fields_match", False) is True,
                f"{key}: recorded scientific comparison did not pass")
        require(scientific(observed) == scientific(expected),
                f"{key}: recorded reproduction fields differ")


def main() -> int:
    for path in sorted(ROOT.rglob("*.json")):
        load_json(path)
    for path in sorted(ROOT.rglob("*.jsonl")):
        jsonl(path)

    cases, masks, numeric = audit_campaign()
    audit_reduction_and_scaling()
    audit_validation_results()
    audit_derived_csvs()
    audit_ledgers()
    audit_python_sources()
    audit_content_hygiene()
    audit_reproduction()

    report = {
        "status": "passed",
        "scientific_parts": len(SCIENTIFIC),
        "validation_paths": 3,
        "main_pairs": cases,
        "main_masks": masks,
        "numeric_codec_masks": numeric,
        "reduction_pairs": 218,
        "reduction_masks": 5800,
        "post_freeze_cases": 144,
        "manuscript_references": 73,
        "external_records": 78,
        "material_claims": 17,
        "test_methods": 27,
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
