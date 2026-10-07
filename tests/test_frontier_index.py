"""Portable, untimed finite checker regression. Run with Python from any cwd.

Only standard-library pure finite checks: no CLI, subprocess, result writes,
campaigns, external targets, or timing measurements. The adjacent reference
enumerates complete legal masks and groups prefixes, not checker transitions.
"""
import copy
import itertools
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from frontier_reference import prefix_profile
from dataflow import generate as G
from dataflow.checker import check_equal, check_upper
from dataflow.literal import traffic
from dataflow.model import Invalid, difference
from dataflow.moment import AnalysisLimit, Budget, Counter
from dataflow.producer import prove_upper

COUNTS = {}


def bump(name, count=1):
    COUNTS[name] = COUNTS.get(name, 0) + count


def fixtures():
    cases = [("grid-free", G.grid(2)), ("structured-nm", G.structured(2)),
             ("structured-free", G.structured(1, "free")),
             ("packed-overfetch", G.format_change(4, "bitmap", "coordinate", 2, "nm")),
             ("hierarchy", G.hierarchy(G.structured(1, fmt="coordinate"), "bitmap")),
             ("cycle", G.cycle(5)),
             ("cut-nm", G.cut_graph(3, [(0, 1), (0, 2), (1, 2)], "nm")),
             ("offset", G.cut_threshold(3, [(0, 1), (1, 2)], 2))]
    for count in range(5):
        p = G.grid(2)
        p["kernel"]["blocks"] = [{"ids": [3, 1, 0, 2], "count": count}]
        cases.append((f"global-{count}", p))
    p = G.structured(2)
    p["kernel"]["blocks"] = [{"ids": [0], "count": 0}, {"ids": [1], "count": 1},
                              {"ids": [6, 2, 4], "count": 1}, {"ids": [7, 3, 5], "count": None}]
    cases.append(("mixed", p))
    p = G.structured(2)
    p["kernel"]["blocks"] = [{"ids": [7, 1, 5], "count": 2}, {"ids": [4, 0], "count": None},
                              {"ids": [6], "count": 1}, {"ids": [3, 2], "count": 0}]
    cases.append(("permuted-blocks", p))
    p = G.grid(2)
    p["kernel"]["blocks"] = [{"ids": [3], "count": 1}, {"ids": [1], "count": 0},
                              {"ids": [2], "count": None}, {"ids": [0], "count": 1}]
    cases.append(("singletons", p))
    p = G.structured(2)
    p["target"] = copy.deepcopy(p["source"])
    cases.append(("no-terms", p))
    # Swapping mappings changes the sign, not the declared support domain.
    for name, original in list(cases):
        p = copy.deepcopy(original)
        p["source"], p["target"] = p["target"], p["source"]
        cases.append((name + "-reverse", p))
    return cases


def orders(n):
    candidates = [list(range(n)), list(reversed(range(n))),
                  [v for lane in range(4) for v in range(lane, n, 4)],
                  list(range(0, n, 2)) + list(range(1, n, 2))]
    return [row for i, row in enumerate(candidates) if row not in candidates[:i]]


def reference_certificate(pair, order, level=0):
    c, terms = difference(pair, level)
    p = prefix_profile(pair["kernel"]["guards"], pair["kernel"]["blocks"], order, c, terms)
    cert = {"kind": "upper", "level": level, "order": order, "bound": p["bound"],
            "witness": p["witness"], "layers": p["layers"], "statistics": None}
    return cert, p


def certificate_mutations():
    pair = G.structured(2)
    original, _ = reference_certificate(pair, [0, 4, 1, 5, 2, 6, 3, 7])
    B = original["bound"]
    changes = [
        ("initial", lambda c: c["layers"][0][0].__setitem__(2, -1)),
        ("missing-successor", lambda c: c["layers"][2].pop()),
        ("duplicate", lambda c: c["layers"][2].append(copy.deepcopy(c["layers"][2][0]))),
        ("occupancy-range", lambda c: c["layers"][0][0].__setitem__(0, 1)),
        ("occupancy-bool", lambda c: c["layers"][0][0].__setitem__(0, False)),
        ("count-arity", lambda c: c["layers"][2][0].__setitem__(1, [])),
        ("count-type", lambda c: c["layers"][2][0].__setitem__(1, (0, 0))),
        # At layer two the next guard belongs to block zero, not block one.
        ("unaffected-counter-range", lambda c: c["layers"][2][0][1].__setitem__(1, 3)),
        ("unaffected-counter-bool", lambda c: c["layers"][2][0][1].__setitem__(1, False)),
        ("count-negative", lambda c: c["layers"][2][0][1].__setitem__(0, -1)),
        ("row-shape", lambda c: c["layers"][2][0].append(0)),
        ("row-type", lambda c: c["layers"][2].__setitem__(0, {})),
        ("layer-type", lambda c: c["layers"].__setitem__(2, {})),
        ("empty-layer", lambda c: c["layers"].__setitem__(2, [])),
        ("potential-bool", lambda c: c["layers"][2][0].__setitem__(2, False)),
        ("potential-upper-range", lambda c: c["layers"][0][0].__setitem__(2, 2**63)),
        ("potential-lower-range", lambda c: c["layers"][0][0].__setitem__(2, -2**63 - 1)),
        ("order-duplicate", lambda c: c["order"].__setitem__(0, 4)),
        ("order-bool", lambda c: c["order"].__setitem__(0, False)),
        ("order-type", lambda c: c.__setitem__("order", tuple(c["order"]))),
        ("level", lambda c: c.__setitem__("level", True)),
        ("bound-mismatch", lambda c: c.__setitem__("bound", B + 1)),
        ("bound-bool", lambda c: c.__setitem__("bound", False)),
        ("kind", lambda c: c.__setitem__("kind", "equal")),
        ("omit-layer", lambda c: c["layers"].pop()),
        ("extra-field", lambda c: c.__setitem__("trusted", True)),
        ("terminal-potential", lambda c: c["layers"][-1][0].__setitem__(2, -1)),
        ("illegal-witness", lambda c: c.__setitem__("witness", 0)),
        ("witness-bool", lambda c: c.__setitem__("witness", True)),
        ("witness-range", lambda c: c.__setitem__("witness", 1 << 8)),
    ]
    for name, change in changes:
        cert = copy.deepcopy(original)
        change(cert)
        yield name, pair, cert, 0, B, {}
    for name, bound in [("bound-upper-range", 2**63), ("bound-lower-range", -2**63 - 1)]:
        yield name, pair, original, 0, bound, {}
    # A free-domain zero mask is legal but does not attain the positive bound.
    p = G.grid(2)
    cert, _ = reference_certificate(p, list(range(4)))
    cert["witness"] = 0
    yield "nonattaining-witness", p, cert, 0, cert["bound"], {}
    cert = copy.deepcopy(original)
    cert["bound"] = B - 1
    cert["witness"] = None
    yield "terminal-bound", pair, cert, 0, B - 1, {}


def admission_mutations():
    changes = [
        ("overlap", lambda p: p["kernel"]["blocks"][1]["ids"].__setitem__(0, 0)),
        ("repeated-id", lambda p: p["kernel"]["blocks"][0]["ids"].append(0)),
        ("missing-id", lambda p: p["kernel"]["blocks"][0]["ids"].pop()),
        ("empty-block", lambda p: p["kernel"]["blocks"][0].__setitem__("ids", [])),
        ("boolean-id", lambda p: p["kernel"]["blocks"][0]["ids"].__setitem__(0, False)),
        ("negative-count", lambda p: p["kernel"]["blocks"][0].__setitem__("count", -1)),
        ("overfull-count", lambda p: p["kernel"]["blocks"][0].__setitem__("count", 5)),
        ("boolean-count", lambda p: p["kernel"]["blocks"][0].__setitem__("count", True)),
        ("float-count", lambda p: p["kernel"]["blocks"][0].__setitem__("count", 2.0)),
        ("wrong-capacity", lambda p: p["architecture"]["capacity"].__setitem__(0, 47)),
        ("wrong-binding", lambda p: p["target"]["bindings"][0].pop()),
        ("unknown-field", lambda p: p.__setitem__("trusted", True)),
    ]
    p = G.structured(2)
    cert, _ = reference_certificate(p, list(range(8)))
    for name, change in changes:
        pair = copy.deepcopy(p)
        change(pair)
        yield name, pair, cert, 0, cert["bound"], {}


class FrontierIndex(unittest.TestCase):
    def verify(self, pair, order, level=0):
        independent, reference = reference_certificate(pair, order, level)
        produced = prove_upper(pair, order, level, max_layer=4096, max_total=4096)
        for field in ("bound", "witness", "layers"):
            self.assertEqual(produced[field], independent[field])
        total = sum(map(len, independent["layers"]))
        expected = {"accepted": True, "claim": "upper", "level": level,
                    "bound": reference["bound"], "exact": True,
                    "checked_states": total, "attaining_mask": reference["witness"]}
        for cert in (independent, produced):
            self.assertEqual(check_upper(pair, cert, level, cert["bound"], 4096, 4096), expected)
        for mask, value in reference["values"].items():
            self.assertEqual(value, traffic(pair, "target", mask)[level] - traffic(pair, "source", mask)[level])
        c, terms = difference(pair, level)
        budget = Budget(operations=50_000_000)
        self.assertEqual(Counter(pair["kernel"]).square(c, terms, budget=budget),
                         sum(value * value for value in reference["values"].values()))
        fixed = sum(b["count"] is not None for b in pair["kernel"]["blocks"])
        m = len(terms)
        self.assertEqual(budget.used, (1 + m + m * (m + 1) // 2) * (1 + fixed))
        bump("profile_cases"); bump("profile_rows", total)
        bump("literal_mask_level_checks", len(reference["values"]))

    def test_profiles_and_orders(self):
        for name, pair in fixtures():
            for level in range(len(pair["architecture"]["capacity"])):
                for order in orders(pair["kernel"]["guards"]):
                    with self.subTest(case=name, level=level, order=order):
                        self.verify(pair, order, level)

    def test_all_four_guard_permutations(self):
        chosen = [item for item in fixtures() if item[0] in ("grid-free", "global-2", "singletons", "structured-free")]
        for name, pair in chosen:
            for order in itertools.permutations(range(4)):
                with self.subTest(case=name, order=order):
                    self.verify(pair, list(order))
                    bump("complete_permutations")

    def test_certificate_rejections(self):
        for name, pair, cert, level, bound, limits in certificate_mutations():
            with self.subTest(case=name):
                with self.assertRaises(Invalid):
                    check_upper(pair, cert, level, bound, **limits)
                bump("certificate_rejections")

    def test_admission_rejections(self):
        for name, pair, cert, level, bound, limits in admission_mutations():
            with self.subTest(case=name):
                with self.assertRaises(Invalid):
                    check_upper(pair, cert, level, bound, **limits)
                bump("admission_rejections")

    def test_loose_statistics_and_row_order(self):
        pair = G.structured(2)
        cert, _ = reference_certificate(pair, [0, 4, 1, 5, 2, 6, 3, 7])
        total = sum(map(len, cert["layers"]))
        # Statistics are ignored; list row order is not part of the recurrence.
        for stats in (None, [], False, {"total_states": -999, "exact": False}):
            c = copy.deepcopy(cert)
            c["statistics"] = stats
            for rows in c["layers"]:
                rows.reverse()
            answer = check_upper(pair, c, 0, c["bound"])
            self.assertTrue(answer["exact"]); self.assertEqual(answer["checked_states"], total)
            bump("informational_controls")
        for bound in (cert["bound"] + 4, 2**63 - 1):
            c = copy.deepcopy(cert)
            c["bound"] = bound; c["witness"] = None
            if bound == 2**63 - 1:
                c["layers"][-1][0][2] = bound
            answer = check_upper(pair, c, 0, bound)
            self.assertFalse(answer["exact"]); self.assertIsNone(answer["attaining_mask"])
            self.assertEqual(answer["checked_states"], total)
            bump("loose_boundary_controls")

    def test_state_limits_and_equality_charge(self):
        pair = G.structured(2)
        cert, _ = reference_certificate(pair, [0, 4, 1, 5, 2, 6, 3, 7])
        total = sum(map(len, cert["layers"]))
        peak = max(map(len, cert["layers"]))
        self.assertTrue(check_upper(pair, cert, 0, cert["bound"], peak, total)["accepted"])
        for layer, states in ((peak - 1, total), (peak, total - 1)):
            with self.assertRaises(AnalysisLimit):
                check_upper(pair, cert, 0, cert["bound"], layer, states)
            bump("state_limit_controls")
        c, terms = difference(pair)
        charge = (1 + len(terms) + len(terms) * (len(terms) + 1) // 2) * 3
        budget = Budget(operations=charge)
        self.assertTrue(check_equal(pair, {"kind": "equal", "level": 0, "square_sum": 0}, budget=budget)["accepted"])
        self.assertEqual(budget.used, charge)
        with self.assertRaises(AnalysisLimit):
            check_equal(pair, {"kind": "equal", "level": 0, "square_sum": 0}, budget=Budget(operations=charge - 1))
        bump("equality_charge_controls", 2)

    def test_checker_does_not_use_producer(self):
        from unittest.mock import patch
        pair = G.structured(2)
        cert, _ = reference_certificate(pair, [0, 4, 1, 5, 2, 6, 3, 7])
        with patch("dataflow.producer.prove_upper", side_effect=AssertionError("producer is not a checker dependency")):
            self.assertTrue(check_upper(pair, cert, 0, cert["bound"])["accepted"])
        bump("independent_checker_controls")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FrontierIndex))
    print(json.dumps({"status": "PASS" if result.wasSuccessful() else "FAIL",
                      "timing_run": False, "counts": COUNTS}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
