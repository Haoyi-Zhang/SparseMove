"""Finite tests for the production side of metamorphic comparisons."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dataflow.generate import structured
from dataflow.literal import traffic
from dataflow.transformation_check import check_transformation


class TransformedProductionTests(unittest.TestCase):
    def setUp(self):
        self.pair = structured(1)
        self.mask = 3
        self.source = traffic(self.pair, "source", self.mask)
        self.target = traffic(self.pair, "target", self.mask)

    def test_swapped_pair_matches_swapped_oracle(self):
        swapped = copy.deepcopy(self.pair)
        swapped["source"], swapped["target"] = swapped["target"], swapped["source"]
        check_transformation(swapped, self.mask, self.target, self.source)

    def test_mismatched_production_traffic_is_rejected(self):
        with patch("dataflow.transformation_check.traffic", return_value=[-1]):
            with self.assertRaisesRegex(AssertionError, "traffic"):
                check_transformation(self.pair, self.mask, self.source, self.target)

    def test_mismatched_production_signature_is_rejected(self):
        with patch("dataflow.transformation_check.eval_difference", return_value=-1000000):
            with self.assertRaisesRegex(AssertionError, "signature"):
                check_transformation(self.pair, self.mask, self.source, self.target)


if __name__ == "__main__":
    unittest.main()
