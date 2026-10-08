"""Compare transformed production traffic and signatures with a literal oracle."""
from dataflow.literal import traffic
from dataflow.model import difference, eval_difference


def check_transformation(pair, mask, source_values, target_values):
    source = traffic(pair, "source", mask)
    target = traffic(pair, "target", mask)
    if source != source_values or target != target_values:
        raise AssertionError("transformed production traffic differs from oracle")
    for level, (old_source, old_target) in enumerate(zip(source_values, target_values)):
        constant, terms = difference(pair, level)
        if eval_difference(constant, terms, mask) != old_target - old_source:
            raise AssertionError("transformed production signature differs from oracle")
