"""Tiny exhaustive-prefix oracle: no production imports or transition recurrence.

Enumerate full legal masks independently, then group their prefixes by the
mathematical frontier state. This is exponential, limited to twelve guards,
and only a finite regression reference, not a solver or general proof.
"""
from itertools import combinations, product


def prefix_profile(n, blocks, order, constant, terms):
    if type(n) is not int or not 1 <= n <= 12:
        raise ValueError("reference is limited to 1..12 guards")
    if sorted(order) != list(range(n)):
        raise ValueError("reference requires a permutation")
    seen = []
    options = []
    for block in blocks:
        ids, count = block["ids"], block["count"]
        seen.extend(ids)
        sizes = range(len(ids) + 1) if count is None else [count]
        options.append([
            sum(1 << v for v in choice)
            for size in sizes for choice in combinations(ids, size)
        ])
    if sorted(seen) != list(range(n)) or any(not row for row in options):
        raise ValueError("reference requires a nonempty disjoint support domain")
    legal = sorted(sum(parts) for parts in product(*options))
    fixed = [sum(1 << v for v in b["ids"]) for b in blocks if b["count"] is not None]
    universe = (1 << n) - 1
    layers = []
    prefix = 0
    for t in range(n + 1):
        future = universe ^ prefix
        open_terms = [a for a, _ in terms if a & prefix and a & future]
        open_blocks = [b for b in fixed if b & prefix and b & future]
        table = {}
        for mask in legal:
            chosen = mask & prefix
            occupancy = sum(1 << j for j, a in enumerate(open_terms) if a & chosen)
            counts = tuple((b & chosen).bit_count() for b in open_blocks)
            reward = sum(w for a, w in terms if not a & future and a & chosen)
            key = (occupancy, counts)
            table[key] = max(reward, table.get(key, reward))
        layers.append([[o, list(q), value] for (o, q), value in sorted(table.items())])
        if t < n:
            prefix |= 1 << order[t]
    values = {x: constant + sum(w for a, w in terms if a & x) for x in legal}
    bound = max(values.values())
    return {"layers": layers, "bound": bound,
            "witness": min(x for x in legal if values[x] == bound),
            "legal_masks": legal, "values": values}
