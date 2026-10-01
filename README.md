# Dataflow-equivalent mapping

Exact, mask-conditioned byte comparison for a deliberately finite sparse-tensor
residency contract. This is an internal research artifact, not a deployed compiler,
hardware simulator, neural-network benchmark, cache simulator, or proof-assistant
development.

## What is included

`src/dataflow/` contains the strict IR validator, byte-signature extractor,
cardinality counter, equality decision, counterexample constructor, frontier proof
producer, separately written checker, codecs, literal interpreter, and local rewrite
constructors. `proofs/arguments.md` contains the mathematical arguments and the
implementation-bound arithmetic audit. `inputs/` retains every exact generated
main-campaign pair and compact exact graph descriptors for the reduction campaign.
`results/` contains all frozen observations, including unresolved controls.

`tests/` contains 24 test methods, including 26 malformed-input mutations, 14
damaged-certificate mutations, a signed-64-bit boundary case, a shipped certificate
example, packed-overfetch and hierarchy cases, and bounded exhaustive checks of the
fixed-zero reduction. `scripts/` contains deterministic generation, measurements,
integrity auditing, reproduction, and three complementary validation paths:

- `adversarial_crosscheck.py` uses production modules but regenerates small cases and
  exact optima rather than reading frozen expected answers;
- `standalone_oracle.py` intentionally does **not** import the production `dataflow`
  package and uses a separately written strict admission path before independently
  interpreting, encoding, decoding, and checking every retained finite campaign case;
- `reviewer_stress.py` does not call the frozen input generator and creates fresh
  mapping shapes for direct, swap, guard-renaming, equality, and upper-bound checks.

No other project folder, private cache, paper source, network service, model API,
GPU, compiler backend, or external scientific solver is required.

## Requirements and one-command reproduction

Use Linux with Python 3.10 or later, a writable temporary directory, and roughly
150 MiB of working storage. Only the Python standard library is imported. The driver
and its sequential children use one CPU, a 1 GiB address-space cap per process, and
42/44 second soft/hard CPU limits. Each child has a 240-second wall timeout. A slower
host may fail rather than silently relax the frozen envelope.

From the repository root, with an output path that does not already exist:

```sh
python3 scripts/reproduce.py --output /tmp/dataflow-reproduction
```

The driver runs the artifact audit, 24 tests in normal mode and the same 24 under Python optimization, all three validation paths, and 15
scientific parts: nine main-campaign chunks, four scaling/ordering chunks, the
fixed-zero reduction campaign, and the certificate-structure benchmark. It recreates
all 1,730 main-campaign mapping pairs and all 218 reduction pairs. Every non-timing
scientific field is compared with the retained JSON; exact generated input bytes are
also compared. CPU time, wall time, and peak RSS are deliberately excluded from exact
matching. Statuses, bounds, witnesses, state counts, charged operations, certificate
structure, mask counts, and generated inputs are not. An unresolved result is never
converted into success. Swap-event counts must remain zero.

The three validation paths may also be run separately; each output path must not
already exist:

```sh
python3 scripts/adversarial_crosscheck.py --output /tmp/dataflow-adversarial.json
python3 scripts/standalone_oracle.py --output /tmp/dataflow-standalone.json
python3 scripts/reviewer_stress.py --output /tmp/dataflow-stress.json
```

The production-coupled adversarial check covers 350 signed-OR count/witness cases,
90 mapping pairs over 1,074 masks, 58 exact frontier optima, 566 codec/semantic cases,
and 80 reduction instances over 16,720 masks. The standalone oracle replays 1,730
pairs over 256,074 masks, 13,997 packet executions, and 218 reduction pairs over
5,800 masks without importing production code. Its admission self-check accepts the
valid structured example, reports the source and target peak as 48 payload bytes, and
rejects seven focused mutations: payload capacity 48 to 47, control capacity 9 to 8,
an invalid event permutation, a parent error, guard/operand and binding/operand
mismatches, and a Boolean identifier. The post-freeze stress suite creates
144 fresh pairs over 2,562 masks and performs 3,219 source/target-swap checks, 3,219
guard-renaming checks, 192 exact-square/self-equality checks, and 96 upper-certificate
checks. These are finite project-authored checks, not external replication or a
machine-checked general proof.

For a smaller bounded chunk, still with the validation prelude and exact comparison:

```sh
python3 scripts/reproduce.py --output /tmp/dataflow-structured --parts structured
```

Successful command execution is evidence of reproducibility, not by itself a proof
of the general mathematical statements.

## Command-line example

All examples run from the repository root. Certificate output paths must not already
exist.

```sh
PYTHONPATH=src python3 -m dataflow validate examples/structured.json
PYTHONPATH=src python3 -m dataflow equal examples/structured.json --output /tmp/equality-certificate.json
PYTHONPATH=src python3 -m dataflow check-equal examples/structured.json --certificate /tmp/equality-certificate.json
PYTHONPATH=src python3 -m dataflow upper examples/structured.json --output /tmp/upper-certificate.json
PYTHONPATH=src python3 -m dataflow check-upper examples/structured.json --certificate /tmp/upper-certificate.json --bound 0
PYTHONPATH=src python3 -m dataflow check-upper examples/structured.json --certificate examples/structured-zero-bound-certificate.json --bound 0
PYTHONPATH=src python3 -m dataflow trace examples/structured.json --mask 3
```

For the shipped upper certificate, `--max-layer 1` is a legal analysis budget that is
too small and therefore returns JSON status `unresolved` with exit 2. Raising the same
budget to `--max-layer 3` accepts the certificate. A structurally or mathematically
damaged certificate remains `rejected` with exit 1 when the budget is sufficient.

An upper bound is target bytes minus source bytes at the selected hierarchy edge.
The checker receives the requested bound independently of the certificate. A loose
valid bound needs no attaining witness; a witness proves tightness. The equality
certificate is a claim tag whose checker recomputes the exact squared sum; it is not
a succinct proof that avoids the counting computation.

Exit 0 means the requested computation completed; inspect `accepted` in the JSON.
An equality counterexample also returns 0 with `accepted:false`. Exit 1 rejects
malformed input or a false certificate; exit 2 reports a resource-limited unresolved
analysis. A killed process or missing output is never a certificate. Certificate
publication is atomic, refuses overwrite, and is limited to 16 MiB. These are local
reliability controls, not a security evaluation.

## Contract and implementation limits

Values are unsigned 32-bit modular integers; inputs are immutable and outputs are
dense. Both mappings contain the same guarded product-accumulation events exactly
once, with one guard per conditional event. Supports satisfy disjoint exact-cardinality
or free blocks. Structural presence does not require a numerically nonzero value.

A tile loads on its first active descendant use and remains for its half-open declared
lifetime. Parent scopes contain child addresses and lifetimes. Storage is reserved
conservatively even for an unused tile; duplicate live copies consume separate
capacity. There is no implicit eviction, spill, recomputation, or prefetch. Dense,
globally indexed bitmap-packed, and coordinate packets count different exact bytes.
The global mask and dense outputs have separately reserved control memory.
Instruction storage, mask-distribution energy, conversion computation, and accumulator
accesses are outside the payload-edge metric.

Executable admission permits at most 4,096 guards, 65,536 events and outputs, 64
tensors, four hierarchy edges, and 131,072 scopes. Packed support arrays contain at
most 65,536 addresses and expanded packed-record work is capped at 200,000 per
mapping. Exact-count preflight is capped at 50 million charged operations; frontier
construction defaults to 100,000 states per layer and 300,000 total. These are
implementation bounds, not the definitions of the unbounded families used in the
complexity theorem.

The checker accepts signed 64-bit potentials. Under the admission limits, one edge
has at most 2^17 scopes and each transfer is at most the 2^40 capacity, so either
mapping's cost is below 2^58. A conservative absolute sum over the expanded signed
coefficients is below 2^60. The accepted integer range therefore covers every
admitted intermediate value rather than relying on overflow-prone behavior.

## Evidence, certificate size, and non-claims

The frozen campaign has 256,074 legal-mask traffic checks and 13,997 masks with
actual packet encoding, decoding, and modular execution. The fixed-zero reduction
campaign checks 218 thresholded graph mappings and 5,800 legal masks against literal
traffic, the signed signature, and the Max-Cut closed form. Equality scaling times
measure only the exact squared-count phase, not parsing, admission, extraction, or
checker recomputation.

The complexity statement is quantified as follows: deciding whether every legal mask
satisfies target-minus-source traffic `<= 0` is coNP-complete, while the complementary
question of whether some legal mask has positive difference is NP-complete. The
interchange-only `cut_graph` tests cover one adjacent swap per edge. The complete
threshold reduction also uses offset merges; the retained path-graph trace for edges
`(0,1),(1,2)` and threshold 2 performs two interchanges and one merge, changes 16
residencies to 15, reaches the generated target exactly, and remains admitted at an
eight-byte payload peak after every step.

The certificate benchmark records both compact and wide-frontier regimes. Grouped
structured instances use 65 states / 1,052 serialized bytes at eight 2:4 groups and
257 / 3,727 bytes at 32 groups. Interleaving the same eight groups uses 32,291 states
and 924,932 bytes. A twelve-vertex clique uses 4,096 states and 60,126 bytes. These
measurements expose order and interaction width; they do not claim polynomial-size
certificates for unrestricted instances.

No model is trained and no parameter is fit to the campaign, so ordinary statistical
train/test overfitting is not the relevant failure mode. The real risk is structural
specialization to the finite IR and generators. The standalone oracle, fresh stress
generator, negative controls, and metamorphic invariants reduce implementation
coupling; they do not establish deployed-workload representativeness.

No neural accuracy, silicon energy, device timing, workload-wide speedup, cache-miss
prediction, or production-compiler coverage is claimed. The producer and checker have
separate frontier loops but share the written contract and Python runtime. The prose
proofs are not proof-assistant developments, and all validation remains project-authored.
The standalone oracle does not import production validation code, but it still shares
the written IR contract, frozen JSON corpus, Python semantics, and host environment;
those common trust boundaries are not presented as independently established facts.
The hardness result fixes an eight-byte **payload** capacity and requested movement
bound zero while control and program storage grow with the graph.

AI assistance was used substantively for research design, proof development, code,
input generation, tests, analysis, validation, and writing. The artifact makes no
claim of human-only research or independent external review. Accountable human review
of correctness, originality, authorship, and applicable publication policy remains
required before external use.

## Files, references, and licensing

`claim_evidence_ledger.csv` maps each material claim to proofs, code, tests, and raw
results. `external_resources.csv` records 73 manuscript sources and five
calibration-only sources. `reference_verification.csv` records identifier and scope
checks; `reference_context_audit.csv` maps every manuscript key to its actual citation
context and claim class. Metadata resolution is not represented as experimental
replication.

`results/summary.csv` and the other CSV files are derived transparently from retained
JSON. `results/equality-plot.csv` includes only completed runs; the unresolved
256-group preflight remains in `results/equality.csv` and is deliberately excluded
from the timing curve. Run `python3 scripts/summarize.py` to refresh derived tables
without rerunning science.

Source code, exact generated inputs, result data, and original prose proofs are
supplied under the MIT license in `LICENSE`. No third-party research implementation
or paper PDF is redistributed. Source attribution does not imply that an external
baseline was executed. The artifact is anonymous, and no repository URL has been
invented.
