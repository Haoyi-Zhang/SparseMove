# Mathematical arguments and exact boundary

These are human-readable mathematical proofs developed in this project, not
proof-assistant output. The executable implementation is checked on finite inputs.
The generic coverage basis, exact second-moment identity and frontier dynamic
programming are established mechanisms; the claimed result concerns their precise
combination with the residency contract and its complexity separation.

## 1. Contract and notation

Let G be n independent Boolean positions before promises. A mask S is a subset of
G. A partition consists of fixed-cardinality blocks B_j with required counts k_j
and a union F of free blocks. The legal family is

    Omega = {S subset G : |S intersect B_j| = k_j for every fixed block j}.

Blocks are nonempty, disjoint and cover G together with F; 0 <= k_j <= |B_j|.
Consequently Omega is nonempty. This is a promise on actual structural support,
not on the number of numerically nonzero arithmetic results. Active values may
be zero. The runtime mask must satisfy the promise; otherwise no theorem applies.

A shared kernel is a finite multiset of distinct event identities. Each event has
one guard g in G or an unconditional guard, a fixed output index and a nonempty
fixed list of immutable input reads. An active event adds the product of its reads
to its output in Z/(2^32). A sparse address is either always present or attached
to one guard; admission requires an event reading a conditional address to have
that same guard. The executable language does not express conjunctions of
independent sparse-operand guards or compressed-output updates.

A mapping is an event permutation, explicit half-open residency lifetimes and
address tiles, and a leaf-residency binding for every event operand. Each nonroot
residency has one parent at the preceding hierarchy level, containing both its
address tile and lifetime. A resident tile is lazily transferred once, immediately
before its first active descendant use, and retained for its declared lifetime.
An unused tile is not transferred, but its declared worst-case storage is reserved.
No evictions, spills, prefetches or implicit recomputations occur. Equal-time
releases precede allocations. Simultaneous duplicate tiles are separately reserved.

Every value slot is four bytes. Dense tiles of extent d have 4d bytes. Bitmap-packed
tiles have four bytes per structurally present position; their positions are known
from an already resident global mask. Coordinate-packed tiles have an eight-byte
(lo,count) header and eight bytes per present (coordinate,value) record. Both packed
forms include always-present positions. Global-mask bytes ceil(n/8) and dense-output
bytes 4o are charged once on the first edge, and separately reserved in control
memory. Static descriptors, instructions, mask distribution, conversion computation
and accumulator accesses are not payload-edge transfers in this model. In particular,
a constant payload capacity is NOT constant total memory or constant energy.

## 2. Semantics and exact traffic extraction

**Lemma 1 (codec law).** Decoding an encoded tile gives its immutable logical values
at every tile address, with zero at structurally absent positions.

*Proof.* Dense encoding emits one four-byte word per address, replacing absent
positions with zero; the decoder reads that sequence in address order. Bitmap
encoding and decoding traverse the same address interval and the same global mask,
so each emitted word is consumed at exactly its corresponding present position.
Both place zero at the remaining positions. Coordinate encoding records the address
and value at each present position, and its header records the interval start and
record count. Decoding checks the header and each monotonically emitted address,
then returns its value and zeros elsewhere. There is neither a lossy numeric
conversion nor an address renumbering. This proves all three cases. This law is for
packets produced by these codecs, not arbitrary malformed external packets. QED.

**Lemma 2 (operational soundness).** An admitted mapping executes exactly the shared
kernel result for every legal mask and every assignment of active mod32 values.

*Proof.* By parent containment and strictly decreasing level numbers, every bound
leaf read has a finite acyclic chain to off-chip immutable storage. At the first
active use, load the chain from root to leaf. Lemma 1 inductively gives every child
the same logical address values as its parent. Parent lifetime containment and the
use-in-leaf-lifetime check keep every required ancestor resident. Capacity reservation
covers each actual encoded size because packed size never exceeds its declared
maximum. Thus no modeled spill is necessary. The operand-presence condition ensures
that an active conditional read is present. Every mapping executes each active
event exactly once; associativity and commutativity of addition in Z/(2^32) allow
any event permutation. Outputs start at zero and are stored once. QED.

For a residency r, let A_r be the set of conditional guards of its bound descendant
uses and let u_r say that some such use is unconditional. Its trigger is 1 if u_r,
and otherwise OR_A_r(S) = 1[A_r intersects S]. An empty conditional footprint has
trigger zero. The encoded packet size has the mask-linear form

    b_r(S) = h_r + sum_g p_rg 1[g in S],

where h_r and all packet coefficients are nonnegative integers fixed by its format,
tile and address-support map. This includes packed positions never used directly
by that residency: overfetch is charged when the residency is triggered.

**Theorem 3 (exact movement signature).** On each hierarchy edge, admitted mappings
have an exact traffic difference

    f(S) = C_target(S) - C_source(S) = c + sum_A d_A OR_A(S),

with integer coefficients. It can be extracted in polynomial time and size in the
expanded event/binding/residency/packed-record representation.

*Proof.* A residency transfers if and only if one descendant event is active; it
transfers once rather than once per descendant. Therefore its exact contribution
is its trigger times b_r(S). This remains true at ancestor levels: union the guards
of all descendant uses, not their individually charged transfer counts. The identity

    x_g OR_A = OR_{g} + OR_A - OR_{A union {g}}

holds by considering x_g=0 and x_g=1. Expand each conditional packet term with this
identity; unconditional triggers already have a constant-plus-singletons form.
Add common mask/output traffic at the declared edge and subtract source from target.
Combine equal footprints and remove zero coefficients. Each expanded packet term
creates at most three OR terms. The extraction visits finitely many bounded-length
ancestor paths and explicit packed positions, hence is polynomial in this expanded
representation. It is not a polynomial claim in logarithmically encoded tensor
extents for arbitrary symbolic loop nests. QED.

## 3. Promise-conditioned equality and counterexamples

For any A subset G define the exact avoidance count

    Z(A) = 2^(|F minus A|) product_j binom(|B_j minus A|, k_j),

with an out-of-range binomial equal to zero. Set D = c + sum_A d_A.

**Theorem 4 (complete equality test).** Let m be the number of nonzero footprints.
Then

    Q = D^2 Z(empty) - 2D sum_A d_A Z(A)
        + sum_A,B d_A d_B Z(A union B)

is exactly sum_{S in Omega} f(S)^2. Therefore Q=0 if and only if f(S)=0 for every
legal mask. Its computation uses O(m^2 (b+1)) elementary count/bitset operations,
where b is the number of fixed blocks, and polynomial-length integers.

*Proof.* The choices in distinct fixed blocks and F are independent as combinatorial
sets, so Z(A) counts the legal masks avoiding A. This is exact counting, not a
stochastic independence assertion about empirical sparsity. Put z_A(S)=1[S avoids A].
Since OR_A=1-z_A, f=D-sum_A d_A z_A. Expanding the square gives the stated formula,
because z_A z_B=z_(A union B). Every term in the original finite sum is nonnegative,
and every legal mask has positive weight one; thus the sum vanishes exactly when
all differences vanish. There are at most m(m+1)/2 distinct pair evaluations before
optional caching. Each count is at most 2^n, while coefficient lengths are polynomial
in the input bytes. Sums and products have polynomial bit length; using exact
binomial evaluation and integer arithmetic gives polynomial bit complexity. QED.

The square identity is ordinary algebra. The useful restriction is that avoiding
unions can be counted cheaply under the declared support promise and that exact
residency traffic has a short signed-OR representation.

**Corollary 5 (constructive non-equality).** A legal separating mask can be found
in O(n m^2 (b+1)) count operations whenever Q>0.

*Proof.* Maintain imposed-one set O and imposed-zero set R. To count masks avoiding
A consistent with the prefix, return zero if A intersects O or O intersects R;
otherwise choose k_j-|O intersect B_j| positions from B_j minus (O union R union A),
and choose freely among the remaining free positions. The same squared-sum formula
works on that restricted family. At the next guard, the zero and one subfamilies
partition the current family, so their squared sums add to the positive current
sum. Choose a branch whose sum is positive. After n steps the remaining family
contains exactly one legal mask, and its squared difference is positive. QED.

For g independent four-position blocks, the running dense-tile mapping has source
B traffic 32 sum_i x_i per block and target B traffic 64 OR_B per block. Under 2:4,
both are 64, although their unrestricted signatures differ. Under free masks they
are not equal. A global count of 2g does not impose two per block: for g=2, distribute
all four ones in one block; target-minus-source B traffic is -64 instead of zero.
These are coarse full-B-tile mappings, not optimal SpMM implementations.

## 4. Frontier certificates for one-sided bounds

Choose a guard order. Immediately before each position, retain one touched/not-touched
bit for each OR footprint with at least one processed and at least one unprocessed
member. Also retain the selected count for each fixed block that has members on
both sides of the cut. On a guard assignment, update its open counters; reject a
branch that already exceeds its required count or cannot attain it with the guards
remaining. Update touched bits and charge each footprint coefficient exactly at
its last member. Forget closed footprints and closed fixed blocks.

**Lemma 6 (state sufficiency).** Prefixes with the same retained state have identical
legal future choices and identical future incremental rewards.

*Proof.* A future guard can affect a not-yet-closed footprint only through whether
one of its previous members was selected, exactly the stored bit. Its coefficient
is still uncharged. A closed footprint has already contributed fully and is absent
from future rewards. For each open fixed block, feasibility of suffix choices
depends only on its selected count. Unopened blocks have count zero, and completed
blocks have met their exact required count. Disjoint blocks introduce no other
cross-prefix constraint. Thus a prefix's other details affect only its accumulated
reward, not future legality or reward. QED.

A certificate supplies a table of integer potentials P_t(q) for retained states at
every layer. The checker demands initial state value zero, a row for every legal
successor of every listed state, the inequalities

    P_(t+1)(q') >= P_t(q) + gain_t(q,bit),

and final potential plus c no greater than the independently requested bound U.
Informational statistics do not influence acceptance. Extra states cannot remove
the obligation to cover every successor from the initial state.

**Theorem 7 (soundness and finite completeness).** An accepted certificate proves
f(S)<=U for every legal mask. Exact maximum-prefix potentials form an accepted
certificate with U=max_Omega f. An additional legal mask attaining U proves tightness.

*Proof.* For any legal mask, follow its unique sequence of transitions from the
initial state. The checker requires every such transition, so induction on layers
bounds its charged prefix reward by the corresponding potential. At the last layer
all footprints are charged and all counts are satisfied; add c and apply the
terminal inequality. For completeness take P_t(q) to be the maximum charged reward
of a prefix reaching q. Lemma 6 justifies merging states and the max-plus recurrence.
These exact potentials satisfy every checked inequality with their optimal terminal
bound. The maximum exists because Omega is finite and nonempty. An attaining mask
proves the reverse inequality for that bound. Implemented state/time caps may return
unresolved and therefore do not inherit unrestricted algorithmic completeness. QED.

If w_t OR footprints and J_t fixed blocks cross a cut, the number of candidate
states is at most 2^w_t product_(j in J_t)(k_j+1), often with fewer reachable states.
This is a correlation frontier, not the number of physically resident payload slots.
The explicit-certificate recurrence is a standard form of finite dynamic programming,
not a new generic solver. Common footprint cancellation may reduce this parameter.

## 5. Constant-payload hardness

**Theorem 8.** For the unbounded finite IR family, deciding whether all legal masks
satisfy C_target-C_source<=0 is coNP-complete, even with one hierarchy edge, an
eight-byte payload capacity, dense four-byte scalar tiles, and disjoint 2:4 support
blocks. The global control memory and program description are not bounded by eight
bytes. The requested movement threshold is the fixed constant zero.

*Proof.* Non-universality has a polynomial witness: a mask of n bits. Check the
cardinality blocks and evaluate the literal event/residency cost in polynomial time,
then test whether it is positive. Thus the problem is in coNP.

For hardness reduce the complement of the standard unweighted Simple Max Cut
decision problem. An instance is a graph G=(V,E) and an integer L with
1<=L<=|E|; the NP question asks whether a cut of size at least L exists.
For each graph edge {u,v}, create four guarded multiply-add events with guards
u,u,v,v. Each event has a four-byte input A slot and a four-byte B scalar operand.
The A residency is one event long in both mappings. The source orders the four
events as u,u,v,v and uses two consecutive B residencies, covering the first pair
and the second pair. The target swaps the middle two event identities and retains
B residencies by execution slot, obtaining u,v,u,v. Source B traffic is
4(x_u+x_v), target B traffic is 8 OR_{u,v}, and their difference is

    8 OR_{u,v} - 4x_u - 4x_v = 4 (x_u XOR x_v).

The A traffic, arithmetic events and outputs agree. Serialize these edge gadgets;
one A and one B word are live at a time in either schedule. Their total difference
is 4|cut(S)|.

Now append L-1 serialized offset units. Each unit contains two unconditional events
that read one always-present A word and the same B scalar. The source gives the two
events separate one-event B residencies, while the target gives them one residency
spanning both events. A traffic and arithmetic cancel, but target-minus-source B
traffic is 4-8=-4. The merged target lifetime still overlaps only one one-event A
residency, so both mappings retain the same eight-byte payload capacity. Therefore

    f(S) = 4 (|cut(S)| - (L-1)).

The fixed request f(S)<=0 holds for every support exactly when G has no cut of size
at least L. The number of offset units is at most |E|-1, so the construction is
polynomial.

For the 2:4 restriction, replace every vertex guard by a block consisting of that
guard and three new dummy guards, requiring exactly two selected positions. A zero
vertex selection extends by choosing two of the three dummies; a one selection
extends by choosing one. Thus every vertex assignment has 3^|V| legal extensions,
and every legal mask projects to a vertex assignment. Add identical neutral
single-event/single-residency computations for the dummy guards, and for isolated
vertex guards when needed. The offset events are unconditional and need no lifting.
All neutral traffic cancels, and serial execution keeps the eight-byte payload
capacity. Consequently the fixed-zero decision is unchanged under 2:4. The
reduction is polynomial, proving coNP-hardness. QED.

This theorem concerns an arbitrary-sized finite family, not the literal finite
admission caps of one implementation. A polynomial-size upper certificate for all
instances is not claimed. The exponential frontier is compatible with the theorem.
The executable artifact separately exhausts all simple graphs through four vertices
under free supports and through three vertices under the 2:4 lifting, for every
nontrivial threshold: 218 generated pairs and 5,800 legal masks agree between the
literal traffic interpreter, the extracted signature and the closed-form reduction.
Those finite checks validate the implementation of the gadgets; they are not the
general hardness proof.

## 6. Separating examples and rewrite rules

**Proposition 9 (density tie).** On a b by b array of guards, let the source B
residencies touch rows and target residencies touch columns. Each affected residency
has four bytes. Both iid expected B traffic functions equal 4b(1-(1-p)^b). Yet a
mask consisting of one complete row gives target-minus-source 4(b-1), and one
complete column reverses the sign. The affected B traffic ratio is b, not a ratio
of total program time or total traffic. The literal construction uses one-event
A slots and serialized row/column B scopes, fitting eight payload bytes. QED by
counting the nonempty rows and columns.

This example refutes only the specified iid histogram as a universal certificate;
it does not claim that D2T2, Sparseloop or other richer models ignore correlation.

**Proposition 10 (no bounded-size violating-mask test).** For every n>=3 an
admitted eight-payload-byte pair has positive cost difference only on the full
n-guard mask.

*Proof.* Take guards to be the edges of a simple n-cycle. Source B scopes correspond
to vertices and touch the two incident edge guards. Target B scopes are n singletons
and one all-guards scope. The same two events per guard are arranged and bound to
realize both, with one four-byte B scalar residency at a time. A slots are single-event
four-byte tiles in both. Hence f/4=|S|+1[S nonempty]-|incident vertices of S|. For empty
S this is zero. A proper nonempty cycle-edge subset is a disjoint union of c>=1 paths;
it has |S|+c incident vertices, so the difference is 1-c<=0. The full cycle has n
edges and n vertices, giving one. Only the full mask violates a zero upper bound,
and n is unbounded. QED.

**Proposition 11 (local rules with re-admission).** The following constructors
preserve semantics when all their outputs pass admission.

Merge two identical leaf tiles with the same format and parent, taking the lifetime
hull and replacing their bindings. With common packet size b(S)>=0 and triggers t1,t2,
its traffic change is b(S)(t1 OR t2-t1-t2)=-b(S)t1t2<=0. Ancestor trigger unions are
unchanged. Lifetime-hull capacity must be checked: a gap with other live tiles may
invalidate an otherwise byte-improving merge.

Split a leaf tile into disjoint address subtiles and route each operand by address.
For dense or bitmap-packed headerless formats, b1+b2=b and each child trigger is no
greater than the original trigger, so b1t1+b2t2<=bt. Coordinate format duplicates
its header: when both children are used it can add eight bytes, and its increased
reservation can also fail admission. This is not silently treated as a monotone rule.

Replace a leaf encoding using the codec law. A pointwise smaller packet-size function
with the same trigger cannot increase edge traffic, but semantics alone says nothing
about byte order. Dense-to-bitmap and coordinate-to-bitmap are pointwise nonincreasing
under the global-mask contract. Arbitrary format changes require a separate comparison.

Adjacent interchange preserves the shared event multiset. Some bindings follow events
and selected operand bindings stay with execution slots; the constructor rechecks
address coverage and retimes lifetimes before capacity/parent admission. It is
semantics-preserving by Lemma 2, not automatically cost-monotone, as Theorem 8 shows.

A sequence with certified bounds U_i has final difference at most sum_i U_i by
pointwise telescoping over the same legal mask. A joint certificate may be smaller:
on an odd cycle of graph-cut gadgets the sum of edge maxima is 4|E|, while the
joint maximum is 4(|E|-1). QED.

## 8. Executable integer range and certificate-size boundary

The checker stores each potential as a signed 64-bit integer. Under the executable
admission limits this range covers every value the admitted signature can generate.
At one hierarchy edge there are at most 131,072 = 2^17 scopes in a mapping. Each
scope's actual packet is no larger than its unconditional reservation, and admission
requires the simultaneous reservation to fit a capacity no larger than 2^40 bytes.
In particular each individual transfer is at most 2^40 bytes. A residency transfers
at most once, so the total payload traffic of either mapping on one edge is at most
2^17 2^40 = 2^57 bytes. The separately counted mask/output constant is at most 2^40,
so either nonnegative edge cost is strictly below 2^58 and the target-minus-source
difference lies strictly between -2^58 and 2^58.

The frontier recurrence may temporarily hold a sum of signed signature coefficients
rather than a realized difference. A dense conditional residency contributes one
coefficient of magnitude at most its reservation. A packed conditional residency
with header h and mask-linear record sum p contributes an h term and, per record,
the three-term identity x_g OR(A) = OR({g}) + OR(A) - OR(A union {g}). Therefore the
sum of absolute coefficient magnitudes contributed by one mapping is conservatively
less than three times its total reservation-transfer envelope; source subtraction
adds another such envelope. Including constants leaves the absolute intermediate
sum below 2^60. This is inside the signed 64-bit interval. The unit test named
`test_signed_64bit_certificate_boundary` also rejects values outside the accepted
integer range. This argument is about the bounded executable, not the arbitrary-size
family used in the complexity theorem.

Certificate verification is polynomial in the explicit certificate length and input
size. No theorem claims that every admitted or unbounded instance has a polynomial-size
certificate. The retained benchmark makes this distinction observable. Grouped
structured instances have 65 states / 1,052 compact JSON bytes at eight exact-2:4
groups and 257 / 3,727 bytes at 32 groups. Interleaving the same eight groups yields
32,291 states / 924,932 bytes. A twelve-vertex clique yields 4,096 states / 60,126
bytes. These are deterministic instance measurements, not an asymptotic upper bound.
The state-width formula in Section 4 and the coNP-completeness theorem are consistent
with exponential certificates in unfavorable orders or interaction graphs.

## 9. Validation independence, fresh cases, and interpretation

The executable evidence uses four distinct levels that must not be conflated.

1. The production producer and checker have separately written frontier-transition
   loops, but share admission, signature extraction, the written IR contract, and the
   Python runtime.
2. The literal interpreter follows events, bindings, parent chains, and load-once
   state directly rather than evaluating the extracted signature. Packet execution
   additionally serializes and decodes bytes before modular arithmetic.
3. `scripts/adversarial_crosscheck.py` regenerates small instances and exact optima,
   but imports production modules. It is a production-coupled cross-check, not an
   independent implementation.
4. `scripts/standalone_oracle.py` intentionally does not import the production
   `dataflow` package. It has its own parser, admission checks, legal-mask enumerator,
   load-once interpreter, signed-OR construction, exact-square computation, packet
   codecs, modular executor, and reduction reconstruction. On the retained input it
   checks all 1,730 pairs and 256,074 masks, 13,997 packet executions, and all 218
   reduction pairs / 5,800 masks.

The standalone oracle lowers the chance that one production function explains all
finite agreements. It remains project-authored, follows the same prose contract, and
runs in the same language and host environment. It is not external replication,
proof-assistant mechanization, or evidence that the prose contract matches a device.

`scripts/reviewer_stress.py` provides a different defense against generator coupling.
It does not call the frozen generator and creates 144 post-freeze pairs with fresh
partitions, hierarchy choices, formats, support blocks, and event orders. Direct
traffic is checked over 2,562 masks. Guard renaming and source/target exchange preserve
or negate traffic as required, self-pairs are exactly equal, exact squares match brute
force, and accepted upper certificates match enumerated maxima. Because no learned
model or fitted parameter exists, statistical train/development/test overfitting is
not the applicable concept. The residual risk is structural: the finite IR and both
case generators may omit behaviors found in broader sparse compilers or hardware.
Fresh generation and metamorphic checks reduce specialization to retained fixtures;
they do not establish workload breadth or performance generalization.

## 10. Reference and claim closure

The publication package treats bibliography size as a relevance check, not a target
to maximize. Every BibTeX key in the manuscript is cited, every citation key is
present, and the artifact audit rejects duplicate keys and duplicate stable
identifiers. `reference_verification.csv` records the scholarly identifier used for
identity checking. `reference_context_audit.csv` records the manuscript section,
claim class, and reason each source is cited. The audit distinguishes formal
comparators, sparse architecture/compiler context, analytical cost models, and
calibration-only sources. A DOI or official-record match confirms bibliographic
identity; it does not imply that another paper's experiment was reproduced.
