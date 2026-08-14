# Circle-FRI field-frontier experiment contract

**Status:** frozen experiment-representation boundary v1, root/SOL reviewed;
no field, extension, Circle domain, hash, AIR, FRI schedule, or proof encoding
is selected. Generic certificate and reference machinery is authorized under
this boundary. Candidate-specific Script, Circle, AIR, FRI, or prover work
remains closed until its exact descriptor and certificate gates pass.

## Purpose

This contract prevents an implementation convention from becoming the BCH
architecture by accident. It separates the algebraic roles, fixes what must be
content-pinned before measurement, and defines equal evidence requirements for
the surviving Mersenne-field candidates.

The existing `field:m31-base-control` result is a measured neutral control. It
does not select M31, an extension degree, or a proof protocol.

## Roles which must remain separate

| Role | Symbol | What it controls | Selection status |
| --- | --- | --- | --- |
| Trace/base field | `B` | witness columns, AIR constraints, characteristic, and base Circle coordinates | open |
| Circle evaluation domain | `D subset C(B)` | exact subgroup/coset, generator, order, trace length, blowup, and code evaluation set | open |
| Code alphabet/coefficient field | `E` | values carried by encoded polynomials and composition evaluations | open; may equal or extend `B` |
| AIR-batching challenge field | `F_batch` | random linear combinations of constraint terms | open; any alias to `E` is explicit |
| FRI challenge field | `F_fri` | folding and proximity-test challenges | open; any alias to `E` is explicit |
| DEEP challenge field and point space | `F_deep`, `C(E)` | out-of-domain point sampling and quotient evaluations | open |
| DEEP quotient strategy | `Q_deep` | `E(i)` with real/imaginary decomposition or an `E`-only alternative | open and measured separately |
| Algebraic-hash field | `F_hash` | any note/nullifier/AIR-native permutation | open; equality with `B` must be justified, not assumed |
| Byte-hash channel | `H_outer` | transcript framing, Merkle commitments, transaction context, and byte-domain binding | open |
| Systemic soundness model | `S_total` | composition of algebraic, proximity, hash, grinding, parser, and union-bound terms | open |

An “M31 degree 5 proof” is therefore not a complete design name. A concrete
candidate must say which role uses that extension, whether the Circle domain
stays over the base field, every embedding between distinct roles, and which
soundness event requires the extension. Different-characteristic fields may
not be mixed without a complete typed embedding/arithmetization design.

The Circle paper permits extension-valued codewords and challenges while the
evaluation domain remains on the base circle. Its `E(i)` DEEP construction does
not imply that every proof value doubles in width: real/imaginary batching can
remain over `E`, and an alternative quotient strategy stays in `E`. This is a
measured strategy axis, not an inherited default.

## Soundness is an event DAG

Raw field cardinality is not an independent security term. It appears inside
specific AIR-batching, lookup, DEEP, or FRI bad-event bounds. The worksheet must
give non-overlapping event nodes and dependencies, then compute:

```text
epsilon_system <= sum(epsilon_event_j)
systemicBits = -log2(epsilon_system)
```

Challenge-sampler bias, Fiat-Shamir/random-oracle failure, Merkle/hash binding,
grinding, parser/canonicality failure, and each algebraic/proximity opportunity
are separate only when they are genuinely different events. The same
bad-challenge event may not be counted under independent `air`, `challenge`,
and `field` labels. Several 128-bit component bounds do not compose to a
128-bit systemic bound.

## Mechanical Mersenne frontier

For every row below, `p = 2^q - 1` passed a deterministic Lucas-Lehmer check.
Every `p` is `3 mod 4`; therefore `-1` is nonsquare and the base-field circle
`x^2 + y^2 = 1` has order `p + 1 = 2^q`. `d` below is only the least extension
degree whose raw field cardinality exceeds 128 bits. It is not a soundness
claim.

| Base | Base Circle order | Fixed base payload | Least `d` above 128 raw bits | Raw extension payload | Initial disposition |
| --- | ---: | ---: | ---: | ---: | --- |
| M13 | `2^13` | 2 bytes | 10 | 20 bytes | analytical/domain control |
| M17 | `2^17` | 3 bytes | 8 | 24 bytes | analytical/domain control |
| M19 | `2^19` | 3 bytes | 7 | 21 bytes | analytical/domain control |
| M31 | `2^31` | 4 bytes | 5 | 20 bytes | measured base; extension open |
| M61 | `2^61` | 8 bytes | 3 | 24 bytes | serious unmeasured candidate |
| M89 | `2^89` | 12 bytes | 2 | 24 bytes | serious unmeasured candidate |
| M107 | `2^107` | 14 bytes | 2 | 28 bytes | high-capacity control |
| M127 | `2^127` | 16 bytes | 2 | 32 bytes | high-capacity control |

The first full-arithmetic shortlist is M31 degree-5 and degree-6 families,
M61 degree 3, and M89 degree 2 with `X^2+1`. The M31 entries remain families,
not concrete candidates, until exact polynomial/tower realizations are named
and certified.

M31 degree 4, M61 degree 2, and M127 degree 1 remain raw-cardinality controls
at roughly 124, 122, and 127 bits. They are not finalists unless a separate
repetition construction proves the complete nontrivial AIR/DEEP bound. M107
and M127 degree 2 remain dormant capacity escalators: add registry rows now,
but activate only the smallest needed candidate if M89's exact worksheet lacks
headroom. They may not be eliminated by presumed Script hostility.

The narrow bases receive the cheapest domain-size and operation-count gates
first. A small base payload does not compensate for a Circle domain that cannot
hold the exact trace and blowup, or for a 7--12-limb extension that is already
dominated in real BCH cost.

## Canonical candidate record

Every experiment candidate must freeze all of these fields before a Script
kernel is written:

```text
candidateId
basePrimeExponent q
basePrime p and deterministic primality certificate
role assignment: B, D, E, F_batch, F_fri, F_deep, Q_deep, F_hash, H_outer
extension degree d for each non-base role
exact monic irreducible polynomial or typed tower
independent irreducibility certificate
coefficient basis and limb order
explicit field/tower/version tags
fixed-width unsigned little-endian base-limb encoding
exact extension-element byte length
canonical zero and one
multiplication and reduction relation
square relation
prover-supplied inverse-hint verification relation
Frobenius/conjugation and every field-embedding map if used
Circle equation, domain field, subgroup/coset conditions, order, generator,
affine/projective representation, and point encoding
challenge domain tags, rejection sampler, statistical distance, retry cap,
and fail-closed behavior
maximum intermediate magnitudes and reduction schedule
raw cardinality worksheet and the exact soundness event nodes which consume it
```

No host-side normalization may occur before VM execution. Each base limb must
arrive as its exact fixed-width payload, be length-checked, receive an exact
zero sign byte synthesized by Script, be converted with `OP_BIN2NUM`, and be
range-checked against `p`. Unused high bits are zero. The synthesized guard is
verifier work; it is not an extra proof byte. Each extension limb is decoded
independently in declared coefficient order `c_0..c_(d-1)`. Truncation,
suffixes, omitted zero coefficients, out-of-range values, sign aliases, swapped
limbs, alternate tower order, and trailing bytes reject. Fixed-width wire
values remain distinct from minimally encoded signed-magnitude Script
arithmetic values.

## Algebra certificates

### Base primality

For a Mersenne candidate, retain the exponent-primality check and the complete
deterministic Lucas-Lehmer result under a content-pinned reference
implementation. Recompute it independently before promotion and retain exact
commands, versions, outputs, and artifact digests.

### Direct extension polynomial

For monic `f` of degree `d` over `F_p`, retain a Rabin certificate:

```text
h_0 = X
h_i = h_(i-1)^p mod f, for i = 1..d
require h_d = X
for every prime r dividing d:
  g_r = h_(d/r) - X
  require gcd(f, g_r) = 1
  retain u_r, v_r with u_r*f + v_r*g_r = 1
```

The repository checker and an independent CAS/toolchain must agree, with exact
commands, versions, outputs, and content digests. Ephemeral searches or an
attractive sparse reduction polynomial are not evidence.

The current generic fixtures are an earlier checkpoint, not satisfaction of
that gate. Independent Node and Python repository implementations now replay
the Mersenne checks for q=13,17,19,29,31,61,89,107,127 (with q=29 correctly
rejected) and the Rabin/Bezout certificate for `X^2+1` over M89. Both fixtures
remain `generic-math-unqualified`, `not-cas-reviewed`, `not-evidence`, and
`selection: none`. Candidate activation still requires an independent CAS or
equivalently reviewed external checker.

### Tower extension

Every tower step must separately prove that its defining element is a
non-square, non-cube, or otherwise satisfies the applicable irreducibility
criterion in the exact parent field. The final flattened polynomial, basis
mapping, multiplication relation, and encoding must agree with the tower
implementation.

On chain, inversion is never computed by an extended Euclidean algorithm. The
prover supplies a canonical hint `H`, and Script verifies `A * H = 1` in the
selected extension. Zero and malformed hints reject.

## Fair staged experiment

Escalation is strictly ordered:

1. complete the typed role, embedding, and DEEP-strategy descriptor;
2. pass the prime, domain-order, and provisional soundness upper-bound screen;
3. pass both irreducibility-certificate implementations;
4. pass the canonical codec and every alias/boundary mutation;
5. pass generic reference arithmetic, KATs, and metamorphic relations;
6. pass equal-relation Libauth and BCHN kernels, with LeanBCH support or lack of
   support recorded explicitly; unsupported coverage is never a pass; and
7. retain a measured Pareto set, eliminating only for mathematical invalidity,
   canonicality disagreement, VM/standardness failure, proved
   soundness/domain impossibility, or measured dominance under the same
   relation and security contract.

### Gate A — analytical elimination

For every frontier row, record:

- exact maximum base and extension Circle orders, while keeping the base
  evaluation domain distinct from extension challenge fields;
- exact subgroup/coset, AIR-degree, trace-length, and blowup conditions rather
  than treating `p+1` as a domain-feasibility proof;
- raw element and operation-witness bytes;
- schoolbook and optimized multiplication counts without calling them VM
  costs;
- maximum intermediates under the proposed reduction schedule; and
- a discrete, event-DAG 128-bit soundness feasibility worksheet.

This gate may kill a candidate. It cannot qualify one.

### Gate B0a — exact algebra-component admission

Gate B is split so arithmetic can be falsified before a complete proof tuple is
chosen. B0 is strictly component-only: it cannot assign a protocol role, Circle
domain, DEEP field, transcript sampler, hash, soundness event, or tuple.

Before any candidate-specific arithmetic runs, freeze an additive descriptor
which binds the exact modulus, polynomial or typed tower, basis, limb order,
codec, arithmetic formulas, stage-by-stage intermediate bounds, current BCH
execution profile, repository certificate replay, independent external checker,
source artifacts, and the common campaign. Every path and digest is resolved
from bytes. Both checkers must consume the same canonical certificate.

The first admitted descriptor is M89 degree 2 with `X^2+1`. Its pinned SymPy
1.14 replay independently confirms the Mersenne prime using Lucas--Lehmer and
confirms irreducibility using direct polynomial analysis, factorization, and the
Legendre criterion. This admits only a non-ranking arithmetic experiment. It is
not a field, Circle-domain, or protocol selection.

### Gate B0b — equal base and extension kernels

For every admitted construction, run the same semantic corpus through the
native reference, standard Libauth, the real unmodified BCHN Script leg, and
LeanBCH wherever supported:

- canonical decode/encode;
- add, subtract, negate, multiply, square, and equality;
- the identical high-level relations `E-MAC: D=A*B+C`,
  `E-SQUARE-MAC: D=A^2+C`, and
  `E-INVERSE-CHECK: A!=0 and A*H=1`;
- boundary, random, metamorphic, and every-limb malformed mutations; and
- exact locking/unlocking bytes, opcode histogram, MUL/DIV/MOD
  operand-byte-product total, result-push bytes, VM/op cost, stack maxima,
  element maxima, applicable limits, and headroom.

Use the same deterministic seed, case counts, corpus categories, parser duties,
and adversarial mutation families. Numeric elements need not be identical
across different fields, but their semantic role and boundary category must be.
The immutable machine-checkable contract at
`p2/gate-b/equal-relation-experiment.v1.json` freezes the seed
`0123456789abcdef`, engine policies, metric vector, empty artifact slots, and
the original pre-execution blockers. The additive B0 campaign freezes exact
case-count formulas, generator framing, relation/category/mutation order, the
four-candidate comparison cohort, schoolbook and optimized tracks, and
counterbalanced run order. M89 may run alone first only as a non-ranking harness
shakedown. Any harness change after inspecting that result requires the full
M31-d5, M31-d6, M61-d3, and M89-d2 cohort to be rerun in one campaign epoch.

BCH arithmetic cost must be measured. Fewer limbs and wider operands are a
real tradeoff because current `OP_MUL`, `OP_DIV`, and `OP_MOD` charge a
quadratic operand-byte component and result pushes add cost. Other arithmetic
operations do not automatically receive that byte-product charge. Payload
bytes or base-multiplication counts alone do not rank candidates. For a
schoolbook `d`-limb extension with `B`-byte limbs, the leading product term is
approximately `d^2*B^2=(d*B)^2`; equal 24-byte payloads can therefore begin
near the same leading term and diverge through reductions, Karatsuba/tower
formulas, intermediate widths, stack traffic, and runtime paths. B0 results may
kill an algebra or implementation. They cannot rank fields for protocol use
without a shared complete operation mix and security contract.

### Gate B1 — complete typed protocol descriptor

After the full B0 cohort and root/SOL review, freeze the first complete typed
protocol candidates. Each must name `B`, `D`, `E`, `F_batch`, `F_fri`,
`F_deep`, `Q_deep`, `F_hash`, and `H_outer`; every equality and embedding;
the exact Circle equation, group/coset, order, generator, trace length, blowup,
and point codec; AIR degrees and opportunity counts; witness masking and degree
effects; DEEP quotient and denominator exclusions; transcript schedule and
domain tags; each rejection sampler and retry bound; FRI rate, fold, query,
grinding, and final schedule; and the dependency-aware systemic soundness DAG.

No candidate-specific Circle, DEEP, sampler, FRI, or query implementation may
start from a B0 algebra descriptor alone.

### Gate C — Circle and one complete query

Only after Gate B1, freeze and measure:

- on-circle, subgroup, generator, doubling, inverse/J-twin, and encoding
  relations;
- a domain of the exact proposed size with duplicate, off-circle,
  wrong-subgroup, and wrong-coset mutations;
- one fold at each surviving arity;
- the exact transcript and Merkle roles; and
- one transcript-derived complete query packaged in its proposed BCH carrier
  role.

Every comparison uses the same `PoolActionFv1` semantics, AIR, topology, and a
concretely derived systemic target of at least 128 bits. Parameters are tuned
independently where the soundness model requires them; the resulting proof and
complete-transaction consequences must be recorded.

## Representation freeze outcome

The old 33-row `circle-fri-candidate-matrix.v1.json` remains an immutable
legacy component catalogue. It is not a complete-candidate model. The additive
v2 prequalification registry content-pins v1, registers the M13/M17/M19 narrow
controls, M31/M61/M89 arithmetic frontier, M107/M127 escalators, and invalid
M29 control, and assigns the measured M31 base corpus to no field role or
tuple. Exact q, degree, limb width, raw width, legacy mapping, certificate
coverage, source path/kind/role, and nonqualification labels are fail-closed.

`circle-fri-candidate-matrix.v2.schema.json` is deliberately incapable of
representing a complete tuple or any Circle, DEEP, hash, outer-channel, or
embedding descriptor: every composition array is schema-locked empty. This
closes the red-team path in which a shallow descriptor could appear frozen.
The additive B0 descriptor schema deliberately freezes only arithmetic and
fails closed on tuple, role, Circle, DEEP, hash, sampler, and soundness fields.
Before the first real tuple exists, a separate additive B1 schema must encode
the complete canonical candidate record above and resolve every referenced
certificate and source artifact. Neither v2 nor B0 can qualify or select
anything.

`soundness-worksheet.v2.schema.json` is likewise explicitly
`prequalification-only`. It replaces the legacy fixed buckets with
unique bad-event and opportunity identities, an acyclic dependency graph,
exact rational bounds, and a recomputed systemic union. Raw field cardinality
is not an event kind. Ancestor/descendant double counting, duplicate sampler
ownership (including derivation nodes), and non-unit undecomposed multiplicity
reject in conformance tests. The v2 language cannot express `128-bit-pass`, and
the root validator rejects any unintegrated v2 worksheet instance. A future
qualification revision must resolve source commits, candidate/proof artifacts,
measurements, raw transactions, and standardness evidence from content rather
than trusting self-declared references.

The following remain hard pre-measurement gates rather than representation
ambiguities:

- every activated family needs an exact polynomial or tower, encoding,
  embeddings, domain, sampler, and certificate bundle;
- every active kill gate needs a deterministic command, artifact schema, exact
  threshold, and metric vector; qualitative v1 text is legacy context only;
- the exact current Circle-STARK paper bytes must be locally replayable before
  a construction claim is promoted; the v1 digest alone is not a local
  artifact; and
- a repository checker plus an independent implementation may be built now,
  but the certificate gate remains blocked until an independent CAS or
  equivalently reviewed external checker is available.

## Selection rule

No scalar score selects the field. Retain the measured non-dominated frontier
across:

- systemic soundness and ZK validity;
- complete deposit and withdrawal transaction bytes;
- BCH VM/op/hash/stack headroom;
- desktop prover median, p95, RSS, and effective core use;
- implementation/formal-assurance burden; and
- component-specific classical and PQ assumptions.

Security and accepted-language correctness dominate speed and bytes. Field
selection remains closed until a root/SOL review of Gate B and Gate C evidence.

## Stop conditions

Stop the affected candidate if any of these occurs:

- the polynomial/tower or its encoding is ambiguous or uncertified;
- raw field capacity is presented as systemic soundness;
- base-field and extension-field Circle orders are conflated;
- the proof is host-normalized before Script sees malformed bytes;
- engines disagree on acceptance, value, or supported metrics;
- a projected cost is presented as measured BCH evidence;
- the exact AIR/domain lower bound cannot fit the candidate subgroup/coset and
  degree conditions;
- zero knowledge is deferred until after proof sizing; or
- component success is promoted without complete-transaction evidence.
