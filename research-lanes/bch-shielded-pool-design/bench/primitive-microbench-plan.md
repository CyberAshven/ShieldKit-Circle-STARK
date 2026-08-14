# Circle-FRI primitive and compound-query benchmark plan

The benchmark order is a sequence of cheap falsifiers. A component may be
eliminated by a lower bound, but only a complete serialized transaction can
qualify the product.

## Reused infrastructure

- `zk-verifier-surface/tools/measure/measure_kernels.mjs` supplies the artifact
  and kernel-measurement pattern. Its BN254 calibration is not a Circle result.
- `verifier.cash` and the banked `labs/fri-stark-96k` lane supply P2SH32
  packaging, per-input attribution, first-try corpus, and dual-engine patterns.
  Their Goldilocks numbers and relation are controls only.
- LeanBCH supplies independent transaction decoding, VM execution, and exact
  operation-cost cross-checks where its model supports the required opcode and
  transaction context.
- `bch-conformance/legs/bchn` supplies a real BCHN script-engine leg. It does
  not by itself establish full transaction policy or CashToken standardness.
- Planck is available only after a semantic kernel is frozen and differential
  tests prove the optimized replacement equivalent.
- `fri-cage` must wrap memory-heavy prover jobs so an experimental blow-up does
  not destabilize the desktop.

No new generic BCH benchmark framework is authorized. The implementation phase
adds only Circle-specific vectors and thin adapters to these existing tools.

## Recorded limits

Experiments pin `profiles/bch-current-2026-08-08.json`: 100,000 complete
standard transaction bytes, 10,000 bytes per script and current stack element,
1,000 cumulative stack items, 100 conditional levels, 128 native NFT
commitment bytes, and per-input operation-cost budget
`(41 + unlockingBytes) * 800`.

## Tranche 0: codecs and reference arithmetic

Before emitting Script, implement deterministic native known-answer vectors for:

- fixed-width base and extension decoding, rejecting every value `>= p`;
- add, subtract, negate, multiply, square, inverse, inverse-hint verification,
  division-by-zero rejection, and maximum-limb boundaries;
- extension-tower basis ordering, irreducibility evidence, Frobenius where used,
  and alternate-limb rejection;
- Circle point encoding, on-circle and subgroup checks, identity, negation,
  addition, doubling, generator order, and off-circle rejection; and
- `PoolStateFv1`, `TxContextFv1`, and statement round trips with no suffix or
  byte-order alias.

Kill a field/tower/domain on any disagreement, overflow ambiguity, duplicate
point, unintended vanishing zero, x-fiber selector alias, or noncanonical
acceptance.

## Tranche 1: isolated BCH kernels

Every vector records exact locking and unlocking bytes, inputs/outputs, VM
result, evaluated instructions, signature checks, hash digest iterations,
arithmetic cost, pushed stack bytes, total operation cost, primary/alt/function
stack maxima where supported, and artifact/source/toolchain digests.

Required kernels:

```text
field-decode / extension-decode / point-decode
base add / sub / negate / multiply / square / inverse-check
extension add / multiply / square / inverse-check
circle add / double / rotate / J-twin / subgroup check
Circle FFT butterfly / batch-inversion verification
SHA-256 / HASH256 over 20, 32, 64, 128, and 256 bytes
candidate algebraic permutation, leaf hash, and internal-node hash
transcript tagged absorb / squeeze / rejection-sampled challenge
Merkle authentication step and complete path
binary / arity-4 / arity-8 FRI fold
final-polynomial or terminal-codeword check
state, payout, fee, source, token, and carrier introspection bindings
```

Isolated arithmetic sums are diagnostic, not a compound verifier projection.
Compiler scheduling, stack movement, hashing, parsing, and introspection interact.

## Tranche 2: exact empty-shell transactions

For each carrier count under consideration, serialize deposit and withdrawal
transactions with the exact state source/successor, persistent carrier
sources/successors, one external funding input, withdrawal payout, and optional
transparent change. Use canonical placeholder lengths only for proof sections,
then report those placeholders separately from measured bytes.

Kill a topology which:

- requires an extra transaction per action or a finite carrier stock;
- cannot bind every role and exact successor;
- violates any per-input limit before proof verification;
- leaves no defensible room for a 128-bit proof lower bound; or
- counts an estimated shell as complete transaction evidence.

## Tranche 3: one complete query

The first compound proof kernel is one real transcript-derived query including:

1. canonical proof/session header parsing;
2. public statement and context binding;
3. commitment-root absorption and challenge derivation;
4. one canonical Merkle path or multiproof;
5. one Circle-FRI fold for the selected arity;
6. required DEEP/composition checks for that query;
7. terminal/final-polynomial contribution; and
8. exact carrier role and successor binding.

Package the kernel in the actual proposed P2SH32 role and run Libauth plus
LeanBCH. Add the BCHN leg when the fixture format is available. Kill candidates
whose deployed compound cost contradicts the earlier lower bound or whose
cross-engine results differ.

## Tranche 4: prover-dominant kernels

On `profile:desktop-prover-i9-13900h-2026-08-08`, measure native field/tower
throughput, Circle FFT, candidate hash/permutation, Merkle construction, trace
generation, masking, and FRI folding. Use all 20 online logical CPUs and record
effective concurrency. These measurements can eliminate an obviously
impossible candidate; they cannot establish the under-60-second complete
withdrawal gate.

## Evidence and escalation

All output conforms to `primitive-microbench.schema.json` or
`evidence/measurement.schema.json`. Each candidate-matrix row owns one cheap
kill gate. Root reviews results after Tranche 1 and after the first compound
query. No field, hash, masking, AIR, or FRI profile is selected until the
soundness and ZK worksheets are complete and the measured non-dominated set is
reviewed by SOL.
