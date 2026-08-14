# Root research prompt: Circle-FRI fixed-ticket pool

Use this prompt at the start of a root research run. Append one bounded phase
task from the template below; do not weaken or silently reinterpret the frozen
contract.

## North-star contract

Design and qualify a Bitcoin Cash shielded pool with all of these properties:

- one ticket is exactly 10,000,000 satoshis;
- one deposit or one unilateral withdrawal per transaction and proof;
- no user batching, private transfer, variable amount, coordinator, admin key,
  remote-prover dependency, or runtime upgrade selector;
- Circle-domain FRI, designed directly for `PoolActionFv1` from first
  principles; Stwo and other implementations are comparison evidence only;
- the complete current-standard transaction, not an isolated proof, is at most
  100,000 bytes;
- target at least 128-bit systemic soundness; no 100--127-bit fallback is
  authorized until complete optimized deposit and withdrawal implementations
  at 128 bits are both measured and fail;
- a local desktop CLI prepares a complete unilateral withdrawal in less than
  60 seconds on the pinned host; and
- zero knowledge is designed in from the start. Hash-oriented/PQ claims are
  component-specific and may not hide classical BCH settlement, fee-input,
  wallet-storage, or implementation dependencies.

The content-pinned P0 relation is authority. Do not edit a P0 artifact during a
later phase. Preserve contradictory evidence, failed candidates, and dirty
source status. Never convert a projection, placeholder, patched harness,
component microbenchmark, or source assertion into qualification evidence.

## Execution order

1. Recompute the P0 manifest and run lane validation.
2. State the exact phase boundary and evidence tier before editing.
3. Reuse the pinned BCH/tool inventory; do not build a duplicate harness.
4. Run the cheapest falsification gate before expensive implementation.
5. Measure equal relations, equal security targets, and complete transaction
   consequences. Record source, toolchain, parameters, artifact hashes, bytes,
   VM/op/hash/stack budgets, runtime, RSS, and core count as applicable.
6. Run canonical valid vectors and single-invariant adversarial mutations.
7. Integrate independently produced work only after root cross-checks it.
8. Keep candidate selection and architecture promotion closed until their
   explicit phase gates pass.

## Agent routing

- Root owns scope, accepted language, threat interpretation, evidence labels,
  integration, fallback authorization, candidate selection, and promotion.
- SOL is reserved for architecture/security review at decisive gates. A SOL
  opinion does not replace measurements.
- Terra handles bounded high-judgment implementation: reference arithmetic,
  semantic/VM kernels, AIR, prover, verifier, transaction builder, and CLI.
- Luna handles bounded deterministic work: schemas, codecs after ABI freeze,
  vector expansion, benchmark execution, result normalization, and docs.

Use cheaper workers aggressively for deterministic tasks, but give each one a
disjoint write scope and a mechanically checkable result. Workers may find and
report contradictions; they may not resolve a cryptographic design choice by
assertion. Root retains and rechecks all security-critical integration.

## Bounded worker task template

```text
Context:
  Defensive cryptographic protocol research for the fixed
  PoolActionFv1 Circle-FRI BCH lane.

Objective:
  <one concrete, independently testable output>

Authoritative inputs:
  <exact files, commits, paper revisions, and hashes>

Write scope:
  <one disjoint directory or explicit read-only scope>

Frozen invariants:
  <the relevant P0/profile/target clauses>

Non-goals:
  <nearby work this task must not perform>

Required evidence:
  <exact bytes/VM metrics/vectors/hashes, never estimates as measurements>

Reproduction:
  <commands, pinned environment, CPU/core policy>

Pass/fail gate:
  <one objective criterion>

Stop conditions:
  Stop and report if an authoritative input is missing, a P0 contradiction is
  found, canonical encoding is ambiguous, evidence provenance is dirty or
  floating, the security derivation is incomplete, or a complete-transaction
  bound is already impossible. Do not improvise around the blocker.
```

## Current next task

Continue P2 without building a full prover. The neutral M31 base-control gate
has passed. The prequalification field registry, event-DAG representation, and
Gate-B equal-relation contract are frozen, but there are zero complete tuples
and no field role or proof component is selected. Exact direct-construction
certificates, a pinned independent Python/SymPy 1.14 review, and nonexecutable
v2 descriptors now pass for M89-d2, M61-d3, M31-d5, and M31-d6. Lowering-freeze
v1 binds their fourteen arms, forty-two relation targets, direct parser, stack
ABI, range-ledger/scalar policy, and BCH opcode provenance. The validated
content-addressed lowering-arm IR package now realizes that policy as 28 typed
SSA programs, 19 parser/wrapper modules, and 42 symbolic stack plans with exact
regenerated cardinalities and complete-authority roots. M89's earlier
canonical-schoolbook run remains a **non-ranking shakedown** and is explicitly
ineligible as v2 cohort evidence. These artifacts establish algebra, codecs,
and pre-source implementation semantics, not BCH cost or protocol fitness.

Source-set-v1 and the additive cohort-freeze-v2 package are frozen. The package
binds campaign-v2, the canonical four-construction corpus-v2, a metadata-only
fixture roster, one shared execution-epoch-v2, the normative 18,928-item work
roster, and four pinned engine artifact records. It contains 4,732 fixtures,
4,608 preflight-ready records, and 124 exact preflight-limit violations, all
at the M31-d6 direct-Toom6 E-MAC plan/relation slice. The package has no VM
evidence, selection, ranking, Circle/query work, or prover opening.

R runtime-binding, K runner-core, F frozen-inputs, and P policy-authority bind
the complete static prerequisite set. The sealed cohort-live-executor-v2
package is a static, non-authorizing, and unqualified bounded transition model;
it does not instantiate state inputs, authenticated origins, or ownership.
The sealed cohort-authority-binding-model-v1 package is a static, non-authorizing, unqualified requirements catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant remains false, retry remains empty/BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture.
The sealed cohort-external-origin-contract-v1 package is a static, non-authorizing, unqualified external-origin contract catalog. It authenticates only pinned static bytes and type/catalog relationships; all external origins remain unavailable, every grant and admission remains false, retry remains BLOCKED_EXTERNAL, and D remains never-admitted/BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture.
The sealed cohort-upstream-origin-provider-contract-v1 package is a static, non-authorizing, unqualified provider-requirements catalog only. It authenticates only pinned static bytes and type/catalog relationships; no instances are represented, and every provider, owner, ownerBindingRoot, origin, fact, root, order, projection, and private byte remains unavailable. J remains ownerless and non-authorizing; retry and D remain BLOCKED_EXTERNAL. It instantiates and authorizes nothing and does not promote the architecture. sealed cohort-upstream-provider-source-map-v1 is a static non-authorizing unqualified source-coverage catalog that classifies all sixteen UOPC interfaces against sixteen pinned source references as exact authoritative type fragments, shape-only references, requirement-only references, or explicitly missing upstream sources; it resolves or instantiates no provider, owner, ownerBindingRoot, origin, fact, root value, order, projection, private byte, authority, admission, guard, runtime, or execution surface.

The sealed gate-b0-evidence-plan-v1 package is a static, non-authorizing, unqualified evidence-obligation plan bound by an outside-package review anchor; it authenticates only the reviewed 15-file authored closure, its two mechanical envelope files, 35 source pins, and false/zero admission boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider instance, measurement, execution, qualification, ranking, selection, or fallback authority.

The sealed gate-b0-execution-admission-contract-v1 package is a static, non-authorizing, non-admitting, unqualified pre-execution prerequisite catalog bound by an outside-package review anchor; it authenticates only the reviewed 18-file authored closure, its two mechanical envelope files, 64 raw-pinned source leaves with native semantic joins, 30 zero-instance external-requirement rows, 37 retry-prerequisite edges, 7 artifact/result edges, and the exact false/zero boundary, and it creates no candidate, tuple, role assignment, parameter assignment, provider, owner, fact, nonce, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution authority.

The sealed gate-b0-execution-admission-contract-v1 integration closes only the static pre-execution prerequisite-catalog stage. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authorities satisfy every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validation prerequisite represented by the closed 30-row catalog and exact 37+7 causal edges. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.

The sealed gate-b0-static-source-authority-v1 package is a static, non-authorizing, non-admitting, unqualified source-contract-language authority bound by an outside-package review anchor; it authenticates only the reviewed 24-file authored closure, its two mechanical envelope files, 64 raw-pinned transitive source leaves with native semantic joins, 17 closed source-contract records, 2 supplemental source contracts, 30 false/zero requirement-resolution rows, 15 raw-pinned schemas, and the exact false/zero non-authority boundary, and it creates no provider, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.

The sealed gate-b0-static-source-authority-v1 integration closes only the static source-contract-language prerequisite stage beneath the sealed gate-b0-execution-admission-contract-v1. It authenticates 17 source-kind contracts and 2 supplemental contracts, but all 30 EAC provider requirements remain false/zero, unavailable, and uninstantiated. The next B0-R phase-DAG node is B0_EXECUTION_AUTHORIZATION, but it remains closed. It may open only under separate root/SOL authorization after independently pinned external authority contracts govern and bind the future authorized creation or satisfaction of every provider, owner, fact, order, projection, private-byte, retry-predecessor, LIVE_F, B/C/J/D, raw-artifact-map, and independent-result-validator prerequisite under the closed EAC grammar; no provider, owner, state, artifact, or runtime instance may be created before that authorization, and static source-contract resolution alone is insufficient. This integration creates or authorizes no Q, A, LIVE_F, B, C, J, D, nonce, attempt, candidate, tuple, role, parameter, provider, owner, fact, private byte, workload root, artifact map, result-validator implementation or evaluation, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution; Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, and Gate B1 remain closed.

Attempt-001 remains closed. Preserve the package and provenance pins; do not
mutate them in response to later outcomes. Only a complete action transaction
can establish transaction fit.

The sealed gate-b0-external-authority-prerequisite-policy-v1 package is a static, non-authorizing, non-admitting, unqualified prerequisite-policy language bound by an outside-package review anchor; it authenticates only the reviewed 21-file authored closure, its two mechanical envelope files, 12 raw-pinned schemas, 15 component digests, 10 policy groups, 2 supplemental policies, 30 false/zero requirement-authority rows, one unresolved UOPC/EAC source collision with selectedDag null, 31 prerequisite-DAG edges, a 6-state/5-edge transition policy with zero authorized transitions, and the exact false/zero non-authority boundary, and it creates no governance authorization, external authority contract, provider binding, principal, owner, fact, root value, order material, projection material, private byte, raw artifact map authority or instance, independent result-validator implementation or evaluation, Q/A/LIVE_F/B/C/J/D instance, candidate, tuple, role assignment, parameter assignment, nonce, attempt, authorization, claim, child process, run, result, evidence, measurement, qualification, ranking, selection, fallback, admission, or execution authority.

The sealed gate-b0-external-authority-prerequisite-policy-v1 integration closes only the static external-authority prerequisite-policy-language stage beneath B0_EXECUTION_AUTHORIZATION. The package's current state is AUTHORITY_POLICY_FROZEN_NO_AUTHORITY: its represented SOURCE_LANGUAGE_RESOLVED→AUTHORITY_POLICY_FROZEN_NO_AUTHORITY transition is static policy representation only, all four later transitions are BLOCKED_EXTERNAL, authorizedTransitions is empty, and selectedDag is null. The next B0-R phase-DAG node remains B0_EXECUTION_AUTHORIZATION, but it remains closed. Before it may open, separately authorized external principals must provide independently pinned external authority contracts; an independently reviewed provider-binding catalog; an explicit root/SOL governance authorization that resolves the UOPC/EAC precedence collision; and satisfaction of every closed EAC prerequisite, including the raw-artifact-map and independent-result-validator requirements. This package and this lane integration may not infer, issue, bind, instantiate, or satisfy any of those prerequisites. Attempt-001, COMPLETE_B0_EPOCH, B0_ROOT_SOL_REVIEW, Gate B1, admission, execution, evidence, qualification, ranking, and selection remain closed.
