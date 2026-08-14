# Architecture evidence-plan review — 2026-08-14

## Outcome

`PASS_STATIC_PLAN_READINESS_HOLD_EXECUTION_SELECTION_AND_QUALIFICATION`

The immediate-phase evidence plan is suitable as a non-authorizing planning
baseline. It is not coverage-complete and cannot authorize candidate execution,
selection, or a full prover. Hard Gates 1 and 5 remain blocked by four retained
PoolActionFv1 contradictions. The honest next relation identity is
`PoolActionFv2`, not an in-place Fv1 refreeze.

No field, extension, Circle domain, proof hash, masking construction, AIR, FRI
schedule, soundness parameter, carrier count, or proof tuple is selected by this
review.

## Evidence reviewed

- Frozen product profile and lane authority inputs.
- PoolActionFv1 relation, transaction binding, responsibility map, threat model,
  mutation index, P0 freeze, contradiction capsule, blocked refreeze disposition,
  and zero-state measurement admission.
- P1 codecs, injected-fact relation oracle, and proof-free transaction shells.
- Candidate matrix v1 and tuple-incapable component registry v2.
- Primitive microbenchmark plan, measurement schema, planned 79-case corpus,
  soundness prequalification schema, and current phase plan.
- Sealed Gate-B0 plan and later static authority-language packages as planning
  evidence only.

Independent read-only audits agreed that:

- all four blocker dispositions are `OPEN_BLOCKED`;
- materialized relation-closure falsifiers are `0`;
- measurement admission is `0`;
- candidate matrix v1 has 33 component rows with cheap gates;
- candidate registry v2 cannot represent a complete tuple;
- all 79 PoolAction vector cases are planned rather than materialized; and
- no Circle-domain, transcript, DEEP, FRI, masking, complete-query, complete
  transaction, soundness, or desktop-prover evidence is admitted.

## Immediate-phase coverage

| Deliverable | Verdict | Evidence gap / next kill gate |
| --- | --- | --- |
| Exact relation and threat model | HOLD | Four retained contradictions; pivot to Fv2 and materialize closure evidence. |
| Candidate matrix | PARTIAL | Component taxonomy exists; complete tuple composition is schema-inexpressible. |
| BCH primitive microbenchmarks | PARTIAL | M31 base control only; no Circle/transcript/Merkle/DEEP/FRI complete query. |
| Measurement schema and adversarial corpus | PARTIAL | Schema omits composed security/ZK/session/corpus bindings; 79 cases have no bytes/results. |
| Cheap kill gate per candidate | PARTIAL | v1 prose gates exist; typed B0 gates remain pending and cannot execute. |
| Phased disjoint work plan | PASS AS PLAN | Must now route work to Fv2 closure, not more authority scaffolding. |

## Hard-gate state

1. Responsibility-complete relation/threat model: **HOLD**.
2. Concrete Circle-FRI soundness: **missing**.
3. Masking/ZK leakage: **missing**.
4. Canonical proof/field/transcript/parser encodings: **partial controls only**.
5. Exact transaction-context binding: **HOLD**.
6. Complete transaction bytes: **missing**.
7. Current unmodified BCHN/Libauth acceptance: **missing**.
8. VM/opcode/hash/stack/carrier budgets: **component controls only**.
9. Valid and adversarial transaction corpora: **planned only**.
10. Desktop proof timing/RSS/failures: **missing**.
11. LeanBCH cross-check: **M31 component control only**.
12. Exact provenance/logs: **partial and currently stale in two evidence tracks**.

The 100-bit fallback remains closed because no optimized complete 128-bit
deposit and withdrawal have been measured and failed the 100,000-byte limit.

## Validation commands and observations

Passing focused checks:

```sh
npm run lane:shielded-pool:p1:test
# 23/23 passed

node research-lanes/bch-shielded-pool-design/research/candidate-composition.test.mjs
# 11/11 passed; confirms v2 is tuple-incapable by construction
```

The authoritative integration validator currently exits `1`:

```sh
node research-lanes/bch-shielded-pool-design/validate.mjs
```

Observed failures:

1. `cohort-freeze-v2` generated engine, epoch, manifest, and checksum bytes no
   longer reproduce the tracked authority snapshot.
2. The cohort semantic-population check aborts after that drift, although
   in-memory generation still returns 4 constructions, 14 arms, 42 plans,
   1,288 corpus cases, 4,732 unique fixtures, 18,928 work items, and 124 limit
   violations.
3. Both M31 source manifests pin the ShieldKit-LABS root at commit
   `8e55004e6be0c76bb6aa8aba4d9edbadf2c767f0`, while current HEAD is
   `c92e1f81176f6d196410e70564c50c2bdbd02cb9`.

These are current-provenance failures, not new measurements. The historical
packages must be preserved. A future cohort refresh must regenerate the whole
package atomically. M31 provenance must be versioned and the measurement rerun;
changing only the commit string would misrepresent old evidence.

## Architecture decision

The four contradictions change accepted-language and public/witness semantics,
so they require `PoolActionFv2`. Network-enum narrowing alone is not the reason
for the pivot. Fv2 freezes only relation-layer structure now:

- exact networks `mainnet`, `chipnet`, and `regtest`;
- mutable zero-fungible state NFT with a 128-byte commitment;
- token-free verifier carriers;
- SHA-256 outer context/envelope/session binding, explicitly separate from the
  future proof transcript;
- one typed proof-suite manifest digest with no assigned proof parameters;
- a fully consumed canonical transaction view and proof-session envelope; and
- deterministic acyclic normalized-template to concrete-lock/genesis provenance.

The normative decision and closure gate are recorded in
`spec/poolaction-fv2-relation-closure-charter-v1.md`.

## Eliminations and preserved controls

- In-place Fv1 refreeze: **eliminated**, because it would hide an
  accepted-language change.
- Further Gate-B0 authority scaffolding as the next phase: **eliminated**, because
  it does not close a relation responsibility or produce evidence.
- Carrier token presence: **eliminated for Fv2**, because the state NFT already
  supplies unique mutable state and no frozen product requirement needs another
  token.
- Injected context/session facts: **eliminated** as authoritative inputs.
- Existing killed candidate rows remain killed for their recorded reasons; no
  surviving cryptographic candidate is ranked or selected here.

## Next bounded phase

Implement only the five Fv2 closure artifacts named by the charter:

1. closed normative schemas and role-consumption map;
2. nonempty raw transaction/envelope/template/lock/genesis fixtures;
3. two correctness-independent recomputers;
4. all 57 retained falsifier families as executable stable cases; and
5. independently reproduced results plus a root/SOL gate decision.

Work must remain disjoint and no structural fixture may reach proof acceptance
while the proof suite is unselected. BCH execution, candidate measurements,
tuple selection, soundness qualification, and the full prover remain closed.

## SOL review

SOL review was required for this version boundary and completed with a bounded
implementation PASS. A new independent SOL review is mandatory after the full
falsifier report and before Fv2 refreeze or Hard Gate 5 authorization.

