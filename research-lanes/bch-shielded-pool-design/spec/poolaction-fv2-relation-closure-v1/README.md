# PoolActionFv2 relation-closure package v1

Status: `SUPERSEDED_UNQUALIFIED_FAILED_ROUTE`

> This package is retained only as failed-route and mutation-control evidence.
> It is not normative, has no current implementation authority, and receives
> zero Hard-Gate-1 closure credit. The active charter is
> [`../poolaction-fv2-relation-closure-charter-v2.md`](../poolaction-fv2-relation-closure-charter-v2.md).
> The v2 package must be validated independently against that charter.

This was drafted as an additive relation package for `PoolActionFv2`, relation
version `2`. It did not close the Fv1 interface contradictions and is not a
proof-suite selection, BCH execution result, or deployment artifact.

The package is deliberately fail-closed.  `proofSuiteStatus` is fixed to
`UNSELECTED` and the only permitted proof-boundary result is
`REJECT_UNSELECTED_PROOF_SUITE`.  A caller may provide displayed digest values,
but `validate.mjs` recomputes every displayed value from raw inputs and rejects
a mismatch; no supplied digest or session fact is authoritative.

## Files

- `schemas/` contains closed Draft 2020-12 schemas for the relation input,
  authenticated transaction view, proof-session envelope, provenance DAG, and
  verifier-role consumption matrix.
- `normative/` contains the frozen outer relation, binding rules, and role
  matrix.
- `validate.mjs` is a dependency-light static validator and recomputer.
- `validate.test.mjs` executes schema, canonical-byte, and mutation controls.

Run:

```sh
node --test research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-v1/validate.test.mjs
node research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-v1/validate.mjs --self-check
```

## Explicit boundary

The schema records required `currentBchIntrospection` bindings but does not
assert that they are available in a current BCH VM.  That decision, concrete
locking-bytecode derivation, materialized transaction fixture, independent
recomputer, falsifier corpus, and every proof-suite parameter remain outside
this artifact.  Consequently, the package may receive only artifact-2
structural credit and remains `HOLD` for Hard Gate 1.
