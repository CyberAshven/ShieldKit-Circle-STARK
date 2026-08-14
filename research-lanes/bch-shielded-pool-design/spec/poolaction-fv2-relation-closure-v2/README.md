# PoolActionFv2 relation-closure package v2

Status: `NORMATIVE_ABI_EVIDENCE_ONLY_PROOF_REJECTED`.

This package implements the bounded ABI authorized by
[`poolaction-fv2-relation-closure-charter-v2.md`](../poolaction-fv2-relation-closure-charter-v2.md).
It supersedes the unqualified v1 draft without altering it.  It provides a
binary relation encoding, field-source contract, closed JSON evidence
interchange schemas, structural fixtures, and static checks.

It does **not** select a proof suite, prove a statement, execute BCH, measure
anything, construct a deployment, qualify a candidate, or authorize an
activation.  Every fixture is structurally well-formed but terminates at
`REJECT_UNSELECTED_PROOF_SUITE`.

JSON is evidence interchange only.  It is never a runtime hash preimage.  The
runtime byte preimages are specified in [binary-codec-v2.md](binary-codec-v2.md)
and rebuilt by `validate.mjs`.

## Package checks

```sh
node --test research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-v2/validate.test.mjs
node research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-v2/validate.mjs --self-check
(cd research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-v2 && sha256sum -c SHA256SUMS)
```

The static checks reject, among other things, dynamic network identity in a
transaction view, a shared `activeInputIndex`, arbitrary token records,
singular carrier slots, caller-supplied digest/provenance relation inputs,
unconsumed carrier bytes, and acceptance under an unselected suite.

## Gate position

This package may support only an internally consistent normative-v2 artifact.
Hard Gate 1 remains `HOLD` pending the separately required independent
recomputers, materialized falsifier corpus, current-BCH execution evidence,
proof-suite selection/verification, and independent review.
