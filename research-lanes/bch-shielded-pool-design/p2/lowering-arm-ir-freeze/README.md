# Lowering-arm IR freeze package

This directory freezes the complete pre-source authority for the four direct
extension-field constructions. It deterministically regenerates and validates
14 ordered arithmetic arms, 28 typed SSA programs, 19 parser/wrapper modules,
and 42 relation-specific symbolic stack plans. The compact root artifact binds
the full regenerated authority by domain-separated digests; it does not commit
the roughly 30 MB repeated trace serialization.

`lowering-arm-ir-freeze.v1.json` is valid only with its strict schema, exact
raw-file pins, frozen upstream artifacts, Node runtime binding, compact ordered
indexes, complete-authority roots, `MANIFEST.json`, and `SHA256SUMS`. Parser
invocations are identified by `(planId, invocationId)` because bare invocation
IDs are deliberately plan-local. The base Git commit is provenance only: the
authority was generated from a dirty, untracked worktree, so exact raw-file
digests—not a false clean-commit claim—bind the source bytes.

The digest contract is acyclic. Package object digests hash
`UTF8(domain) || 0x00 || canonical-sorted-JSON-UTF8`; raw file digests hash
exact bytes. `MANIFEST.json` covers every package payload file except itself and
`SHA256SUMS`; `SHA256SUMS` additionally covers `MANIFEST.json` and excludes
itself.

This is host-validated, pre-execution IR—not execution evidence. It contains no
BCH source/bytecode or BCH-VM-exact stack proof, and makes no byte/cost/limit,
campaign, ranking, field/Circle/query/protocol-selection, soundness, ZK, PQ,
transaction-fit, prover-time, qualification, or release claim. Source emission
remains closed in this artifact; the lane may open a separate mechanical
emission step only after validating this exact content digest. VM execution,
measurement, campaign evidence, ranking, and selection remain later gates.
