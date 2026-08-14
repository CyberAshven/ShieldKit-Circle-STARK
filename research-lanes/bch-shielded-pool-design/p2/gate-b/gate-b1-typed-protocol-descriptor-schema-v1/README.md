# gate-b1-typed-protocol-descriptor-schema-v1

Unsealed Gate B1 blocked-v1 schema architecture. It creates no descriptor, candidate, tuple, parameter assignment, proof, transaction, runtime, provider resolution, or qualification path.

The v1 schema retains only identity/digest records, the frozen scope and P0 input observations, pinned source references, non-admitting B0 observations, null review/evidence slots, and the five-leaf fixed-statement codec evidence boundary. That codec source closure is read as raw regular-file bytes and hashes only; it is not imported, evaluated, selected, or allowed to supply a digest adapter. Both adapter roles remain null and `BLOCKED_EXTERNAL`.

All 18 former protocol-language surfaces are exact pending markers with no candidate-admission or qualification effect. `fallbackAuthorization` is exactly `{ "kind": "NONE" }`. The v1 semantic entrypoint verifies this blocked boundary and then fails with `DESCRIPTOR_LANGUAGE_PENDING_ADDITIVE_SCHEMA_VERSION` before registry construction or protocol calculations.

`protocolProjectionDigest` is a nonauthorizing schema-architecture digest: its acyclic flat preimage contains schema/descriptor identity, safe observations, and the ordered marker roster. Its declared included/excluded rosters exactly partition the descriptor top level (plus the synthetic `self` exclusion). It excludes qualification, review/evidence, its own digest, and descriptor-root content. Any admitting language requires a separately authored additive v2 schema; v1 declares only the unresolved full v2 schema identity (`shieldkit-labs/p2/gate-b/gate-b1-typed-protocol-descriptor/v2/typed-protocol-descriptor/v2`, path and raw hash null).

The package is intentionally unsealed. `MANIFEST.json` and `SHA256SUMS` must remain absent.
