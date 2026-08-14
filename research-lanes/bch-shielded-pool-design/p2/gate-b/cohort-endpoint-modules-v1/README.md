# Cohort endpoint modules v1

This additive package freezes the two package-local Node module endpoints for
the fixed Circle-FRI four-engine cohort: Native and Libauth. It is static
research machinery, not a runner, orchestrator, authorization writer, or
evidence record. `executionAllowed` and `semanticExecutionPerformed` are both
false everywhere in its authority root.

`endpoints/native-endpoint.mjs` contains a provenance-normalized 5,055-byte
frozen Native kernel (one export/name normalization), followed by a closed
WorkerRow admission wrapper with no module edges. `endpoints/libauth-endpoint.mjs` begins with the exact
593,066-byte materialized Libauth bundle (`ffbee87e074d6df03a03a2068a8f77fe6776f8139cd9bd2cb5e3ac70091bf68f`), then appends the closed WorkerRow controller. That controller decodes the bound fixture authentication program, instantiates standard BCH2026, calls `vm.evaluate`, then calls `vm.stateSuccess`. It contains no `vm.verify` path.

The endpoint ABI, strict LF-NDJSON parser/output contract, empty external stdin
digest, 4,608-row cardinality, empty-success-stderr rule, 600,000 ms monotonic
deadline, and 128 MiB future combined-output cap are descriptive static
contracts only. A future private controller admits each row through its
non-cloneable `AdmittedDispatch`/WeakSet handle, rehashes each WorkerRow copy,
and then serializes only this package's exact clone-safe projection; a brand
must not transit structured clone and no endpoint claims to enforce that
private provenance. This package cannot start that worker.

All package inputs are regular, single-link, read-only files in read-only
directories. `semantic-validator.mjs`, `materialize.mjs --check`, and the KATs
only parse text/JSON and inspect bytes, modes, hashes, and links. They never
import an endpoint, execute a VM, start BCHN/Lean, or emit evidence.

The validator first accepts only a finite reviewed-byte authority: the exact
Native module/kernel/controller suffix and exact Libauth module/bundle-prefix/
controller suffix are immutable byte-length/SHA-256 pins. The embedded closed
controller grammar is defense in depth over those reviewed bytes, not a proof
for arbitrary JavaScript. It rejects computed/template controller properties,
sensitive string literals, reflection APIs, and WorkerRow authority fields,
then proves the direct, unconditional Libauth path from fixture decode through
`vm.evaluate(program)` and `vm.stateSuccess(state)` into the returned verdict.
It accepts no `vm.verify`, dead-code token stand-in, host capability, or
additional VM path.

The authority envelope is acyclic: the root binds the raw/content identities of
`MANIFEST.json`, `SHA256SUMS`, `semantic-validator.mjs`, both endpoint
descriptors/modules/controllers, and the manifest roster digest. To avoid a
reverse self-hash edge, MANIFEST excludes the root, itself, and SHA256SUMS;
SHA256SUMS covers MANIFEST plus that manifest roster, while excluding the root
and itself. The root content digest covers that closure instead. Any closure
update changes the root digest; a validator-byte update is therefore an
externally reviewable root/manifest change, not self-authorized behavior.
