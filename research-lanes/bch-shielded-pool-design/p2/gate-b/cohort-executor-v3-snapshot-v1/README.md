# Cohort executor v3 retained-byte snapshot v1

This additive package opens the frozen Gate-B authority graph before claim
creation and hands pure code canonical byte records. It derives all 4,732
fixtures, 4,608 eligible rows per engine, and the five fixed endpoint codecs
without pathname reads in the pure dataflow. Capture checkpoint and endpoint
validation in this package is structural only; it is not observation
provenance and does not mint a capture token. A future live executor owns that
receipt/brand at the point where descriptor-backed capture is actually made.

`snapshot-open.mjs` is the only filesystem boundary and a safe façade over the
module-local production trust boundary in `production-api.mjs`. The latter
owns the live `/proc/self/exe` and authority brands; no attestation writer is
exported. `snapshot-pure.mjs` has no filesystem, child-process, VM, or path
APIs. This package does not execute engines, create authorization or claims,
build evidence payloads, or perform the 26-payload success KAT.

Each retained record carries canonical retained bytes, raw-source SHA/length,
all seven fstat fields (`dev`, `ino`, `mode`, `uid`, `gid`, `nlink`, `size`),
and exact SHA-256/canonicalization/frame/domain metadata. The six authority
values are parsed from those records; their values-root digest is included in
the authority snapshot digest. The retained authority catalog is opened once,
pinned to its sealed raw SHA-256/byte length and content digest, and joins
every frozen value and source plan path/raw SHA/length before the authority is
branded. Runtime bytes are retained from `/proc/self/exe`
with readlink/realpath identity and an idempotent fstat-bound descriptor receipt;
each live authority consumer positionally rereads and hashes the complete same
descriptor before deriving. Capture structure binds only a supplied snapshot
digest and enforces the fixed five-endpoint matrix, role-bound
stdin/stdout/stderr streams, and strictly increasing decimal monotonic
checkpoints.

Runtime and authority WeakSet membership is created only inside the pre-claim
filesystem opener closure. Closing the retained descriptor is idempotent but
makes the runtime and every authority consumer stale and invalid. The stable
`deriveSnapshotDigestBinding` projection is the downstream binding surface;
it still requires live authority membership. `deriveRecoveryStableProjection`
omits the bare descriptor fd and dynamic open/close receipt history; those
remain private live-state checks. Returned byte buffers are defensive copies;
Buffer contents are mutable, so every public consumer rehashes the complete
authority snapshot synchronously before deriving anything. Mutating a retained
copy fails closed, while mutating a derived stdin/fixture copy is isolated.

Capture checkpoint validation is structural-only and non-authoritative in this
package. Endpoint-kind checkpoints carry canonical `stat:null`; stream-kind
checkpoints join exact stream stat/digest/length. The validator enforces the
fixed endpoint matrix, exact checkpoint event order, and a strict closed
outcome. Observation provenance remains exclusively a future live executor
responsibility.

`node generate.mjs --check` regenerates and compares the authority catalog and
manifest, validates schemas in strict mode, checks safe paths, exact regular
file/directory modes, no links/extras, verifies the complete file/directory
closure, and verifies `SHA256SUMS`.
