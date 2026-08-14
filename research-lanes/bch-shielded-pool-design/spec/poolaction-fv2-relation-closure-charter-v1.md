# PoolActionFv2 relation-closure charter v1

Status: `SUPERSEDED_UNQUALIFIED_FAILED_ROUTE`

> This document is retained only as contradictory predecessor evidence. It has
> no current implementation authority and receives zero Hard-Gate-1 closure
> credit. The active ABI charter is
> [`poolaction-fv2-relation-closure-charter-v2.md`](./poolaction-fv2-relation-closure-charter-v2.md).
> Nothing below may override or supplement that charter.

Historical status at the time this failed route was drafted:
`AUTHORIZED_BOUNDED_CLOSURE_IMPLEMENTATION_NO_REFREEZE`.

This charter authorizes only the minimum architecture and evidence work needed
to close the four retained PoolActionFv1 contradictions. It authorizes no proof
suite, candidate tuple, measurement, BCH execution, deployment, qualification,
selection, fallback, or full prover.

## Version boundary

The new relation identity is:

```text
relationId      = PoolActionFv2
relationVersion = 2
```

PoolActionFv1 remains immutable historical evidence. Its codecs, injected-fact
oracle, and proof-free shells remain useful as lower-bound and mutation
controls, but they cannot receive Fv2 closure credit. The Circle-FRI candidate
matrix v2 is a different namespace and is not PoolActionFv2.

The version pivot is mandatory because authenticating a recomputed transaction
view, raw proof-session bytes, and concrete-lock provenance changes the
accepted language and public/witness semantics. Network-enum narrowing alone
would not justify silently changing the relation.

## Frozen product inheritance

Fv2 inherits without change:

- one fixed `10,000,000` satoshi ticket;
- exactly one deposit transaction and one unilateral withdrawal transaction per
  ticket;
- a separate transparent input funds fees;
- no user batching, private transfers, change notes, required coordinator,
  privileged path, or runtime proof-suite selector;
- one complete current-standard BCH transaction per action, at most `100,000`
  bytes;
- target 128-bit soundness, with the existing measured-failure-only fallback;
- complete desktop withdrawal proving below 60 seconds; and
- Circle-domain FRI designed for BCH without a generic prover-stack dependency.

## Four retained predecessor contradictions

Fv2 must close, rather than overwrite, these retained blockers:

1. `P0-NETWORK-SCHEMA-CODEC-DRIFT`
2. `P1-CONTEXT-DIGEST-FACT-INJECTION`
3. `P1-CARRIER-LOCK-ANCHOR-ERASURE`
4. `P1-PROOF-SESSION-CONTEXT-ERASURE`

The authoritative predecessor evidence remains under
`evidence/poolactionfv1-contradiction-capture-v1/` and
`spec/poolaction-relation-disposition-refreeze-v2/`. No Fv2 artifact may amend
those historical records.

## Structural bindings frozen now

### Networks

The complete ordered network vocabulary is:

```json
["mainnet", "chipnet", "regtest"]
```

Matching is exact lowercase ASCII. Empty values, aliases, case variants, and
all other strings reject. A deployment selects exactly one member and every
relation role authenticates it.

### Token roles

- State source and successor: mutable NFT, fungible amount `0`, commitment
  exactly 128 bytes, unchanged category and capability.
- Every verifier carrier: no token record (`NONE`).
- Withdrawal payout, transparent funding, and optional transparent change:
  token-free as already required by the frozen product.

The 128-byte bound is source-derived from
`MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12 = 128` in BCHN source commit
`864c53ee34924cca6c6b6d96607ff2cedcdccf02`; it is not a remembered or
project-local constant.

Carrier-token presence is a relation error. The state NFT is the unique mutable
state carrier; adding another token would add issuance, conservation,
substitution, and replay responsibilities without a product requirement.

### Proof-suite slot

The relation contains one typed `proofSuiteManifestDigest: bytes32`. It binds a
future, separately reviewed proof-suite manifest. It does not select a base
field, extension, Circle domain, AIR, transcript construction, masking scheme,
FRI fold, blowup, query count, grinding schedule, or final check.

No structurally valid envelope can reach proof acceptance while the referenced
suite is unavailable or unselected.

### Outer binding hash

Fv2 uses SHA-256 for transport and relation binding. This choice is fixed and
is not an agile algorithm slot, a `HASH256` alias, or a selection of the future
Circle-FRI transcript hash.

Let:

```text
LP(x) = u32be(byte_length(x)) || x
```

Then:

```text
contextDigest =
  SHA256(ASCII("PoolActionFv2/context/v1") || 0x00
         || LP(networkId)
         || LP(canonicalAuthenticatedTxView)
         || LP(provenanceRoot))

envelopeRoot =
  SHA256(ASCII("PoolActionFv2/envelope/v1") || 0x00
         || LP(rawEnvelopeBytes))

sessionDigest =
  SHA256(ASCII("PoolActionFv2/session/v1") || 0x00
         || LP(contextDigest)
         || LP(envelopeRoot)
         || LP(sectionScheduleBytes)
         || LP(proofSuiteManifestDigest))
```

No caller-supplied derived digest or session fact is authoritative. A supplied
comparison value is permitted only when the consuming role recomputes the value
from authenticated raw inputs and enforces byte equality.

### Canonical authenticated transaction view

The normative Fv2 package must define one fully consumed canonical encoding of
all relation-relevant current-BCH fields, including:

- transaction version and locktime;
- active input index;
- ordered input outpoints, sequences, roles, authenticated source values,
  complete source locks, and complete source token records;
- ordered output values, complete locks, and complete token records;
- the unique state and carrier predecessor/successor bundle;
- ticket reserve delta, withdrawal payout, fee funding, optional change, and
  fee-policy fields; and
- the one normalized envelope-bearing input slot.

Every field requires a pinned current-BCH introspection mapping. A field that
cannot be authenticated is a blocker; its digest may not be injected. The
envelope slot is normalized in the transaction view to avoid a self-reference,
while the raw envelope bytes are separately bound by `sessionDigest`.

### Proof-session envelope

The normative envelope is versioned and fully consumed. It contains a canonical
section directory with exact type, ordinal, offset, length, and schedule bytes.
The final codec must enforce:

- one canonical section order;
- no missing, duplicate, overlapping, gapped, or trailing bytes;
- checked offset/length arithmetic with no aliases or overflow;
- rejection of unknown critical sections;
- raw-byte coverage by `envelopeRoot`; and
- independent recomputation of the same envelope root, schedule, context, suite
  digest, and session digest by every verifier role that relies on them.

### Lock and deployment provenance

Concrete state and carrier locks must be the deterministic output of one typed,
total, acyclic derivation:

```text
normalized templates + typed parameters + pinned toolchain
  -> protocol template digest
  -> pool instance and manifest inputs
  -> exact concrete state/carrier locking bytecode
  -> deterministic genesis deployment recipe
```

Every node and edge is encoded canonically and hashed. Each concrete byte must
have exactly one provenance path. A concrete lock, genesis-derived outpoint, or
manifest digest may not be fed back into an ancestor identity.

## Required closure artifacts

1. Closed Fv2 normative schemas and prose for relation inputs, the authenticated
   transaction view, envelope/directory, provenance DAG, token roles, and
   verifier-role consumption.
2. A nonempty materialized closure bundle containing serialized transaction
   fixtures, nonempty raw envelopes, parsed schedules and roots, normalized
   templates, exact concrete locks, and a deterministic genesis recipe.
3. Two independent recomputers which accept only raw inputs and produce
   byte-identical transaction views, schedules, roots, digests, locks, and
   provenance outputs.
4. The 57 retained falsifier families expanded into executable, stable cases
   with exact inputs, expected rejection layer, and raw digests.
5. An independent result report and a root/SOL gate decision.

Structural proof fixtures must reject at the proof boundary until a proof-suite
manifest is selected. Counts, schemas, and plans alone receive no closure
credit.

## Hard Gate 1 pass rule

Hard Gate 1 may receive relation-closure credit only when:

- schema and codec accept exactly the same three networks;
- both recomputers agree byte-for-byte on every derived value;
- every raw byte and every claimed transaction field is consumed;
- every verifier role independently recomputes every binding it relies on;
- provenance is total, deterministic, and acyclic to each concrete byte;
- all materialized falsifiers reject at their specified boundaries;
- each of the four predecessor blockers points to explicit closing evidence; and
- no unselected proof suite or structural fixture reaches proof acceptance.

The only permissible positive verdict is relation-closure credit. It grants
zero proof, transaction, BCH execution, measurement, qualification, selection,
fallback, or deployment credit.

## Hard Gate 5 and later work

Deferred work includes the selected Circle-FRI suite, complete valid proofs,
composed 128-bit soundness, exact current-BCH VM and policy execution, complete
standard deposit and withdrawal transactions, exact ticket accounting, live
genesis/category binding, the complete adversarial corpus, and measured desktop
proving. None may be inferred from Fv2 structural closure.

## Disjoint implementation scopes

- Root: normative Fv2 relation, threat/responsibility mapping, integration, and
  gate decisions.
- Terra A: canonical transaction-view and envelope reference implementation.
- Terra B: independent recomputer and deterministic template-to-lock compiler;
  no shared correctness-critical implementation with Terra A.
- Luna A: schemas, known-answer encodings, and frozen corpus expansion after
  the ABI is reviewed.
- Luna B: independent runner/result normalization and reproducibility receipts.
- SOL: independent adversarial review after the complete falsifier report and
  before any Fv2 refreeze or Hard Gate 5 authorization.

No worker may select proof parameters, relax a frozen constraint, substitute an
injected digest, promote a structural fixture, or modify another worker's
write scope.

## Stop conditions

Stop with HOLD if any required transaction field lacks authenticated current-BCH
introspection; any derived fact remains injectable; any envelope byte is
unconsumed; provenance is partial, cyclic, ambiguous, or nondeterministic; a
carrier token becomes necessary; a required falsifier accepts; an unselected
proof suite reaches acceptance; or the phase begins choosing proof parameters,
executing BCH, admitting measurements, or extending B0 authority scaffolding.
