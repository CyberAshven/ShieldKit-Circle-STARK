# PoolActionFv1 pre-refreeze falsifiers v1

This sealed package is an inert, deterministic, synthetic/offline falsifier
subset for the blocked PoolActionFv1 relation disposition. Its status is and
remains `BLOCKED_VERSION_PIVOT_NO_REFREEZE`; `relationRefreezeAllowed` is
`false`. It binds the exact blocked disposition package, historical P0 freeze,
and four-item contradiction capsule without changing any historical byte.

The executable corpus has 57 individually identified rows: two canonical
positive projections (one DEPOSIT and one WITHDRAWAL), both with three
carriers, and 55 expected rejections. Every negative first validates its
positive antecedent. Three valid synthetic session antecedents A, B, and C are
materialized before cross-splice tests. The SUT receives only the candidate
model; case identifiers, mutations, expectations, and expected rejection
stages remain outside it.

`index.v1.json` also records the stricter 57-family review contract with group
counts 12 positives, 4 networks, 9 context/token, 7 locks, 18 sessions,
4 parser, and 3 splice. Only 44 families are materially covered by this
synthetic corpus; 13 are explicitly `PLANNED_NOT_MATERIALIZED`. A 100% receipt
therefore means agreement on the 57 executed rows only. It does not mean the
57-family contract is complete and closes no blocker.

## Frozen identities and model boundary

The stdlib oracle independently re-expresses the historical 589-byte `PAST`
layout and complete `TxContextFv1` byte grammar without importing or executing
P1/project modules. It enforces full consumption and rejects every unlisted
mutation. The state-side model recomputes each ordered section leaf and the
session root from exact PAST, its extracted profile and manifest digests,
carrier count, checkpoint, and ordered raw section payloads. Root-bearing
wrappers and the supplied membership vector are excluded from the root
preimage. Each carrier record is checked against its ordinal, exact complete
manifest lock, local leaf membership, and the same sole anchor at input 1.

SHA-256 and the synthetic checkpoint are test-only deterministic plumbing.
They are not a selected context digest, proof-profile commitment function,
transcript, proof grammar, wrapper, or deployment choice. The vector producer
and offline SUT share correctness-critical serializer, digest, token, lock-DAG,
and root helpers; there is no dual independent byte derivation or independent
digest/root implementation. This is regression evidence, not closure evidence.

The lock control instantiates three typed, acyclic synthetic locks. Carrier 1
contains byte `ab` inside a canonical one-byte data push; the decoded
`OP_CODESEPARATOR` count remains zero. No BCH script is executed and no claim
is made that these synthetic locks are usable covenant bytecode.

The 10,000-byte script and element ceilings and later 100,000-byte aggregate
transaction ceiling are static contract assertions only. This package does not
derive `maxSectionPayloadBytes`, execute a full transaction, or claim BCH
acceptance, cost, standardness, relayability, or soundness.

## Remaining blockers and non-authority

All four contradictions remain open:

- `P0-NETWORK-SCHEMA-CODEC-DRIFT`
- `P1-CONTEXT-DIGEST-FACT-INJECTION`
- `P1-CARRIER-LOCK-ANCHOR-ERASURE`
- `P1-PROOF-SESSION-CONTEXT-ERASURE`

A selected immutable digest, selected proof grammar/checkpoint, concrete
reviewed wrapper and maximum section derivation, deployment manifest and real
locks, independent implementations/review, BCH covenant/VM/full-transaction
evidence, and root/SOL final-byte review are all absent. Nothing here grants
measurement admission, qualification, ranking, selection, promotion,
deployment, or relation refreeze authority.

## Inert validation

Run from this directory:

```sh
python3 oracle.py check
sha256sum --check SHA256SUMS
```

The oracle uses only the Python standard library. It reads this package and the
exact pinned source artifacts for checksum comparison. It does not import or
run P1, Node, BCHN, Libauth, a VM, a network, a proof, a prover, or a full
transaction. All JSON files are two-space, key-sorted canonical JSON with one
trailing newline. `MANIFEST.json` inventories the eight non-envelope files;
`SHA256SUMS` covers those eight plus `MANIFEST.json` and excludes itself.
