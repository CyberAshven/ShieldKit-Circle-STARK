# PoolActionFv2 ABI-v2 static red-team HOLD — 2026-08-14

Status: `UNQUALIFIED_FAILED_ROUTE_EVIDENCE_P0_MANIFEST_AND_ACTION_SOURCE_UNAUTHENTICATED`.

This note records the first independent adversarial review of the ABI-v2
relation-closure charter and its static package. It preserves the failed route;
it does not amend the charter, qualify the relation, or authorize BCH VM,
proof-system, measurement, deployment, or activation work.

## Reviewed artifacts

- Charter: `spec/poolaction-fv2-relation-closure-charter-v2.md`, 635 lines,
  23,967 bytes, SHA-256
  `aa1a63b17c74bc5f4f09c4c5009914a42c0942cd320cbf82fce6bad19d45191e`.
- Static package: `spec/poolaction-fv2-relation-closure-v2/`; its self-check,
  15 tests, JSON parsing, checksum manifest, and whitespace checks pass.
- Falsifier contract: `spec/poolaction-fv2-falsifier-contract-v2/`; 57 retained
  families plus 16 additive rows are dispositioned, but no variant has been
  materialized or executed.

These mechanical passes do not close the failures below.

## P0 blockers

### 1. Deployment manifest is not authenticated by the locked runtime bytes

`validateRelationInput` hashes the caller-provided deployment manifest and
uses the resulting comparison value. It does not prove equality between that
manifest-derived commitment and a constant authenticated by the state/carrier
source locks. Carrier parsing only proves that the supplied redeem script
matches its P2SH20 source lock.

Independently reproduced counterexample:

1. Load `fixtures/structural-deposit-n1.v2.json`.
2. Change only `relationInput.deploymentManifest.networkId` from `chipnet` to
   `mainnet`.
3. Leave every source lock and carrier unlocking/redeem byte unchanged.
4. `validateRelationInput` accepts and returns deployment commitment
   `ee345488dd201469355396392252317f1016df4f05495fbd1eb12f08dfbeecc7`.

The unchanged state and carrier source locks are respectively
`a9143e3fbb63cdd47cb52b2a8102ff8e9e3573612a5187` and
`a914ba4b6cc0a94a2e62aa71e94a4071be684c9b44dc87`. A valid state-category
substitution with correspondingly changed state observations is the same
failure class.

### 2. `actionKind`/`actionTag` has no authenticated source

The interchange object supplies `actionKind`, and the validator uses it to
select roles, topology, reserve direction, payout rules, and the byte encoded
in `TxViewV2Bytes`. No introspected discriminator or embedded action constant
authenticates that value. “Manifest-fixed role topology and action branch” is
not a byte-level source.

A repair must remove the authoritative caller field and derive the action from
unique, introspected transaction facts, or introduce separately authenticated
action authority. It must not merely compare two caller representations.

### 3. The source table is not exhaustive

The charter requires exactly one source class for every runtime field, but the
table omits at least `txView.carrierCount` and treats several header, reserved,
frame, schedule, and economics primitives only as aggregates. Gate 1 cannot
close on an incomplete field-to-byte/source inventory.

### 4. Carrier-local fixed-index semantics and structural locks disagree

The charter requires each carrier role to check its manifest-fixed input
index, while the structural compiler creates one identical carrier redeem and
lock for all ordinals. A repaired ABI must choose and falsify one exact rule:
either ordinal-specific locked scripts/constants, or a generic carrier script
which derives its slot from `OP_INPUTINDEX` and proves the corresponding
manifest mapping. The current text claims the former while materializing
neither.

## Bounded defects

- Provenance evidence does not bind `initialStateValueSats` to the fixture
  relation/action. A withdrawal-N=3 provenance object with value `0` is
  accepted after recomputing its comparison root.
- Evidence schemas' `runtimeU64` patterns admit some values above
  `0x7fffffffffffffff`; the custom encoder rejects them later, but the schemas
  do not satisfy their independent closed-range claim.
- The falsifier README's checksum command must run from the checksum file's
  package directory.
- The deployment and action-source counterexamples are contracted but not
  materialized/executed; no static self-test covers them.

## Interrupted recomputer evidence

The Node recomputer and four N=1/N=3 deposit/withdrawal raw/KAT pairs under
`p1/fv2-relation-closure-v2/` were produced before the P0 findings. Their
raw-to-KAT recomputation and compact-JSON result hashes are internally
consistent, but they inherit unauthenticated `deploymentManifestCoreHex` and
caller `actionTagHex`. Retain them only as failed-route evidence. They grant no
independent-recomputer, relation-closure, BCH VM, transaction, or proof credit.

## Gate ruling

Hard Gate 1 remains `HOLD`. Stop fixture expansion, second-language
recomputation, and falsifier execution until a new byte-level contract:

1. authenticates manifest/deployment bytes against every relevant locked role;
2. derives or separately authenticates the action tag;
3. resolves carrier ordinal/index semantics;
4. enumerates every runtime byte and source class;
5. binds provenance initial state to the relation; and
6. materializes the counterexamples above as mandatory rejecting tests.

Hard Gate 5 and all proof selection, BCH execution, standardness, transaction
size, performance, qualification, deployment, and activation gates remain
closed.
