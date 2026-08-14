# PoolActionFv2 relation-closure charter v2

Status: `AUTHORIZED_BOUNDED_ABI_IMPLEMENTATION_NO_REFREEZE`

This charter supersedes the draft ABI in
`poolaction-fv2-relation-closure-charter-v1.md` and the unqualified package at
`poolaction-fv2-relation-closure-v1/`. It does not amend the historical
PoolActionFv1 evidence. It authorizes only relation-closure artifacts,
structural proof-rejected fixtures, independent recomputation, and falsifiers.
It authorizes no proof suite, BCH execution, measurement, deployment,
qualification, parameter selection, security fallback, or full prover.

## Identity and inherited product contract

```text
relationId      = PoolActionFv2
relationVersion = 2
abiVersion      = 2
```

PoolActionFv2 inherits without change:

- one fixed `10,000,000` satoshi ticket;
- one deposit and one unilateral withdrawal transaction per ticket;
- one action proof per transaction and no user batching;
- no private transfers, change notes, coordinator, privileged path, or runtime
  proof-suite selector;
- withdrawal payout exactly `10,000,000` satoshis;
- exactly one final transparent input funds fees and optional transparent
  change is token-free;
- one complete current-standard BCH transaction, at most `100,000` bytes;
- target 128-bit soundness and the existing measured-128-bit-failure-only
  fallback rule;
- complete local desktop withdrawal proving below 60 seconds; and
- Circle-domain FRI co-designed for BCH without a generic prover-stack
  dependency.

The current source table is BCHN commit
`864c53ee34924cca6c6b6d96607ff2cedcdccf02`. It yields
`MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12 = 128`, `MAX_SCRIPT_SIZE = 10000`,
`MAY2025_MAX_SCRIPT_ELEMENT_SIZE = MAX_SCRIPT_SIZE`, and
`MAX_STANDARD_TX_SIZE = 100000`. These values constrain later concrete
fixtures; they are not complete-transaction evidence.

## Why v1 is superseded

The v1 draft is retained as failed-route evidence. It must not receive closure
credit because it:

1. treated the three native token projections as a complete arbitrary
   CashToken record even though fungible-only and immutable-empty-NFT records
   can collide;
2. treated `networkId` as dynamically authenticated physical-chain identity,
   which current BCH introspection cannot provide;
3. placed evaluation-site-relative `OP_INPUTINDEX` in a supposedly shared
   digest;
4. hashed Canonical JSON at runtime;
5. allowed a caller-facing full provenance DAG into runtime authority; and
6. froze one envelope slot and stripped unlocking-bytecode framing.

The repaired ABI closes those defects without changing the relation identity.

## Primitive encodings

All byte lengths are exact and all parsers consume their complete input.
Unknown, duplicated, omitted, noncanonical, overflowing, or trailing fields
reject.

```text
u8        unsigned 1-byte integer
u16be     unsigned 2-byte big-endian integer
u32be     unsigned 4-byte big-endian integer
u64le     unsigned 8-byte little-endian integer
i64le     signed 8-byte two's-complement integer, used only for derived evidence
bytes32   exactly 32 bytes
bytes128  exactly 128 bytes
LP(x)     u32be(byte_length(x)) || x
```

Runtime nonnegative VM numbers are range-checked and encoded as `u64le`.
Implementations may use `OP_NUM2BIN(8)` only after proving the value is
nonnegative and at most `0x7fffffffffffffff`; this avoids the four-byte
signed-magnitude alias at values such as sequence `0xffffffff`. Counts,
ordinals, indices, and LP lengths are range-checked before `u32be` encoding.
Transaction hashes remain in the exact byte order returned by
`OP_OUTPOINTTXHASH`; no implicit reversal is permitted.

`SHA256` below means one SHA-256 hash, not `HASH256` and not an algorithm-agility
slot. Outer domains are exact ASCII followed by one `0x00` byte.

## Closed token observation language

No Fv2 runtime schema admits an arbitrary token union. A role selects exactly
one of two encodings constructed from the native category, commitment, and
amount observations:

```text
TokenObservationV2 =
  tag:u8
  || extendedCategoryLength:u16be || extendedCategoryBytes
  || commitmentLength:u16be || commitmentBytes
  || amount:u64le

NONE =
  00 || 0000 || empty || 0000 || empty || 0000000000000000

STATE_MUTABLE_NFT_ZERO =
  01 || 0021 || Cwire[32] || 01
     || 0080 || commitment[128]
     || 0000000000000000
```

The tag is role-derived and never caller-supplied. State source and successor
must use `STATE_MUTABLE_NFT_ZERO`, with the same `Cwire`, capability byte `01`,
zero amount, and independently validated 128-byte commitments. Every carrier,
external funding input, payout, and optional transparent change must use
`NONE`.

On the admitted state language the canonical native token prefix is uniquely:

```text
ef || Cwire[32] || 61 || 80 || commitment[128]
```

An encoded zero fungible amount is invalid. The known fungible-only versus
immutable-empty-NFT collision is wholly outside the admitted roles and both
members reject. No Fv2 artifact may call `TokenObservationV2` a complete
arbitrary CashToken record.

## Deployment domain and acyclic authority

`networkId` remains exactly one lowercase ASCII member of:

```json
["mainnet", "chipnet", "regtest"]
```

It is only a static deployment-domain label. It is not physical-chain identity,
does not appear in the dynamic transaction view, and does not prove protection
against replay on a fork with identical deployment history. That residual is
explicit. A future physical-chain anti-replay requirement would require a
consensus, external-oracle, or product change and is outside this charter.

`DeploymentManifestV2CoreBytes` is a fixed binary object with this exact order:

```text
ASCII("P2DM")
u16be(2)
networkTag:u8                         // 00 mainnet, 01 chipnet, 02 regtest
reserved:u8 = 00
protocolTemplateDigest:bytes32
poolInstanceId:bytes32
preExistingAnchorDigest:bytes32
genesisAncestryDigest:bytes32         // pre-lock ancestry, never a derived txid loop
stateCategoryWire:bytes32
ticketSats:u64le = 10000000
feePolicyMaxSats:u64le
proofSuiteStatus:u8                   // 00 UNSELECTED, 01 SELECTED
proofSuiteManifestDigest:bytes32      // all zero iff UNSELECTED; nonzero iff SELECTED
carrierCount:u32be                    // N >= 1
carrierLayout[N]
depositRoleMap
withdrawalRoleMap

carrierLayout[i] =
  ordinal:u32be = i
  inputIndex:u32be = i + 1
  outputIndex:u32be = i + 1
  expectedValueSats:u64le

depositRoleMap =
  stateInputIndex:u32be = 0
  externalInputIndex:u32be = N + 1
  stateOutputIndex:u32be = 0
  payoutPresent:u8 = 0
  payoutOutputIndex:u32be = 0
  changeOptional:u8 = 1
  changeOutputIndex:u32be = N + 1

withdrawalRoleMap =
  stateInputIndex:u32be = 0
  externalInputIndex:u32be = N + 1
  stateOutputIndex:u32be = 0
  payoutPresent:u8 = 1
  payoutOutputIndex:u32be = N + 1
  changeOptional:u8 = 1
  changeOutputIndex:u32be = N + 2
```

The core contains no concrete state lock, carrier lock, genesis transaction ID,
or downstream evidence root. Its sole runtime identity is:

```text
deploymentCommitment =
  SHA256(ASCII("PoolActionFv2/deployment/v2") || 00
         || LP(DeploymentManifestV2CoreBytes))
```

Concrete state/carrier redeem bytecode and locking bytecode are deterministic
children of `deploymentCommitment` and the normalized protocol templates.
Every executing role authenticates the same embedded commitment from its
concrete redeem bytecode. A caller-supplied network label, manifest, commitment,
lock, or evidence root is comparison-only and cannot establish acceptance.

The full compile/deployment DAG, exact locks, byte origins, genesis recipe, and
post-lock deployment records produce a separate `provenanceEvidenceRoot`.
That root is qualification evidence only: it is never a runtime input, never a
context/session preimage field, and never authoritative to a covenant.

### Structural template compiler and genesis evidence

Gate-1 fixtures require deterministic concrete bytes but may not masquerade as
a selected covenant. They therefore use this exact proof-rejecting structural
compiler. It is fixture evidence only and must never be called deployable,
standard, VM-accepted, or a PoolAction verifier.

Raw template input is:

```text
TemplateSetV2Bytes =
  ASCII("P2TS")
  || u16be(2)
  || LP(UTF8(toolchainId))
  || LP(normalizedStateTemplateBytes)
  || LP(normalizedCarrierTemplateBytes)

protocolTemplateDigest =
  SHA256(ASCII("PoolActionFv2/protocol-template/v2") || 00
         || LP(TemplateSetV2Bytes))
```

`toolchainId` is nonempty canonical UTF-8 without NUL. Both normalized template
byte strings are nonempty, distinct, and fully consumed. The structural
fixture set pins them as raw inputs rather than invoking CashScript or another
compiler.

The pre-existing anchor input is exact
`anchorTxHashOpcodeOrder:bytes32 || anchorOutputIndex:u32be`. Its transaction
hash is also the expected state category for the structural CashToken genesis
model. Derivations are:

```text
preExistingAnchorDigest =
  SHA256(ASCII("PoolActionFv2/pre-existing-anchor/v2") || 00
         || LP(anchorTxHashOpcodeOrder)
         || LP(u32be(anchorOutputIndex)))

poolInstanceId =
  SHA256(ASCII("PoolActionFv2/pool-instance/v2") || 00
         || LP(protocolTemplateDigest)
         || LP(u8(networkTag))
         || LP(preExistingAnchorDigest)
         || LP(anchorTxHashOpcodeOrder)
         || LP(u64le(10000000)))

stateCategoryWire = anchorTxHashOpcodeOrder

genesisAncestryDigest =
  SHA256(ASCII("PoolActionFv2/genesis-ancestry/v2") || 00
         || LP(preExistingAnchorDigest)
         || LP(poolInstanceId)
         || LP(stateCategoryWire))
```

The recomputer constructs `DeploymentManifestV2CoreBytes` with those values and
derives `deploymentCommitment`. For role tag `00` state or `01` carrier, let
`roleTemplateDigest` be the matching exact digest defined immediately below:

```text
roleBindingDigest =
  SHA256(ASCII("PoolActionFv2/structural-role/v2") || 00
         || LP(deploymentCommitment)
         || LP(u8(roleTag))
         || LP(roleTemplateDigest))

StructuralRedeemV2(role) =
  20 || roleBindingDigest[32] || 75 || 00

StructuralLockV2(role) =
  a9 || 14 || HASH160(StructuralRedeemV2(role))[20] || 87
```

Here `20` is canonical push-32, `75` is `OP_DROP`, final `00` is `OP_FALSE`,
and `a9 14 ... 87` is the exact P2SH20 locking-bytecode form. `HASH160(x)` is
`RIPEMD160(SHA256(x))`. The final `OP_FALSE` makes every structural redeem
script proof-rejecting by construction. No fixture may replace it with an
accepting opcode or claim covenant execution.

The two role-template digests are exactly:

```text
stateRoleTemplateDigest =
  SHA256(ASCII("PoolActionFv2/role-template/v2") || 00
         || LP(protocolTemplateDigest)
         || LP(u8(00))
         || LP(normalizedStateTemplateBytes))

carrierRoleTemplateDigest =
  SHA256(ASCII("PoolActionFv2/role-template/v2") || 00
         || LP(protocolTemplateDigest)
         || LP(u8(01))
         || LP(normalizedCarrierTemplateBytes))
```

`roleTemplateDigest` in the structural-role formula is the matching value.

After locks exist, off-chain genesis evidence is:

```text
GenesisRecipeV2Bytes =
  ASCII("P2GR")
  || u16be(2)
  || anchorTxHashOpcodeOrder:bytes32
  || anchorOutputIndex:u32be
  || deploymentCommitment:bytes32
  || stateCategoryWire:bytes32
  || LP(stateStructuralRedeem)
  || LP(stateStructuralLock)
  || carrierCount:u32be
  || SUM_i [ordinal:u32be
            || expectedValueSats:u64le
            || LP(carrierStructuralRedeem)
            || LP(carrierStructuralLock)]
  || initialStateValueSats:u64le

genesisRecipeDigest =
  SHA256(ASCII("PoolActionFv2/genesis-recipe/v2") || 00
         || LP(GenesisRecipeV2Bytes))

ProvenanceEvidenceV2Bytes =
  ASCII("P2PE")
  || u16be(2)
  || LP(TemplateSetV2Bytes)
  || LP(DeploymentManifestV2CoreBytes)
  || LP(GenesisRecipeV2Bytes)
  || genesisRecipeDigest:bytes32

provenanceEvidenceRoot =
  SHA256(ASCII("PoolActionFv2/provenance-evidence/v2") || 00
         || LP(ProvenanceEvidenceV2Bytes))
```

`initialStateValueSats` is a raw fixture input and must be sufficient for the
chosen structural action. The evidence object also records a complete byte
origin interval map for every structural redeem/lock byte. That interval map is
validated off-chain but is not part of the runtime commitment or the binary
preimage above. A later real covenant compiler must replace this structural
compiler under a separately reviewed ABI-compatible evidence package; these
always-false locks can never receive BCH or deployment credit.

## Manifest-fixed role topology

For structural carrier count `N >= 1`, wire order is exact:

```text
inputs:
  0       STATE
  1..N    VERIFIER_CARRIER, ordinal = inputIndex - 1
  N+1     DEPOSIT_FUNDING or FEE_FUNDING

outputs:
  0       STATE_SUCCESSOR
  1..N    VERIFIER_CARRIER_SUCCESSOR, ordinal = outputIndex - 1
  N+1     optional TRANSPARENT_CHANGE for DEPOSIT
  N+1     mandatory PAYOUT for WITHDRAWAL
  N+2     optional TRANSPARENT_CHANGE for WITHDRAWAL
```

No other input/output exists. State and all carrier sources share the same
predecessor transaction hash; state source outpoint index is zero and carrier
source outpoint index is `ordinal + 1`. Every carrier preserves its manifest
value, exact source lock, and `NONE` observation into its exact successor.

Every state/carrier script locally enforces:

```text
OP_INPUTINDEX == manifestRoleMap.fixedInputIndex
```

before accepting shared context/session material. `OP_INPUTINDEX` is not
serialized in the shared view. Moving an otherwise valid script to another
input therefore rejects locally without creating role-specific context digests.

The final external input is token-free. Its unlocking bytecode/signature is
excluded from relation hashes to avoid signature self-reference and must later
be independently authorized with the selected current-standard whole-output
binding mode. It never substitutes for carrier-session binding.

## TxViewV2 binary codec

`TxViewV2Bytes` has one exact field order. It contains dynamic transaction facts
plus manifest-fixed role labels checked against wire position. It contains no
network label, active input index, caller digest, provenance DAG, provenance
evidence root, or raw unlocking bytecode.

```text
ASCII("P2TV")
u16be(2)
actionTag:u8                         // 00 DEPOSIT, 01 WITHDRAWAL
reserved:u8 = 00
transactionVersion:u64le
locktime:u64le
carrierCount:u32be
inputCount:u32be = N + 2
inputs[inputCount]
outputCount:u32be
outputs[outputCount]
economics
```

Each input record is:

```text
wireIndex:u32be
roleTag:u8                           // 00 STATE, 01 CARRIER, 02 DEPOSIT_FUNDING, 03 FEE_FUNDING
roleOrdinal:u32be
outpointTxHashOpcodeOrder:bytes32
outpointIndex:u64le
sequence:u64le
sourceValueSats:u64le
LP(sourceLockingBytecode)
TokenObservationV2                  // exact role-selected form
unlockingDisposition:u8             // 00 LOCAL_STATE, 01 CARRIER_SESSION, 02 EXTERNAL_AUTH
```

Each output record is:

```text
wireIndex:u32be
roleTag:u8                           // 10 STATE, 11 CARRIER, 12 PAYOUT, 13 CHANGE
roleOrdinal:u32be
valueSats:u64le
LP(lockingBytecode)
TokenObservationV2                  // exact role-selected form
```

The economics record is:

```text
ticketSats:u64le = 10000000
reserveDirection:u8                 // 00 +ticket for DEPOSIT, 01 -ticket for WITHDRAWAL
feeSats:u64le                       // derived as sum(sources) - sum(outputs)
feePolicyMaxSats:u64le              // embedded manifest constant, equality checked
payoutPresent:u8
payoutOutputIndex:u32be             // zero iff absent
changePresent:u8
changeOutputIndex:u32be             // zero iff absent
```

Every `u64le` dynamic field is constructed from a current-BCH introspection VM
number after range checking. Transaction version, locktime, counts, outpoints,
sequences, source values/locks/token observations, output values/locks/token
observations, and every designated carrier unlocking bytecode use the current
native inspection opcodes. Role tags, ordinals, fixed indices, ticket value,
fee cap, state category, and deployment commitment are embedded deployment
constants. Fee, reserve direction, payout/change presence, exact role counts,
source/successor continuity, and token-role equality are derived and checked.

`TxViewV2Bytes` excludes all input unlocking bytes. State unlocking bytes are
local execution material and may contain no independently authoritative shared
fact. Carrier unlocking bytes are separately and completely bound below.
External authorization bytes remain outside both hashes to avoid signature
self-reference.

## Carrier segment and full-script binding

The proof-suite-independent carrier frame is:

```text
SegmentFrameV2 =
  ASCII("P2SG")
  || u16be(2)
  || ordinal:u32be
  || inputIndex:u32be
  || payloadLength:u32be
  || payload[payloadLength]
```

`payloadLength` is nonzero and consumes the frame exactly. The frame is one
canonically minimally encoded BCH push. A structural carrier unlocking script
is exactly that push followed by the canonical deployment-selected redeem
script push; no prefix, middle argument, alternate push, or suffix is allowed.
The final concrete proof suite may define the payload grammar but may not change
the outer frame without a new ABI version.

For manifest entries `(ordinal_i, inputIndex_i)` in order:

```text
CarrierSessionBytes =
  u32be(N)
  || SUM_i [u32be(ordinal_i)
            || u32be(inputIndex_i)
            || LP(fullUnlockingBytecode_i)]

carrierSessionRoot =
  SHA256(ASCII("PoolActionFv2/carrier-session/v2") || 00
         || LP(CarrierSessionBytes))
```

Every `fullUnlockingBytecode_i` is obtained independently with
`OP_INPUTBYTECODE(inputIndex_i)` and includes push opcodes, encoded lengths,
frame bytes, payload, and redeem script. The state covenant consumes all N full
scripts. Each carrier consumes its own full script and authenticates the same
ordered session through the state-enforced root and manifest role map.

Let payload offsets be cumulative from zero. Then:

```text
ReconstructedEnvelopeBytes = payload_0 || ... || payload_(N-1)

ScheduleBytes =
  u32be(N)
  || SUM_i [u32be(ordinal_i)
            || u32be(inputIndex_i)
            || u32be(offset_i)
            || u32be(length_i)]

envelopeRoot =
  SHA256(ASCII("PoolActionFv2/envelope/v2") || 00
         || LP(ReconstructedEnvelopeBytes))
```

Missing, duplicated, omitted, reordered, differently segmented, noncanonical
push, input-index-swapped, gapped, overlapping, truncated, or trailing bytes
reject. Equal extracted payload under different full unlocking bytes changes
`carrierSessionRoot`. Neither a carrier-local root nor a digest embedded in
bytes it hashes can be authoritative. A selected proof-suite manifest must
later show that segment payload generation is independent of all outer digest
results before proof acceptance can open.

Current active limits require every complete carrier unlocking bytecode and
every pushed element to be at most `10,000` bytes. No maximum payload value is
claimed before the exact redeem bytecode and push overhead are materialized and
counted. The complete transaction must later remain at most `100,000` bytes.

## Context and session binding

```text
contextDigest =
  SHA256(ASCII("PoolActionFv2/context/v2") || 00
         || LP(deploymentCommitment)
         || LP(TxViewV2Bytes))

sessionDigest =
  SHA256(ASCII("PoolActionFv2/session/v2") || 00
         || LP(contextDigest)
         || LP(carrierSessionRoot)
         || LP(envelopeRoot)
         || LP(ScheduleBytes)
         || LP(proofSuiteManifestDigest))
```

All state/carrier verifier roles must independently rebuild byte-identical
`TxViewV2Bytes`, `contextDigest`, `CarrierSessionBytes`, `carrierSessionRoot`,
`ReconstructedEnvelopeBytes`, `ScheduleBytes`, `envelopeRoot`, and
`sessionDigest` from authenticated transaction facts and their embedded
deployment constant. Supplied digests are comparison values only.

When `proofSuiteStatus = UNSELECTED`, the manifest digest is all zero and every
otherwise valid structural fixture ends at
`REJECT_UNSELECTED_PROOF_SUITE`. No structural fixture can return proof
acceptance.

## Field-source classes

The normative package must give every runtime field exactly one class:

- `INTROSPECTED`: obtained from current BCH transaction or sibling-source
  inspection;
- `EMBEDDED_DEPLOYMENT_CONSTANT`: authenticated from the concrete executing
  redeem bytecode and the pre-lock deployment commitment; or
- `DERIVED_AND_CHECKED`: recomputed from the first two classes and enforced.

`currentBchIntrospection` metadata is evidence, not hashed runtime data. A field
without a complete source mapping is a blocker. A caller fact is never a fourth
class.

## Required v2 package

The implementation package is a new
`spec/poolaction-fv2-relation-closure-v2/` namespace. It must include:

1. normative binary field-order and field-source tables;
2. closed schemas for deployment manifest, authenticated transaction view,
   carrier/session envelope, relation inputs, off-chain provenance evidence,
   and verifier-role consumption;
3. an exact responsibility map and threat-model delta preserving every Fv1
   responsibility while adding token-observation, deployment-label residual,
   role relocation, all-carrier framing, digest injection, and provenance-cycle
   controls;
4. validators which reject unknown keys, bad lengths/ranges/order, caller
   digests/evidence roots, and proof acceptance while the suite is unselected;
5. a nonempty proof-rejected structural fixture bundle; and
6. package-local source pins and an outside-package review anchor.

The existing v1 package remains unqualified and must state that it is
superseded. It is not silently repaired in place.

## Required independent evidence

- Two independent recomputers, with no shared correctness-critical codec, take
  only raw transaction/source-output/manifest/template inputs and agree on all
  bytes, locks, deployment/provenance outputs, schedules, roots, and digests.
- Materialized deposit and withdrawal fixtures cover at least `N = 1` and
  `N = 3`; all remain proof-rejected.
- All 57 retained falsifier families are dispositioned without omission. Cases
  requiring selected proof grammar or complete BCH VM execution remain explicit
  deferred gates, not false Gate-1 passes. Architecture-level families and the
  additive v2 falsifiers are materialized and stable.
- Independent replay verifies fixture hashes, expected rejection layers, and
  cross-language byte equality.

At minimum, additive v2 falsifiers cover both members of the token-projection
collision; state capability/amount/length/category mutations; caller network or
deployment-root substitution; role relocation; same payload/different full
script; carrier count/order/ordinal/index/splice errors; JSON preimage aliases;
numeric endian/range/count aliases; caller provenance influence; and the
explicitly undetectable identical-history chain clone residual.

## Gate boundary

Hard Gate 1 remains `HOLD` until all v2 package, recomputer, structural fixture,
falsifier, source-pin, and independent-review evidence exists and passes.
Hard Gate 5 and all proof/VM/transaction/measurement gates remain closed.

The only possible positive result of this phase is relation-closure credit. It
grants zero proof, soundness, ZK, BCH execution, standardness, transaction-size,
performance, qualification, selection, deployment, or activation credit.

Stop with `HOLD` if any field lacks authenticated sourcing; a token collision
enters the admitted language; physical-chain identity is claimed; a shared
digest includes evaluation-site-relative state; any carrier byte is unconsumed;
a digest is authoritative from inside its own preimage; provenance becomes
cyclic or runtime-caller-controlled; a required materialized falsifier accepts;
or this phase begins choosing proof parameters or running qualification work.
