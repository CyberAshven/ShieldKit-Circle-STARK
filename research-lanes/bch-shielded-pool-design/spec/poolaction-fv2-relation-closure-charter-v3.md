# PoolActionFv2 relation-closure charter v3

Status: `AUTHORIZED_BOUNDED_ABI3_IMPLEMENTATION_NO_REFREEZE`

This charter is the normative successor to the failed ABI-v2 attempt. It keeps
the PoolActionFv2 semantic relation at version 2 and replaces only its runtime
encoding and authority model with ABI version 3. ABI-v2 remains immutable
failed-route evidence: its static checks and recomputed fixtures receive no
relation-closure credit because a caller could substitute the deployment
manifest and action selector without changing the locked bytes.

This charter authorizes closed schemas, deterministic binary codecs, an
always-false structural compiler, proof-rejected fixtures, independent
recomputation, and adversarial falsifiers. It authorizes no proof suite, BCH VM
or node execution, complete-transaction claim, field or hash selection,
soundness or privacy claim, measurement, deployment, activation, or full
prover.

## 1. Identity and frozen product

```text
relationId      = PoolActionFv2
relationVersion = 2
abiVersion      = 3
```

`Fv2` and relation version 2 identify the semantic relation. Charter/package
revision v3 and ABI version 3 identify this repaired byte interface. No v2
magic, schema identifier, fixture format, package path, checksum namespace, or
hash domain may be reused. Every ABI-bearing header encodes integer 3 and every
new domain below ends in `/v3`. The `P3` magic prefix identifies ABI-v3; it does
not change the `PoolActionFv2` semantic relation name or relation version.

The following product constraints remain exact:

- ticket and withdrawal payout are exactly `10,000,000` satoshis;
- one deposit transaction or one unilateral withdrawal transaction handles one
  ticket and one user;
- exactly one action proof exists per transaction;
- user batching, private transfers, private change notes, variable amounts,
  runtime algorithm selection, privileged bypasses, replenishment
  transactions, and a required coordinator are forbidden;
- exactly one final token-free transparent input funds deposit value or the
  withdrawal fee; optional transparent change is final and token-free;
- the pool state and persistent verifier carriers never fund fees;
- one complete current-standard BCH transaction is required and must later be
  at most 100,000 bytes;
- systemic target soundness is 128 bits; the at-least-100-bit fallback remains
  closed until complete optimized 128-bit deposit and withdrawal transactions
  are measured and fail the size gate;
- complete local unilateral withdrawal proving must later be below 60 seconds
  on the pinned ordinary-desktop profile; and
- the proof family remains Circle-domain FRI designed for BCH without a generic
  prover-stack dependency.

## 2. Semantic relation preserved by ABI-v3

ABI-v3 changes authenticated representation, not the backend-neutral
PoolAction semantics. The complete `PoolStateFv1` 128-byte codec remains:

```text
offset 0   length 4   ASCII "PAF1"
offset 4   length 2   stateCodecVersion = u16le(1)
offset 6   length 2   reserved = 0000
offset 8   length 8   sequence:u64le
offset 16  length 8   depositCount:u64le
offset 24  length 8   withdrawalCount:u64le
offset 32  length 32  poolInstanceId
offset 64  length 32  noteRoot
offset 96  length 32  nullifierRoot
```

The three numeric state fields are `u64le` wire byte strings but are admitted
only as runtime nonnegative numbers under section 4. After exact little-endian
decoding, each of `sequence`, `depositCount`, and `withdrawalCount` must satisfy
`0 <= x <= 0x7fffffffffffffff`; `LE8(2^63)` and every larger encoding reject.

For ticket value `T=10,000,000`, lock-selected lifetime capacity `C`, and
lock-selected state-carrier base value `B`, every accepted semantic state
satisfies checked, non-wrapping arithmetic:

```text
0 <= withdrawalCount <= depositCount <= C
outstandingTickets = depositCount - withdrawalCount
reserveSats = outstandingTickets * T
stateUtxoValueSats = B + reserveSats
```

The semantic public statement contains, in one selected-suite canonical
encoding to be frozen later:

- relation/profile identity and the lock-selected pool/deployment identity;
- transaction-derived action tag;
- old state outpoint, value, exact source lock, exact state token observation,
  and exact 128-byte state;
- successor state index, value, exact lock, exact state token observation, and
  exact 128-byte state;
- fixed ticket and derived reserve direction;
- nonzero deposit note commitment or canonical zero;
- nonzero withdrawal nullifier or canonical zero;
- exact withdrawal payout index, value, and lock or canonical absence;
- transparent external-input role, optional final change, derived fee, and
  lock-selected maximum fee;
- the proof-suite manifest identity once selected;
- `contextDigest` over the complete non-circular transaction view; and
- the selected proof's own canonical statement and session checkpoint fields,
  without introducing an outer-root-to-proof cycle.

The semantic private witnesses remain:

```text
DEPOSIT:
  ownerSecret
  fresh rho
  recoveryMetadataVersion
  complete note preimage
  canonical authenticated empty-leaf path at old depositCount

WITHDRAWAL:
  ownerSecret
  rho and complete note preimage
  private note index
  canonical note membership path
  canonical nullifier non-membership and insertion witness
```

The unselected interfaces remain obligations rather than chosen algorithms:

- owner authorization commitment;
- note commitment binding pool, fixed ticket, note index, owner commitment,
  rho, and recovery version;
- deterministic note insertion at public old `depositCount`;
- nullifier derivation binding pool, note index, owner secret, and rho;
- authenticated nullifier non-membership and unique insertion;
- canonical selected proof statement, Circle-FRI proof, transcript, masking,
  parser, and proof-section schedule.

No structural ABI fixture establishes any of those cryptographic interfaces.

### 2.1 Deposit transition

```text
sequence          += 1
depositCount      += 1
withdrawalCount    unchanged
noteRoot           inserts one derived nonzero note commitment at old depositCount
nullifierRoot      unchanged
state value       += 10,000,000
public nullifier   32 zero bytes
payout             absent
```

The proof must later establish note well-formedness, capacity, canonical empty
leaf, and unique insertion. The settlement layer derives the action from the
state-value delta, checks the exact state/role topology, and checks:

```text
externalFundingValue = 10,000,000 + transparentChange + fee
```

### 2.2 Withdrawal transition

```text
sequence          += 1
depositCount       unchanged
withdrawalCount   += 1
noteRoot           unchanged
nullifierRoot      inserts one derived nonzero absent nullifier
state value       -= 10,000,000
public commitment  32 zero bytes
payout             exactly 10,000,000 sats
```

The proof must later establish note membership, owner-secret knowledge,
canonical nullifier derivation, old non-membership, and unique insertion. The
settlement layer derives the action from the state-value delta, checks the
fixed-position token-free payout, and checks:

```text
externalFeeInputValue = transparentChange + fee
```

## 3. Current BCH observation boundary

The source authority for current rules is BCHN commit
`864c53ee34924cca6c6b6d96607ff2cedcdccf02`. CashScript facts are pinned to
`v0.14.0-next.3` commit
`5c16940e70944fa96d57abd9b96c5f79d30a3388`. Evidence IDs `INT-001`,
`TOK-005`, and `SEC-007` are normative factual inputs to this charter.
The ABI-v3 package must resolve each ID to content-addressed local source
records, exact file hashes/line spans, and its review artifact; a bare evidence
label is not source authority.

Current native introspection supplies transaction version, locktime, active
input index, input/output counts, every input outpoint and sequence, every
source/output value and locking bytecode, every designated input unlocking
bytecode, and the category/commitment/amount token projections. Every index is
bounds-checked before use. The exact relevant opcodes at the pinned BCHN source
are `OP_INPUTINDEX=0xc0`, `OP_ACTIVEBYTECODE=0xc1`,
`OP_TXVERSION=0xc2`, `OP_TXINPUTCOUNT=0xc3`,
`OP_TXOUTPUTCOUNT=0xc4`, `OP_TXLOCKTIME=0xc5`,
`OP_UTXOVALUE=0xc6`, `OP_UTXOBYTECODE=0xc7`,
`OP_OUTPOINTTXHASH=0xc8`, `OP_OUTPOINTINDEX=0xc9`,
`OP_INPUTBYTECODE=0xca`, `OP_INPUTSEQUENCENUMBER=0xcb`,
`OP_OUTPUTVALUE=0xcc`, `OP_OUTPUTBYTECODE=0xcd`, and token projections
`0xce..0xd3`.

Source-derived current limits used only as later constraints are:

```text
MAX_SCRIPT_SIZE                              = 10,000 bytes
MAY2025_MAX_SCRIPT_ELEMENT_SIZE              = MAX_SCRIPT_SIZE
MAX_STACK_SIZE                               = 1,000 elements
MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12    = 128 bytes
MAX_STANDARD_TX_SIZE                         = 100,000 bytes
MAX_MONEY                                    = 2,100,000,000,000,000 sats
```

These constants do not establish complete-transaction acceptance.

Three limitations remain explicit:

1. Token category/commitment/amount projections are not a complete arbitrary
   CashToken record. In particular, fungible-only and immutable-NFT-plus-FT
   with empty commitment can collide.
2. No opcode authenticates physical mainnet/chipnet/regtest identity.
3. `OP_INPUTINDEX` is evaluation-site-relative and cannot be one shared field
   across multiple executing roles.

ABI-v3 narrows or relocates responsibility around those limitations; it never
claims the opcodes expose more information.

## 4. Primitive and integer encodings

All binary parsers fully consume their input. Unknown, omitted, duplicated,
noncanonical, overflowing, trailing, or reserved-nonzero bytes reject.

```text
u8       unsigned 1-byte integer
u16be    unsigned 2-byte big-endian integer
u32be    unsigned 4-byte big-endian integer
u64le    unsigned 8-byte little-endian byte string
i64le    signed 8-byte two's-complement, derived evidence only
bytes32  exactly 32 bytes
bytes128 exactly 128 bytes
LP(x)    u32be(byte_length(x)) || x
```

Runtime nonnegative numbers are represented in interchange as exact 16-digit
lowercase hex strings containing the eight little-endian bytes. Before
encoding, the VM number must satisfy `0 <= x <= 0x7fffffffffffffff`.
`0000000000000080` (the little-endian encoding of `2^63`) and all larger
values reject. Human decimal strings are display-only derivations and are not
runtime authority. Counts, ordinals, indices, and LP lengths are independently
range-checked before `u32be` encoding.

Transaction hashes use the byte order returned by `OP_OUTPOINTTXHASH`; no
implicit reversal is allowed. `SHA256` below means one SHA-256 invocation, not
`HASH256` and not an algorithm slot. Each domain is exact ASCII followed by one
`00` byte. `HASH160(x)=RIPEMD160(SHA256(x))`.

### 4.1 Canonical minimal BCH push

`MinimalPush(x)` is the unique push opcode/length encoding for the exact byte
string `x`:

```text
0 bytes        OP_0
1..75 bytes    one-byte length || x, except canonical small-integer encodings
76..255        OP_PUSHDATA1 || u8(length) || x
256..65535     OP_PUSHDATA2 || u16le(length) || x
```

The structural objects below never use small-integer payload aliases. A parser
must reject a non-minimal push even when it yields the same payload.

## 5. Closed role-selected token language

No ABI-v3 runtime schema accepts a generic token-kind union. A role selects one
of exactly two observations:

```text
TokenObservationV3 =
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

State source and successor require the second form with the same
lock-selected `Cwire`, mutable capability suffix `01`, zero fungible amount,
and independently introspected exact 128-byte commitments. The admitted native
state prefix is uniquely:

```text
ef || Cwire[32] || 61 || 80 || commitment[128]
```

Every carrier, external funding input, payout, and change output requires the
token-free projection and the role-derived `NONE` tag. The known FT/immutable
empty-NFT collision is wholly outside the state language and may not be
relabelled as a complete token record. A topology that makes an ambiguous
token projection relevant is a hard rejection, not an injected-kind repair.

## 6. Deployment manifest core

`networkId` is exactly one of `mainnet`, `chipnet`, or `regtest`, encoded as
tags `00`, `01`, or `02`. It is a lock-selected static deployment-domain label,
not physical-chain identity. Identical-history fork replay remains an explicit
unmitigated residual.

`DeploymentManifestV3CoreBytes` has this exact order. Its carrier count is
bounded by the exact structural script derivation below, not merely by the
`u32be` representation:

```text
ASCII("P3DM")
u16be(3)
networkTag:u8
reserved:u8 = 00
protocolTemplateDigest:bytes32
poolInstanceId:bytes32
preExistingAnchorDigest:bytes32
genesisAncestryDigest:bytes32
stateCategoryWire:bytes32
ticketSats:u64le = 8096980000000000      // LE8(10000000)
stateCarrierBaseSats:u64le
maxLifetimeDeposits:u64le
feePolicyMaxSats:u64le
proofSuiteStatus:u8                      // 00 UNSELECTED, 01 SELECTED
proofSuiteManifestDigest:bytes32
noUpgrade:u8 = 01
carrierCount:u32be                       // 1 <= N <= 483
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

`stateCarrierBaseSats`, every configured carrier value, and
`feePolicyMaxSats` are in `MoneyRange`. `maxLifetimeDeposits >= 1`, and the
manifest rejects unless
`stateCarrierBaseSats + maxLifetimeDeposits * 10,000,000 <= MAX_MONEY` under
checked non-wrapping arithmetic. `proofSuiteStatus=00` requires the exact zero
digest and makes every structural relation result reject with
`REJECT_UNSELECTED_PROOF_SUITE`. Status `01` requires a nonzero digest of a
later selected, content-addressed proof-suite manifest; ABI-v3 reserves this
state without selecting one here. No other status/digest pairing is valid.
That selected manifest must later bind every algorithm/security-profile field
required by `PoolConfigFv1`, including note and nullifier accumulator capacities
consistent with `maxLifetimeDeposits`; this phase neither chooses nor fabricates
those fields.

The lock-checked pool identity is not a free 32-byte label. Define the exact
acyclic preimage:

```text
PoolIdentityConfigV3Bytes =
  ASCII("P3PI") || u16be(3)
  || networkTag:u8
  || reserved:u8 = 00
  || protocolTemplateDigest:bytes32
  || preExistingAnchorDigest:bytes32
  || stateCategoryWire:bytes32
  || ticketSats:u64le
  || stateCarrierBaseSats:u64le
  || maxLifetimeDeposits:u64le
  || feePolicyMaxSats:u64le
  || proofSuiteStatus:u8
  || proofSuiteManifestDigest:bytes32
  || noUpgrade:u8 = 01
  || carrierCount:u32be
  || carrierLayout[N]
  || depositRoleMap
  || withdrawalRoleMap

poolInstanceId =
  SHA256(ASCII("PoolActionFv2/pool-instance/v3") || 00
         || LP(PoolIdentityConfigV3Bytes))
```

The manifest `poolInstanceId` must equal this recomputation. Thus the fixed
ticket, base, lifetime capacity, fee policy, proof-suite state, carrier layout,
role maps, deployment-domain label, token category, template identity, anchor,
and no-upgrade assertion all bind the state identity. `genesisAncestryDigest`
remains downstream of this identity and is excluded from its own preimage.

For this exact manifest grammar, `byte_length(DeploymentManifestV3CoreBytes)` is
`282 + 20N`; `byte_length(StructuralRedeemV3(role_i))` is `308 + 20N`; and a
one-byte payload produces a minimum complete carrier unlocking bytecode of
`331 + 20N`. The current 10,000-byte script/unlocking limit therefore makes
`N=483` the largest structurally encodable count. The compiler and parser reject
larger N, and independently reject any actual manifest push, redeem, frame,
full carrier unlocking bytecode, LP total, payload length, or schedule offset
which exceeds its declared encoding or current 10,000-byte bound. The later
100,000-byte complete-transaction gate will impose a much smaller measured
bound and receives no credit here.

The core excludes concrete redeem scripts, locks, genesis transaction IDs,
outpoints, proof bytes, carrier payloads, and downstream evidence roots. Its
commitment is:

```text
deploymentCommitment =
  SHA256(ASCII("PoolActionFv2/deployment/v3") || 00
         || LP(DeploymentManifestV3CoreBytes))
```

A decoded manifest object or claimed commitment is comparison evidence only.
Runtime authority begins with the exact manifest bytes selected by the spent
source lock as specified next.

## 7. Lock-selected role authority

Each persistent role has a distinct fixed instance:

```text
RoleInstanceV3Bytes =
  ASCII("P3RI") || u16be(3)
  || roleTag:u8
  || ordinal:u32be
  || fixedInputIndex:u32be
  || fixedOutputIndex:u32be

STATE:
  roleTag=00, ordinal=0, fixedInputIndex=0, fixedOutputIndex=0

CARRIER i:
  roleTag=01, ordinal=i, fixedInputIndex=i+1, fixedOutputIndex=i+1
```

The fixture-only compiler is exact:

```text
StructuralRedeemV3(role_i) =
  MinimalPush(DeploymentManifestV3CoreBytes)
  || OP_DROP
  || MinimalPush(RoleInstanceV3Bytes(role_i))
  || OP_DROP
  || OP_FALSE

StructuralLockV3(role_i) =
  OP_HASH160 || Push20(HASH160(StructuralRedeemV3(role_i))) || OP_EQUAL
```

The corresponding fixed opcode bytes are `OP_DROP=75`, `OP_FALSE=00`, and the
P2SH20 lock `a9 14 <20 bytes> 87`. The trailing `OP_FALSE` makes every
structural role proof-rejecting. It must never be called deployable,
VM-accepted, standard, or an accepting covenant.

For runtime comparison and structural fixtures:

- the active state redeem is the exact state role redeem and its HASH160 is
  selected by state source lock at input zero;
- the state successor lock is byte-identical to the exact state role lock;
- carrier `i` source and successor locks are byte-identical to that ordinal's
  exact role lock;
- every carrier unlocking bytecode ends in one canonical minimal push of that
  exact ordinal-specific redeem;
- the manifest prefix extracted from every active/sibling redeem is
  byte-identical; and
- each executing role locally checks
  `OP_INPUTINDEX == fixedInputIndex` before accepting shared material.

A generic carrier redeem, a caller manifest, or a commitment recomputed only
from caller data cannot satisfy this rule. Distinct ordinal redeems preserve
fixed-role semantics without changing P2SH locking-bytecode length.

## 8. Manifest-fixed topology and action derivation

For `1 <= N <= 483`, input order is exact:

```text
0       STATE
1..N    VERIFIER_CARRIER, ordinal=inputIndex-1
N+1     DEPOSIT_FUNDING or FEE_FUNDING
```

Deposit outputs are:

```text
0       STATE_SUCCESSOR
1..N    VERIFIER_CARRIER_SUCCESSOR
N+1     optional TRANSPARENT_CHANGE
```

Withdrawal outputs are:

```text
0       STATE_SUCCESSOR
1..N    VERIFIER_CARRIER_SUCCESSOR
N+1     mandatory PAYOUT
N+2     optional TRANSPARENT_CHANGE
```

No other count, role, index, or ordering is valid. State and carrier sources
have one predecessor transaction hash. State source outpoint index is zero;
carrier ordinal `i` source outpoint index is `i+1`. Every carrier preserves its
exact ordinal lock, exact configured value, and `NONE` observation into its
successor.

There is no authoritative caller `actionKind` or `actionTag`. After parsing
state values as bounded integers, decode both state commitments with the full
exact `PoolStateFv1` codec. Each input must be exactly 128 bytes, must begin
with ASCII `PAF1`, must encode `stateCodecVersion=u16le(1)`, and must encode
the two reserved bytes as `0000`; any truncation, trailing byte, version
change, or nonzero reserved bit rejects. Let `manifestPoolInstanceId` be the
value recomputed from the lock-selected `PoolIdentityConfigV3Bytes` in section
6. The following equalities are mandatory before any action derivation:

```text
decode(stateSourceCommitment).poolInstanceId
  == manifestPoolInstanceId
decode(stateSuccessorCommitment).poolInstanceId
  == manifestPoolInstanceId
```

Validate both decoded states against the lock-selected base and lifetime
capacity, then derive:

```text
delta = stateSuccessorValue - stateSourceValue

delta == +10,000,000  => DEPOSIT, actionTag=00
delta == -10,000,000  => WITHDRAWAL, actionTag=01
otherwise             => reject
```

Only after this derivation may the validator derive the external input role,
reserve direction, payout presence/index, change position, output count, and
role tags. A display label is outside authority and, if supplied by a user
interface, is checked output only.

Both old and successor states satisfy all section-2 count/order/value
invariants using the manifest `stateCarrierBaseSats` and
`maxLifetimeDeposits`. A deposit additionally requires old
`depositCount < maxLifetimeDeposits`; a withdrawal never reopens deposit
capacity. For either action, `old.sequence < 0x7fffffffffffffff` and
`new.sequence = old.sequence + 1` under checked non-wrapping arithmetic;
values outside the runtime nonnegative-number domain, overflow, or wraparound
reject. The state transition, unchanged fields, note/nullifier active-field
rules, and exact value delta are all checked before an action is derived.

Fee and conservation checks use all introspected source/output values:

```text
fee = SUM(input source values) - SUM(output values)
0 <= fee <= lockSelectedFeePolicyMaxSats
poolFeeSubsidy = 0
```

Every individual value and every checked running input/output sum remains in
`MoneyRange`; overflow or an aggregate above `MAX_MONEY` rejects before fee
subtraction.

The external input and every payout/change role are token-free. A later real
transaction must authorize the external input using a current whole-output
binding mode; its signature bytes remain outside relation hashes to avoid
self-reference.

## 9. TxViewV3Bytes

The shared transaction view contains only lock-selected constants,
introspected facts, and deterministic checked derivations:

```text
ASCII("P3TV")
u16be(3)
derivedActionTag:u8
reserved:u8 = 00
transactionVersion:u64le
locktime:u64le
carrierCount:u32be
inputCount:u32be
inputRecords[inputCount]
outputCount:u32be
outputRecords[outputCount]
economics
```

Each input record is:

```text
wireIndex:u32be
derivedRoleTag:u8
derivedRoleOrdinal:u32be
outpointTxHashOpcodeOrder:bytes32
outpointIndex:u64le
sequence:u64le
sourceValueSats:u64le
LP(sourceLockingBytecode)
roleSelectedTokenObservationV3
derivedUnlockingDisposition:u8
```

Input role tags are state `00`, carrier `01`, deposit funding `02`, and fee
funding `03`. Dispositions are local state `00`, carrier session `01`, and
external authorization `02`.

Each output record is:

```text
wireIndex:u32be
derivedRoleTag:u8
derivedRoleOrdinal:u32be
valueSats:u64le
LP(lockingBytecode)
roleSelectedTokenObservationV3
```

Output role tags are state successor `10`, carrier successor `11`, payout
`12`, and transparent change `13`.

`derivedRoleOrdinal` is never caller-selected. It is fixed exactly as follows
for every input and output record:

```text
STATE, DEPOSIT_FUNDING, FEE_FUNDING,
STATE_SUCCESSOR, PAYOUT, TRANSPARENT_CHANGE:
  derivedRoleOrdinal = 0

VERIFIER_CARRIER and VERIFIER_CARRIER_SUCCESSOR at wire index i+1:
  derivedRoleOrdinal = i, where 0 <= i < carrierCount
```

Any different ordinal rejects even when the role tag and wire index are
otherwise correct.

The economics record is:

```text
ticketSats:u64le = 8096980000000000
derivedReserveDirection:u8          // 00 increase, 01 decrease
derivedFeeSats:u64le
lockSelectedFeePolicyMaxSats:u64le
derivedPayoutPresent:u8
derivedPayoutOutputIndex:u32be       // zero iff absent
derivedChangePresent:u8
derivedChangeOutputIndex:u32be       // zero iff absent
```

`TxViewV3Bytes` includes no network field, physical-chain claim, dynamic active
input index, caller action, caller digest, provenance object/root, full input
unlocking bytecode, proof bytes, or external signature. State unlocking bytes
are local execution material. Carrier unlocking bytes are bound separately and
completely below.

The shared validator additionally requires transaction version exactly `2`,
locktime exactly `0`, and every input sequence exactly `4294967295`. These are
fixed PoolAction codec constants, not caller or manifest selectors; the
introspected values remain encoded in the view so any mutation changes its
bytes before rejection.

## 10. Carrier frames and full-byte session

The proof-suite-independent outer frame is:

```text
SegmentFrameV3 =
  ASCII("P3SG") || u16be(3)
  || ordinal:u32be
  || inputIndex:u32be
  || payloadLength:u32be
  || payload[payloadLength]
```

The payload is nonempty and the frame is fully consumed. A structural carrier
unlocking bytecode is exactly:

```text
MinimalPush(SegmentFrameV3)
|| MinimalPush(StructuralRedeemV3(carrier_i))
```

No prefix, intermediate argument, alternative push, suffix, or trailing byte
is allowed. The full unlocking bytecode, each pushed element, and the redeem
script must each later satisfy the current 10,000-byte limits.

For manifest order `i=0..N-1`:

```text
CarrierSessionBytes =
  u32be(N)
  || SUM_i [u32be(i)
            || u32be(i+1)
            || LP(fullUnlockingBytecode_i)]

carrierSessionRoot =
  SHA256(ASCII("PoolActionFv2/carrier-session/v3") || 00
         || LP(CarrierSessionBytes))

ReconstructedEnvelopeBytes = payload_0 || ... || payload_(N-1)

ScheduleBytes =
  u32be(N)
  || SUM_i [u32be(i)
            || u32be(i+1)
            || u32be(cumulativeOffset_i)
            || u32be(payloadLength_i)]

envelopeRoot =
  SHA256(ASCII("PoolActionFv2/envelope/v3") || 00
         || LP(ReconstructedEnvelopeBytes))
```

Each full script is independently obtained with `OP_INPUTBYTECODE(i+1)`.
Missing, duplicate, reordered, swapped, differently framed, gapped,
overlapping, truncated, non-minimal, foreign-redeem, or trailing bytes reject.
Equal payload under different full script bytes changes `carrierSessionRoot`.

The selected proof suite must later freeze a canonical payload grammar and
segmentation. Identical-envelope resegmentation is therefore a deferred
selected-suite detection gate, not a false architectural rejection claim.

## 11. Context, session, and acyclic dependency graph

```text
contextDigest =
  SHA256(ASCII("PoolActionFv2/context/v3") || 00
         || LP(deploymentCommitment)
         || LP(TxViewV3Bytes))

sessionDigest =
  SHA256(ASCII("PoolActionFv2/session/v3") || 00
         || LP(contextDigest)
         || LP(carrierSessionRoot)
         || LP(envelopeRoot)
         || LP(ScheduleBytes)
         || LP(proofSuiteManifestDigest))
```

Supplied digests are comparison outputs only. The allowed dependency graph is:

```text
lock-selected manifest + introspected transaction
  -> deploymentCommitment + TxViewV3Bytes
  -> contextDigest
  -> selected proof public input and proof construction
  -> carrier payloads
  -> CarrierSessionBytes + ReconstructedEnvelopeBytes + ScheduleBytes
  -> carrierSessionRoot + envelopeRoot
  -> sessionDigest
```

No edge may return from `sessionDigest`, `carrierSessionRoot`, `envelopeRoot`,
`ScheduleBytes`, full carrier unlocking bytes, or a downstream provenance root
into proof/public-input or carrier-payload generation. A declared dependency
graph must be exact, acyclic, and reject any outer-root-to-proof edge.

While `proofSuiteStatus=UNSELECTED`, the digest is all zero and every otherwise
valid structural fixture returns exactly
`REJECT_UNSELECTED_PROOF_SUITE`. Payload bytes are structural test material,
not proof acceptance evidence.

## 12. Exhaustive field-source contract

Every binary-codec leaf has exactly one source class:

- `CODEC_CONSTANT`: magic, ABI version, reserved bytes, domains, fixed tags,
  and fixed ticket literal;
- `LOCK_SELECTED_EMBEDDED`: exact manifest-core and role-instance bytes parsed
  from redeems whose HASH160 is selected by the actual source locks;
- `INTROSPECTED`: transaction/source-output/unlocking bytes returned by exact
  current BCH inspection; or
- `DERIVED_AND_CHECKED`: one deterministic value computed from preceding
  classes and checked against topology, continuity, conservation, or local
  execution.

Caller data is not a source class. `COMPARISON_ONLY` metadata may exist outside
the runtime leaf roster but can never establish acceptance.

The package must publish a machine-readable exact leaf roster and source table.
The coverage validator exact-set compares them and rejects:

- a missing or unknown leaf;
- duplicate or multiply classified leaves;
- a wildcard or grouped entry that hides individual binary fields;
- a source class outside the four allowed classes;
- an asserted opcode which does not supply the mapped bytes;
- a derived value with an undeclared or cyclic dependency; or
- any authoritative caller/comparison field.

Coverage includes every magic/version/reserved/domain/tag byte, every manifest
and pool-identity-config field, every recomputed identity/commitment, carrier
count and layout entry, every role instance field, every tx-view record leaf,
every token observation component, every disposition, economics leaf, frame
field, full unlocking bytecode, payload, schedule offset/length, root/digest,
and role-local index/lock/redeem check.

## 13. Role-local consumption

The state covenant and every ordinal-specific carrier role independently:

1. authenticate its active redeem through the spent P2SH source lock;
2. parse the exact embedded manifest core and its own role instance;
3. check local `OP_INPUTINDEX` against the fixed role input index;
4. recompute and check the pool identity and deployment commitment;
5. inspect and encode the same complete `TxViewV3Bytes`;
6. inspect and consume all N complete carrier unlocking bytecodes;
7. verify each carrier final redeem, manifest prefix, ordinal, and source lock;
8. rebuild carrier session, envelope, schedule, context, and session values;
9. enforce exact state/config invariants, source/successor topology, role token
   language, action delta,
   payout, carrier continuity, and fee equations; and
10. reject because the proof suite is unselected.

`OP_INPUTINDEX` is role-local and excluded from `TxViewV3Bytes`. All shared
bytes and digests are byte-identical across roles. A later concrete covenant
must prove this consumption under current unmodified VM execution; structural
Node/Python validation alone is not that evidence.

## 14. Off-chain template and genesis provenance

Runtime authority never consumes a provenance DAG or evidence root. The
structural fixture compiler nevertheless records an acyclic derivation:

```text
StructuralProgramV3Bytes =
  00 00                 // PUSH_EMBEDDED_MANIFEST_CORE
  01 75                 // EMIT_OPCODE OP_DROP
  02 00                 // PUSH_ROLE_INSTANCE
  01 75                 // EMIT_OPCODE OP_DROP
  01 00                 // EMIT_OPCODE OP_FALSE

NormalizedRoleTemplateV3Bytes(roleClass) =
  ASCII("P3RT") || u16be(3)
  || roleClass:u8       // 00 STATE, 01 CARRIER
  || instructionCount:u8 = 05
  || StructuralProgramV3Bytes

TemplateSetV3Bytes =
  ASCII("P3TS") || u16be(3)
  || LP(ASCII("poolaction-fv2-structural-compiler-v3"))
  || LP(NormalizedRoleTemplateV3Bytes(00))
  || LP(NormalizedRoleTemplateV3Bytes(01))

protocolTemplateDigest =
  SHA256(ASCII("PoolActionFv2/protocol-template/v3") || 00
         || LP(TemplateSetV3Bytes))

preExistingAnchorDigest =
  SHA256(ASCII("PoolActionFv2/pre-existing-anchor/v3") || 00
         || LP(anchorTxHashOpcodeOrder)
         || LP(u32be(anchorOutputIndex)))

stateCategoryWire = anchorTxHashOpcodeOrder

genesisAncestryDigest =
  SHA256(ASCII("PoolActionFv2/genesis-ancestry/v3") || 00
         || LP(preExistingAnchorDigest)
         || LP(poolInstanceId)
         || LP(stateCategoryWire))
```

Each program instruction is exactly two bytes. Instruction tag `00` consumes
the exact manifest core supplied to the compiler and emits its canonical
minimal push; tag `02` consumes the exact role instance and emits its canonical
minimal push; tag `01` emits its second byte as an opcode and consumes no
operand. No other tag, opcode, instruction count, toolchain identifier, role
class, template byte, or trailing byte is valid. Applying this program is
exactly the `StructuralRedeemV3` compiler in section 7; the normalized templates
are provenance preimages, not executable BCH bytecode.

`PoolIdentityConfigV3Bytes` in section 6, rather than a second identity formula,
determines `poolInstanceId`. The anchor transaction hash supplies the exact
state category and is independently bound by `preExistingAnchorDigest`.
Those values determine manifest-core bytes, which determine every structural
redeem/lock. Only afterward may evidence encode concrete locks and a genesis
recipe. `genesisInitialStateValueSats` is provenance, not current-action
authority. A direct-genesis-current-state claim additionally requires the raw
genesis transaction/outpoint and exact equality to the current state source.
Absent that evidence, genesis and current state values remain distinct.

The closed structural-provenance schema records exactly: the template-set bytes
and digest; raw anchor hash/index and recomputed anchor digest; pool-identity
config bytes and recomputed ID; manifest-core bytes and deployment commitment;
for STATE and each carrier in ordinal order, the role-instance, redeem, lock,
and complete non-overlapping byte-origin intervals covering every byte; and
`genesisInitialStateValueSats`. A structural genesis recipe requires that last
value to equal the manifest `stateCarrierBaseSats`, but it is still not a raw
genesis transaction, token-issuance audit, outpoint, or deployment claim. Those
later artifacts may only be added as downstream evidence and never become an
upstream identity input.

The provenance package must record complete byte-origin intervals for every
structural redeem and lock byte. Neither the provenance object nor its digest
may occur in relation input, context, session, proof, or lock-selected manifest
core.

## 15. Responsibility and threat-model delta

All predecessor responsibilities in `responsibility-map-fv1.json` remain
required: profile domain, unique lineage, state codec, fixed ticket, reserve
conservation, note commitment/insertion/membership, spend authority, nullifier
derivation/uniqueness, payout, fee, context, carrier lifecycle, proof session,
canonical parsing, soundness, zero knowledge, recovery/liveness, and evidence
scope. ABI-v3 relocates none of them to a caller.

Additive ABI-v3 responsibilities are:

- `R3-LOCK-SELECTED-DEPLOYMENT`: source locks select exact embedded manifest
  and role bytes;
- `R3-DERIVED-ACTION`: action and all dependent topology/economics labels derive
  only from the exact state-value delta;
- `R3-ORDINAL-ROLE-IDENTITY`: every carrier has one manifest-fixed ordinal,
  source lock, successor lock, and local index;
- `R3-TOKEN-OBSERVATION`: role-selected closed token language excludes the
  known projection collision;
- `R3-ALL-CARRIER-BYTES`: every carrier unlocking byte, wrapper, frame,
  payload, and redeem is consumed in canonical order;
- `R3-EXHAUSTIVE-SOURCES`: every runtime binary leaf has exactly one permitted
  authenticated source;
- `R3-ACYCLIC-SESSION`: no outer/session/provenance result influences proof or
  payload generation; and
- `R3-STRUCTURAL-NONCLAIM`: always-false fixture artifacts can never establish
  deployment or execution credit.

The full predecessor threat model remains in force. Additive threats are:

- caller/coordinated manifest substitution under unchanged locks;
- caller action spoofing and inconsistent action topology;
- redeem or generic-carrier substitution under an unchanged source lock;
- ordinal lock/redeem/frame/source cross-splice;
- token-projection collision entering an admitted role;
- physical-chain identity overclaim;
- role relocation via evaluation-site-relative input index;
- non-minimal push, suffix, omitted byte, or same-payload/different-script
  framing attack;
- integer endian/sign/range/alias attack;
- field-source omission, duplication, wildcarding, or caller reclassification;
- proof/session/provenance dependency cycle; and
- structural proof-rejected artifacts misreported as accepting or measured.

Security goals, adversaries, admitted leakage, out-of-scope boundaries,
PQ-component disclaimers, and liveness requirements in the predecessor threat
model are unchanged. The static network tag supplies no physical-chain replay
guarantee.

## 16. Mandatory fail-first falsifiers

Before positive fixtures receive static closure credit, the ABI-v3 validator
must materialize and reject at least:

1. every manifest identity/config field changed while original locks/redeems
   remain: network tag, protocol-template digest, pool ID, anchor, ancestry,
   state category, ticket, state base, lifetime capacity, fee cap, suite
   status/digest, no-upgrade byte, carrier layout, and role maps;
2. coordinated manifest and both state-observation category changes under the
   original locks;
3. a distinct accepting or always-false redeem under an unchanged source lock;
4. generic carrier locks and N=3 ordinal lock/redeem/frame/source swaps,
   including coordinated reordering;
5. added, flipped, or removed caller action labels under unchanged transaction
   bytes;
6. `+ticket`, `-ticket`, zero, and at least one other delta against both deposit
   and withdrawal topologies;
7. missing, duplicate, wildcard, unknown, and reclassified variants for every
   field-source leaf;
8. exact runtime integer maximum acceptance plus `2^63`, negative, decimal
   alias, leading-zero, endian reversal, width, and overflow rejection; this
   includes `PoolStateFv1.{sequence,depositCount,withdrawalCount}=LE8(2^63)`
   and larger, acceptance of the sequence transition `2^63-2 -> 2^63-1`, and
   rejection of any increment from that maximum;
9. outer session/carrier/envelope/schedule/provenance dependencies injected into
   proof or payload generation;
10. non-minimal pushes, alternate wrappers, final-redeem mutation, prefix,
    suffix, truncation, length alias, and same-payload/different-full-script;
11. both members of the FT-only versus immutable-empty-NFT collision in every
    role where they are forbidden;
12. physical-chain identity and shared-dynamic-input-index claims;
13. genesis/current-state provenance mismatch and downstream-to-upstream
   identity cycles;
14. free or incorrectly recomputed pool identity, invalid suite-status/digest
   pairs, carrier counts `0` and `484`, an actual carrier unlock over 10,000
   bytes, and transaction version/locktime/sequence mutations; and
15. every retained predecessor falsifier family, with selected-proof or BCH-VM
   cases explicitly deferred rather than marked passed.

Each falsifier has a stable ID, one primary invariant, exact baseline and
mutation bytes, expected rejection layer/code, materialization status,
execution status, and evidence hash. Meta-tests of the contract do not count as
relation falsifier execution.

## 17. Required ABI-v3 evidence package

The new `poolaction-fv2-relation-closure-v3/` namespace must contain:

1. this exact identity and binary field order, with no v2 domain reuse;
2. closed schemas for comparison manifest core, raw/introspected transaction
   evidence, carrier session, relation input, structural provenance, derived
   result, and verifier-role consumption;
3. exportable deterministic encoder/parser/compiler helpers;
4. a machine-exact codec leaf roster and exhaustive field-source table;
5. responsibility and threat-model deltas preserving every predecessor ID;
6. a declared dependency graph and cycle validator;
7. fail-first unit tests for every architecture family above;
8. proof-rejected deposit and withdrawal fixtures for `N=1` and `N=3`;
9. pinned source records, outside-package review anchor, manifest, and
   package-local checksums; and
10. explicit nonclaims for proof, VM, standardness, transaction bytes,
    qualification, deployment, and activation.

After the package passes, two correctness-independent Node and Python
recomputers must take only raw/source evidence and agree byte-for-byte on all
manifest, role, lock, transaction-view, carrier, schedule, context, session,
and provenance outputs. Neither recomputer may import the other's codec or
generated expected values.

All four N=1/N=3 deposit/withdrawal fixtures and every materialized
architecture falsifier must replay independently. Selected-proof grammar,
current BCH execution, complete serialized transaction size, security,
zero-knowledge, and desktop proving remain later gates.

## 18. Gate boundary

Hard Gate 1 remains `HOLD` until the ABI-v3 package, two independent
recomputers, four fixtures, complete applicable falsifier execution, source
pins, and fresh independent root/SOL review all agree. Hard Gate 5 and every
proof, BCH execution, transaction, measurement, selection, deployment, and
activation gate remain closed.

The only possible positive outcome of this phase is static relation-authority
closure. It grants zero proof-system, soundness, privacy, VM, standardness,
complete-transaction, performance, field/hash selection, qualification,
deployment, or activation credit.

Stop with `HOLD` if any runtime leaf lacks a permitted authenticated source; a
caller selects deployment or action; a token collision enters the admitted
language; physical-chain identity is claimed; a shared digest includes dynamic
active input index; any carrier byte is unconsumed; any outer or provenance
result feeds proof/payload generation; a required materialized falsifier
accepts; source/fixture evidence is stale or incomplete; or this phase begins
proof-parameter selection or qualification execution.
