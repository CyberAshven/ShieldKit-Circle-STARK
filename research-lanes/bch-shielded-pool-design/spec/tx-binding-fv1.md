# PoolActionFv1 transaction and proof binding

This document freezes the non-circular binding boundary. It does not select the
32-byte digest primitive. `PoolConfigFv1` selects that primitive immutably, and
the same implementation must be used by the prover, wallet, settlement
covenant, and every verifier carrier.

## Construction order and circularity boundary

The wallet performs these steps:

1. reconstruct the authoritative state and every persistent carrier outpoint;
2. choose the public payout, one external funding input, and optional
   transparent change;
3. serialize all transaction fields except input unlocking bytecodes;
4. encode and digest `TxContextFv1`;
5. construct the fixed `PoolActionFv1Statement` containing that digest;
6. generate one proof and its canonically scheduled carrier sections;
7. populate the state and verifier-carrier unlocking bytecodes;
8. sign the final external input using a whole-output-binding BCH signature
   mode; and
9. run complete transaction preflight without patching a proof or signature.

Any change before step 6 requires a new proof. Any change after step 8 requires
a new external-input signature. A stale-state retry starts again at step 1.

The context deliberately excludes all input unlocking bytecodes, proof bytes,
proof wrappers, and external signatures. Including those bytes would make the
proof or signature commit to itself. No other transaction field is excluded.
The transaction ID of the transaction under construction is also absent; the
old state and carrier outpoints are included, while successor outputs are bound
by index and exact contents.

## Primitive encodings

All integers are unsigned little-endian unless an `i` prefix is shown. All
lengths are byte lengths. Every reserved byte is zero. Every byte sequence has
exactly one representation; trailing bytes and non-minimal alternate sections
are invalid.

```text
u8       1 byte
u16le    2 bytes
u32le    4 bytes
u64le    8 bytes
i64le    8-byte two's-complement signed integer
bytes32  exactly 32 bytes
bytes128 exactly 128 bytes
varbytes u16le length followed by exactly that many bytes
```

`varbytes` is limited to 10,000 bytes. A length which does not consume the
entire declared field is invalid. This protocol encoding does not use BCH
CompactSize and therefore has no CompactSize aliases.

Network tags are `0x00` mainnet, `0x01` chipnet, and `0x02` regtest. Action tags
are `0x00` deposit and `0x01` withdrawal.

Input role tags are:

```text
0x00 STATE
0x01 VERIFIER_CARRIER
0x02 DEPOSIT_FUNDING
0x03 FEE_FUNDING
```

Output role tags are:

```text
0x10 STATE_SUCCESSOR
0x11 VERIFIER_CARRIER_SUCCESSOR
0x12 PAYOUT
0x13 TRANSPARENT_CHANGE
```

Each role is followed by a `u16le` role ordinal. State and external roles use
ordinal zero. Carrier ordinal `i` is the zero-based carrier-manifest position.

### Canonical token record

```text
tokenKind u8:
  0x00 none
  0x01 fungible only
  0x02 immutable NFT, optionally with fungible amount
  0x03 mutable NFT, optionally with fungible amount
  0x04 minting NFT, optionally with fungible amount

if tokenKind != 0x00:
  categoryWire32
  fungibleAmount u64le
  commitmentLength u8
  commitment[commitmentLength]
```

For `none`, no other token bytes follow. For fungible-only,
`commitmentLength` is zero. For every NFT, commitment length is 0 through 128
as permitted by the selected current BCH rules; `PoolStateFv1` specifically
requires kind `0x03` and length 128. Category byte order is the exact order
returned and compared by the selected BCH introspection adapter, recorded in
known-answer tests. Alternate category reversal is invalid.

## TxContextFv1 preimage

```text
ASCII "PCTX"                              4
contextCodecVersion = 1                   u16le
networkTag                                u8
actionTag                                 u8
poolInstanceId                            bytes32
carrierManifestDigest                     bytes32
proofSecurityProfileDigest                bytes32
transactionVersion = 2                    u32le
locktime = 0                              u32le
inputCount                                u16le

for each input in wire order:
  inputIndex                              u16le
  inputRoleTag                            u8
  roleOrdinal                             u16le
  outpointTxidWire                        bytes32
  outpointIndex                           u32le
  sequence = 0xffffffff                   u32le
  sourceValueSats                         u64le
  sourceLockingBytecode                   varbytes
  sourceTokenRecord                       token record

outputCount                               u16le

for each output in wire order:
  outputIndex                             u16le
  outputRoleTag                           u8
  roleOrdinal                             u16le
  valueSats                               u64le
  lockingBytecode                         varbytes
  tokenRecord                             token record
```

The context digest is exactly:

```text
ContextDigest(
  ASCII "PoolActionFv1/TxContext" || TxContextFv1Preimage
)
```

and must be 32 bytes. The selected function, padding, and one-shot/incremental
equivalence tests are part of the immutable security profile.

Every field duplicated between the direct `PoolActionFv1Statement` projection
and `TxContextFv1` must compare byte-for-byte equal before proof acceptance.
This includes pool/action/security/manifest identities, state outpoint, value,
lock, token category/capability/zero fungible amount/commitment, payout, fee,
and role indices. All verifier carriers absorb the same canonical statement
bytes and context digest; a second independently supplied statement or digest
is never accepted as another source of truth.

## StatementCoherenceFv1

The following is normative accepted-language logic, even where JSON Schema
cannot express the cross-field equality. P1's semantic oracle must enforce each
row independently and provide one rejection vector per equality family.

| Statement projection | Required source/equality |
| --- | --- |
| `transactionContextDigest` | exactly recompute the selected digest over the fully consumed canonical `TxContextFv1` preimage |
| pool, network, action, proof-security profile, carrier manifest | equal the context header and the immutable deployment configuration |
| old/new state pool IDs | decoded 128-byte states both equal the top-level pool ID |
| `stateInput` | exactly project context input `0`, including outpoint `vout=0`, sequence, source value, lock, mutable NFT category, zero fungible amount, and 128-byte commitment |
| `stateOutput` | exactly project context output `0`, including value, lock, mutable NFT category, zero fungible amount, and 128-byte commitment |
| deposit note event | nonzero top-level commitment; equals the AIR-derived commitment inserted at old `depositCount`; nullifier and payout are canonical zero/absence |
| withdrawal nullifier event | nonzero top-level nullifier; equals the AIR-derived value inserted into the nullifier set; note commitment is canonical zero |
| withdrawal payout | exactly project output `N+1`, including token-free value and lock; deposit has no payout role |
| fee object | external input is exactly `N+1`; optional change is the final output; `feeSats = sum(source values) - sum(output values)`; token fields and roles agree with context |
| every verifier role | absorb byte-identical fixed statement bytes and the same context digest, proof-session header, and security profile |

For a withdrawal payout lock `L`, the direct defense-in-depth digest is:

```text
PayoutLockDigestFv1(L) = ConfiguredContextDigestAlgorithm(
  ASCII "PoolActionFv1/PayoutLock" || u16le(byteLength(L)) || L
)
```

Deposit uses 32 zero bytes. The length is bounded by the canonical `varbytes`
rule, and no other digest algorithm or domain tag is accepted.

Input and output array indices must start at zero, increase by one, and equal
their wire positions. Counts must equal the arrays exactly. Every input source
value, source lock, and CashToken component is part of the context even though
those data are not serialized in the spending transaction itself.

## Fixed role order

For carrier count `N >= 1`:

```text
inputs:
  0       STATE
  1..N    VERIFIER_CARRIER ordinals 0..N-1
  N+1     DEPOSIT_FUNDING or FEE_FUNDING

deposit outputs:
  0       STATE_SUCCESSOR
  1..N    VERIFIER_CARRIER_SUCCESSOR ordinals 0..N-1
  N+1     optional TRANSPARENT_CHANGE

withdrawal outputs:
  0       STATE_SUCCESSOR
  1..N    VERIFIER_CARRIER_SUCCESSOR ordinals 0..N-1
  N+1     PAYOUT
  N+2     optional TRANSPARENT_CHANGE
```

All persistent inputs form one predecessor bundle. The state source outpoint
must have output index `0`. For carrier ordinal `i`, the carrier source outpoint
must have the same transaction ID as the state source and output index `i+1`.
Genesis and every accepted action create exactly that successor bundle at
outputs `0..N`. Matching lock/value/token data from any other outpoint is not a
valid carrier. This rule makes the public state tip sufficient to reconstruct
every carrier outpoint without storing an additional carrier-outpoint root.

The external funding input is exactly one token-free signed input. Transparent
change is either absent or exactly the final token-free output. No unspecified
input or output is accepted.

Each carrier source/successor pair has the same satoshi value, exact configured
lock, and exact configured token record. The state source/successor pair has the
same configured lock, category, mutable capability, and fungible amount exactly
zero; only its 128-byte state commitment and the exact ticket reserve delta may
change.

The configured locks are downstream instantiations of normalized typed script
templates. Identity derivation is strictly acyclic:

```text
normalized protocol/script templates
  -> protocolTemplateDigest
  -> poolInstanceId(pre-existing deployment anchor, token category, config)
  -> carrierManifestDigest(normalized roles, values, tokens, proof schedule)
  -> concrete state/carrier locks
  -> genesis transaction and recorded outpoints/lock hashes
```

`protocolTemplateDigest` contains typed placeholders, not a concrete script
containing `poolInstanceId`. `carrierManifestDigest` may bind
`poolInstanceId`, but contains normalized role templates rather than concrete
carrier scripts containing `carrierManifestDigest`. The resulting concrete
scripts pin the upstream digests and preserve their own exact successor bytes.
The genesis transaction ID/outpoints and hashes of concrete deployed locks are
downstream audit/recovery records and are never fed back into an upstream
digest.

## Fixed proof statement encoding

The Circle-FRI transcript absorbs the following fixed-order statement bytes
before any prover commitment:

```text
ASCII "PAST"                              4
relationVersion = 1                       u16le
profileTag = fixed-ticket-serial-pool     u8 = 0x01
networkTag                                u8
actionTag                                 u8
poolInstanceId                            bytes32
proofSecurityProfileDigest                bytes32
carrierManifestDigest                     bytes32
oldStateOutpointTxidWire                  bytes32
oldStateOutpointIndex = 0                 u32le
oldStateValueSats                         u64le
oldStateBytes                             bytes128
newStateOutputIndex = 0                   u16le
newStateValueSats                         u64le
newStateBytes                             bytes128
ticketSats = 10000000                     u64le
reserveDeltaSats                          i64le
noteCommitmentOrZero                      bytes32
nullifierOrZero                           bytes32
payoutOutputIndexOrffff                   u16le
payoutSatsOrZero                          u64le
payoutLockingBytecodeDigestOrZero         bytes32
feeInputIndex                             u16le
transparentChangeOutputIndexOrffff        u16le
feeSats                                   u64le
maxFeeSats                                u64le
transactionContextDigest                  bytes32
```

`0xffff` is the only absent output-index marker. Deposit uses zero payout
amount/digest and a zero nullifier. Withdrawal uses a zero note commitment and
must use a nonzero nullifier. The full state/source/successor locks, token data,
payout lock, and fee/change output are bound by `transactionContextDigest`; the
statement includes the payout lock digest as a direct defense-in-depth public
input.

## Enforcement split

- The state covenant reconstructs or field-checks the context against actual
  introspection, enforces counts/order, state and carrier successor continuity,
  fixed reserve delta, payout, and fee equations.
- Each verifier carrier pins its own manifest role and successor, parses its
  exact proof section, and verifies the same fixed statement and proof-session
  header. Sections are non-overlapping and collectively exhaustive.
- The external funding input independently authorizes the final outputs. Its
  unlocking script and signature are canonical for its selected standard
  template but remain outside the proof context. Any signature-hash mode must
  bind all inputs and all outputs: for BCH signatures the hash-type byte is
  exactly `SIGHASH_ALL | SIGHASH_FORKID` (`0x41`), with `ANYONECANPAY`,
  `SIGHASH_NONE`, and `SIGHASH_SINGLE` forbidden.
- Whole-transaction consensus supplies the final input/output value balance and
  requires every input to succeed.

A component test which accepts without a complete transaction is insufficient.
Required substitutions include old state, carrier lock/value/ordinal, external
source, payout, change, input/output ordering, proof section, version, locktime,
and sequence.
