# PoolActionFv2 binary codec v2

Status: `NORMATIVE_OUTER_ABI_ONLY`.

This document is an exact field-order restatement of the v2 charter.  It is
the runtime preimage authority; JSON objects in this package are only an
interchange notation which `validate.mjs` maps to these bytes.  No JSON text,
property order, whitespace, or JSON digest is a runtime preimage.

All parsers fully consume their inputs.  `LP(x) = u32be(byte_length(x)) || x`.
All outer domains are exact ASCII followed by `00`.  `SHA256` is one SHA-256
hash; it is neither `HASH256` nor an agility slot.  Dynamic VM numbers are
nonnegative and at most `0x7fffffffffffffff` before their `u64le` encoding.
Transaction hashes use `OP_OUTPOINTTXHASH` byte order without reversal.

## TokenObservationV2

The encoder derives the tag from the manifest-fixed role.  It has no generic
CashToken branch.

```text
NONE =
  00 || 0000 || 0000 || 0000000000000000

STATE_MUTABLE_NFT_ZERO =
  01 || 0021 || Cwire[32] || 01 || 0080 || commitment[128]
     || 0000000000000000
```

State source and successor are the second form, with one embedded category and
128-byte commitments.  All carrier, external-funding, payout, and change
roles are the first form.  Fungible-only and immutable-empty-NFT native
records are not observations in the admitted relation language and reject.

## DeploymentManifestV2CoreBytes

```text
ASCII("P2DM") || u16be(2) || networkTag:u8 || 00
|| protocolTemplateDigest:bytes32 || poolInstanceId:bytes32
|| preExistingAnchorDigest:bytes32 || genesisAncestryDigest:bytes32
|| stateCategoryWire:bytes32 || ticketSats:u64le
|| feePolicyMaxSats:u64le || proofSuiteStatus:u8
|| proofSuiteManifestDigest:bytes32 || carrierCount:u32be
|| carrierLayout[N] || depositRoleMap || withdrawalRoleMap

carrierLayout[i] = ordinal:u32be || inputIndex:u32be || outputIndex:u32be
                 || expectedValueSats:u64le

depositRoleMap = 0:u32be || (N+1):u32be || 0:u32be || 00 || 0:u32be
               || 01 || (N+1):u32be
withdrawalRoleMap = 0:u32be || (N+1):u32be || 0:u32be || 01 || (N+1):u32be
                  || 01 || (N+2):u32be
```

`networkTag` is a static deployment-domain label: `00` mainnet, `01` chipnet,
`02` regtest.  It is not a physical-chain identity and never occurs in
`TxViewV2Bytes`.  This package fixes `proofSuiteStatus=00` and an all-zero
manifest digest.  The deployment commitment is:

```text
SHA256("PoolActionFv2/deployment/v2" || 00 || LP(DeploymentManifestV2CoreBytes))
```

## TxViewV2Bytes

```text
ASCII("P2TV") || u16be(2) || actionTag:u8 || 00
|| transactionVersion:u64le || locktime:u64le || carrierCount:u32be
|| inputCount:u32be || inputRecords[inputCount]
|| outputCount:u32be || outputRecords[outputCount] || economics
```

`actionTag` is `00` deposit or `01` withdrawal.  `inputCount=N+2`; the exact
input positions are state at zero, carriers at `1..N`, and the final external
input at `N+1`.  The exact outputs are state at zero, carrier successors at
`1..N`, then optional deposit change or mandatory withdrawal payout and
optional withdrawal change as in the manifest maps.

```text
inputRecord = wireIndex:u32be || roleTag:u8 || roleOrdinal:u32be
            || outpointTxHashOpcodeOrder:bytes32 || outpointIndex:u64le
            || sequence:u64le || sourceValueSats:u64le
            || LP(sourceLockingBytecode) || TokenObservationV2
            || unlockingDisposition:u8

outputRecord = wireIndex:u32be || roleTag:u8 || roleOrdinal:u32be
             || valueSats:u64le || LP(lockingBytecode) || TokenObservationV2

economics = 10000000:u64le || reserveDirection:u8 || feeSats:u64le
          || feePolicyMaxSats:u64le || payoutPresent:u8
          || payoutOutputIndex:u32be || changePresent:u8
          || changeOutputIndex:u32be
```

`unlockingDisposition` is `00` local state, `01` carrier session, or `02`
external authorization.  There is no active-input field, network field,
caller digest, provenance root, provenance DAG, or unlocking bytecode in the
shared view.  Each executing script performs its local
`OP_INPUTINDEX == fixedManifestInputIndex` check before consuming it.

## Carrier frames and shared session

```text
SegmentFrameV2 = "P2SG" || u16be(2) || ordinal:u32be || inputIndex:u32be
               || payloadLength:u32be || payload[payloadLength]

CarrierSessionBytes = u32be(N) || SUM_i(
  u32be(ordinal_i) || u32be(inputIndex_i) || LP(fullUnlockingBytecode_i))

ScheduleBytes = u32be(N) || SUM_i(
  u32be(ordinal_i) || u32be(inputIndex_i)
  || u32be(offset_i) || u32be(length_i))
```

Each full carrier unlocking bytecode is exactly two canonical-minimal BCH
pushes: the nonempty frame and the nonempty deployment-selected redeem script.
There is no other byte.  Every carrier script and pushed item is at most 10,000
bytes.  The state role consumes every full script through the manifest order;
each carrier consumes its own full script.  Payloads concatenate in manifest
order to form `ReconstructedEnvelopeBytes`.

```text
carrierSessionRoot = SHA256("PoolActionFv2/carrier-session/v2" || 00
                           || LP(CarrierSessionBytes))
envelopeRoot = SHA256("PoolActionFv2/envelope/v2" || 00
                      || LP(ReconstructedEnvelopeBytes))
contextDigest = SHA256("PoolActionFv2/context/v2" || 00
                       || LP(deploymentCommitment) || LP(TxViewV2Bytes))
sessionDigest = SHA256("PoolActionFv2/session/v2" || 00
                       || LP(contextDigest) || LP(carrierSessionRoot)
                       || LP(envelopeRoot) || LP(ScheduleBytes)
                       || LP(proofSuiteManifestDigest))
```

Displayed derived values are comparison values only.  This package has no
proof acceptance path: unselected manifests always result in
`REJECT_UNSELECTED_PROOF_SUITE`.

## Structural compiler and off-chain evidence

The fixture-only structural compiler is exact and always false:

```text
TemplateSetV2Bytes = "P2TS" || u16be(2) || LP(UTF8(toolchainId))
                   || LP(normalizedStateTemplateBytes)
                   || LP(normalizedCarrierTemplateBytes)

protocolTemplateDigest = SHA256("PoolActionFv2/protocol-template/v2" || 00
                                || LP(TemplateSetV2Bytes))

StructuralRedeemV2(role) = 20 || roleBindingDigest[32] || 75 || 00
StructuralLockV2(role) = a9 || 14 || HASH160(StructuralRedeemV2(role))[20] || 87
```

The anchor and all remaining derivations, including `P2GR` genesis recipe and
`P2PE` provenance evidence bytes, are exactly those in charter v2 lines
237–349.  The compiler's final `OP_FALSE` makes it non-deployable
proof-rejected evidence.  Provenance evidence, locks, interval maps, and
genesis records are off-chain only and cannot occur in a relation input,
context, or session preimage.
