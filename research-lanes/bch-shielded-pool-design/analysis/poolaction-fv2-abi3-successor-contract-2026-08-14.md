# PoolActionFv2 ABI-v3 successor checkpoint — 2026-08-14

Status: `AUTHORIZED_FOR_SUCCESSOR_CHARTER_DRAFT_ONLY_GATE_1_HOLD`.

This note freezes the smallest byte-level repair to the failed ABI-v2 route.
It is an architecture checkpoint, not a normative charter or an implementation.
It authorizes no proof-system selection, BCH VM execution, measurement,
deployment, registry event, or activation.

## Identity and namespace

PoolActionFv2 remains the relation identity; ABI-v3 is a new encoding and
runtime-authentication revision:

```text
relationId      = PoolActionFv2
relationVersion = 2
abiVersion      = 3
```

This resolves the naming ambiguity explicitly: `Fv2` and relation version `2`
remain the product/relation identity, while charter/package revision v3 and
`abiVersion = 3` identify the repaired ABI. No v2 magic, schema identifier,
fixture format, checksum namespace, package path, or hash domain may be reused.
All new domains end in `/v3` and every ABI-bearing binary header encodes `3`.

ABI-v2 remains immutable failed-route evidence. Its passing self-checks and
raw-to-KAT recomputations do not qualify ABI-v3.

## Lock-selected deployment authority

The deployment manifest must be selected by the actual spent source locks,
not by a caller object that a validator merely rehashes.

```text
deploymentCommitment =
  SHA256("PoolActionFv2/deployment/v3" || 00
         || LP(DeploymentManifestV3CoreBytes))

RoleInstanceV3Bytes =
  "P2RI" || u16be(3)
  || roleTag:u8
  || ordinal:u32be
  || fixedInputIndex:u32be
  || fixedOutputIndex:u32be
```

The first structural compiler is deliberately proof-rejecting:

```text
StructuralRedeemV3(role_i) =
  MinimalPush(DeploymentManifestV3CoreBytes)
  || OP_DROP
  || MinimalPush(RoleInstanceV3Bytes(role_i))
  || OP_DROP
  || OP_FALSE

StructuralLockV3(role_i) =
  OP_HASH160
  || Push20(HASH160(StructuralRedeemV3(role_i)))
  || OP_EQUAL
```

`DeploymentManifestV3CoreBytes` excludes concrete redeems and locks, so this
construction is acyclic. The manifest bytes are literally committed by the
spent P2SH source lock. A caller-decoded manifest is comparison input only.

The successor charter must require all of the following:

- The state source and successor locks equal the state role instance at
  ordinal 0, input 0, output 0.
- Carrier `i` source and successor locks equal the carrier role instance at
  ordinal `i`, input `i + 1`, output `i + 1`.
- Each carrier unlocking bytecode's final redeem push is the exact
  ordinal-specific redeem selected by that source lock.
- Each executing role checks local `OP_INPUTINDEX` against its fixed absolute
  role index.
- Every sibling redeem contains a byte-identical manifest-core prefix.

Ordinal-specific carrier redeems are the frozen repair. A generic positional
carrier could be sound under a different contract, but would contradict the
failed ABI-v2 fixed-per-role-index promise and is therefore not silently
substituted here.

## Transaction-derived action authority

Caller `actionKind` and `actionTagHex` are removed as authoritative fields.
After introspecting and range-checking the state source and successor values:

```text
delta = stateOutput.valueSats - stateSource.valueSats

delta == +10_000_000  => DEPOSIT / actionTag 00
delta == -10_000_000  => WITHDRAWAL / actionTag 01
otherwise             => reject
```

Only after deriving the action may the relation derive external-input roles,
reserve direction, payout presence and index, change position, output count,
and role tags. A human-readable action label may exist only as a checked
display value outside the authority preimage.

## Exhaustive field-source contract

Every binary-codec leaf has exactly one source class:

- `CODEC_CONSTANT`: magic, ABI version, reserved bytes, domains, fixed tags.
- `LOCK_SELECTED_EMBEDDED`: manifest-core and role-instance bytes selected by
  exact spent P2SH locks.
- `INTROSPECTED`: transaction, source-output, and unlocking bytes obtained by
  exact BCH introspection.
- `DERIVED_AND_CHECKED`: deterministic values derived from the preceding
  classes and locally checked.

Caller input is never a source class. The coverage validator must exact-set
compare the codec leaf roster with the source table and reject missing,
duplicate, wildcard-only, unknown, or multiply classified leaves. Coverage
includes headers, magic/version/reserved bytes, carrier count, every role tag,
ordinal and disposition, all frame and payload fields, schedule offsets,
economics leaves, roots, and local role checks.

## Provenance, integers, and dependency order

`genesisInitialStateValueSats` is genesis provenance, not current-action
authority. A claim that the current state is the direct genesis output also
requires raw genesis transaction/outpoint evidence and equality to the current
state source. Otherwise genesis and current values remain explicitly separate.

Runtime non-negative integers use exact eight-byte little-endian evidence with
the high byte in `00..7f`; display decimals are derived. The maximum accepted
value is `0x7fffffffffffffff`; `0x8000000000000000`, aliases, leading-zero
decimal forms, negatives, and overflow must reject.

The dependency DAG is:

```text
lock-selected manifest + introspected transaction
  -> contextDigest
  -> proof/public input
  -> carrier payloads
  -> carrierSessionRoot/envelopeRoot/schedule
  -> sessionDigest
```

No dependency may return from a session, carrier, envelope, or schedule root
into proof/public-input or carrier-payload generation. Canonical segmentation
remains a selected-proof-suite gate and must not be claimed by this structural
compiler.

## Fail-first falsifiers required before new positive fixtures

The ABI-v3 package must first materialize and execute rejecting tests for:

- network, protocol-template digest, pool ID, token category, fee cap, or
  carrier-layout mutation with original locks and redeems;
- coordinated manifest plus state-observation category mutation with original
  locks;
- distinct redeem replacement under an unchanged source lock;
- N=3 ordinal-carrier lock/redeem swaps, including coordinated frame and source
  reordering;
- caller action-label flip or removal with unchanged transaction bytes;
- `+ticket`, `-ticket`, zero, and other state deltas against both topologies;
- removal, duplication, wildcarding, or reclassification of every source-table
  leaf;
- integer boundary, alias, sign, and overflow cases; and
- an outer session/root dependency inserted into proof-payload generation,
  which must be rejected as a cycle.

Identical-envelope resegmentation is deferred until a selected suite freezes a
canonical segment grammar; it is not misreported as a structural rejection.

## Gate ruling

This checkpoint closes the design question only. Hard Gate 1 remains `HOLD`
until a fresh ABI-v3 charter/package, two independent recomputers, and the
materialized falsifiers agree byte-for-byte. BCH VM execution, whole-transaction
standardness and size, selected proof grammar, security, and performance remain
later gates. Hard Gate 5, selection, deployment, and activation remain closed.
