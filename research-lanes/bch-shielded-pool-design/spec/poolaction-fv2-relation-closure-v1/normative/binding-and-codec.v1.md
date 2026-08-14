# PoolActionFv2 outer binding and codec v1

Status: `NORMATIVE_OUTER_RELATION_ONLY`.

This document defines the only transport and relation-binding hash for
PoolActionFv2.  It neither selects nor constrains a future Circle-FRI suite's
internal transcript primitive.

## Primitive encodings

`SHA256` means one SHA-256 compression-function hash, not `HASH256` and not an
algorithm-selection slot.  `u16be` and `u32be` are unsigned big-endian
integers.  `LP(x) = u32be(byte_length(x)) || x`; the length check rejects values
larger than `0xffffffff` bytes before serialization.

`CanonicalJsonV1(value)` is UTF-8 JSON with:

1. object member names sorted by Unicode code point;
2. no insignificant whitespace;
3. strings encoded by JSON's shortest required escapes;
4. only integers in the schema's stated ranges, never a floating-point value;
5. arrays in their supplied order; and
6. no omitted, duplicate, or unknown object members.

`canonicalAuthenticatedTxView` is `CanonicalJsonV1(authenticatedTxView)`.  It
contains every relation-relevant transaction field in the closed schema.  The
one envelope-bearing input is represented only by
`RAW_ENVELOPE_REPLACED_BY_EMPTY` and empty normalized unlocking bytes.  The raw
envelope is separately bound below.  Every entry in `currentBchIntrospection`
is required by the relation, but availability of a VM mapping is not asserted
by this artifact.

## Envelope wire format

The raw envelope is exactly:

```text
ASCII("PAF2") || u16be(1) || u16be(1) || sectionDirectory || sectionPayload

sectionDirectory = u8(0x01) || u8(0x01) || u16be(0) || u32be(offset) || u32be(length)
```

`0x01` is the sole critical section type, `OPAQUE_SUITE_PAYLOAD`.  It is opaque
until a separately reviewed suite manifest is selected.  The directory is 12
bytes, begins at byte 8, and the payload must begin at byte 20.  `offset` is
exactly 20; `length` is nonzero and exactly consumes the remaining raw bytes.
Thus unknown types, a non-critical flag, duplicate/order aliases, gaps,
overlap, truncation, and trailing bytes reject.  The canonical schedule bytes
are the 12 raw directory bytes.

## Derived values

```text
provenanceRoot = SHA256(ASCII("PoolActionFv2/provenance/v1") || 0x00
                        || LP(CanonicalJsonV1(provenanceWithoutRoot)))

contextDigest = SHA256(ASCII("PoolActionFv2/context/v1") || 0x00
                       || LP(UTF8(networkId))
                       || LP(canonicalAuthenticatedTxView)
                       || LP(provenanceRoot))

envelopeRoot = SHA256(ASCII("PoolActionFv2/envelope/v1") || 0x00
                        || LP(rawEnvelopeBytes))

sessionDigest = SHA256(ASCII("PoolActionFv2/session/v1") || 0x00
                       || LP(contextDigest)
                       || LP(envelopeRoot)
                       || LP(sectionScheduleBytes)
                       || LP(proofSuiteManifestDigest))
```

`provenanceWithoutRoot` is the provenance object with only `provenanceRootHex`
removed.  For every DAG node,
`node.digestHex = SHA256(ASCII("PoolActionFv2/provenance-node/v1") || 0x00 ||
LP(UTF8(node.id)) || LP(UTF8(node.type)) || LP(node.canonicalPayloadBytes))`.

Every displayed digest is a comparison value only.  Each consuming verifier
role must independently reserialize raw values, recompute it, and require byte
equality.  No context digest, session digest, schedule, envelope root,
provenance root, or fact callback can establish acceptance by itself.

## Token and provenance requirements

The state predecessor and successor are mutable CashTokens with amount `0` and
exactly 128 commitment bytes; category and capability are unchanged.  Every
carrier, transparent fee input, payout, and optional change is `NONE`.
Carrier-token presence is a relation error.

The provenance DAG has typed nodes and forward-only edges.  It starts from
normalized templates, typed parameters, and a pinned toolchain; it reaches the
protocol template digest, pool/manifest inputs, exact concrete state/carrier
locks, then the deterministic genesis recipe.  Each concrete-lock byte has one
and only one `byteOrigins` record.  No concrete lock, derived outpoint, or
manifest digest may appear in an ancestor node.

## Proof boundary

The typed `proofSuiteManifestDigestHex` is always present but is `UNSELECTED`
in this package.  Therefore every well-formed structural envelope has result
`REJECT_UNSELECTED_PROOF_SUITE`.  `ACCEPT`, `VALID`, or any equivalent result
is outside this version's schema and validator.
