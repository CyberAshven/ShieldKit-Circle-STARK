# Raw evidence transport, v1

The parser accepts exactly this JSON object shape; all `*Hex` values are
lowercase, unprefixed hexadecimal. `u64le` fields are exactly 16 hex digits and
`outputIndexHex` is exactly eight hexadecimal digits in the charter's `u32be`
encoding.

```text
{
  schema: "poolaction-fv2-recomputer-v3/raw-evidence-v1",
  manifestCoreHex: variable-length exact DeploymentManifestV3CoreBytes,
  anchor: { txHashOpcodeOrderHex: bytes32, outputIndexHex: u32be },
  interfaces: {
    sourceTableStatus: "NOT_SUPPLIED" | "SUPPLIED_UNVERIFIED",
    provenanceStatus: "NOT_SUPPLIED" | "SUPPLIED_UNVERIFIED"
  },
  transaction: {
    versionHex: u64le, locktimeHex: u64le,
    stateActiveRedeemHex: exact active STATE redeem bytes,
    inputs: [{
      outpointIndexHex: u64le, outpointTxHashOpcodeOrderHex: bytes32,
      sequenceHex: u64le, sourceValueSatsHex: u64le,
      sourceLockingBytecodeHex: bytes, unlockingBytecodeHex: bytes,
      token: { categoryHex: bytes, commitmentHex: bytes, amountHex: u64le }
    }],
    outputs: [{
      valueSatsHex: u64le, lockingBytecodeHex: bytes,
      token: { categoryHex: bytes, commitmentHex: bytes, amountHex: u64le }
    }]
  }
}
```

No raw token-kind or native-prefix field is accepted. The parser derives the
charter's unique state form from the authenticated projection
`category=Cwire || 01`, `commitment=PAF1[128]`, and zero amount; its native
prefix, where needed as a comparison artifact, is derivable as
`ef || Cwire || 61 || 80 || PAF1[128]`. `NONE` is exactly empty category,
empty commitment, and zero amount.

The charter mandates a package-local leaf roster, source table, and closed
provenance schema but does not provide their bytes. Their status fields are
therefore deliberately non-authoritative interface inputs. A future package may
replace them with exact artifacts, but this recomputer will never treat either
status as relation acceptance evidence.

`stateActiveRedeemHex` is comparison-only execution evidence. It must equal
the recomputed `StructuralRedeemV3(STATE)` and its HASH160 must equal the
state source lock. It is deliberately excluded from TxView, context, and
session derivations; carrier redeems are instead obtained from and parsed as
the final push of each complete carrier unlocking bytecode.
