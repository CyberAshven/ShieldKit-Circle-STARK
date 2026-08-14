# PoolStateFv1 native commitment codec

`PoolStateFv1` is the complete 128-byte mutable-NFT commitment. It is not a
32-byte digest with an external state preimage. The layout is frozen for the
backend-neutral relation; the algorithms which produce the three 32-byte
identifiers remain immutable `PoolConfigFv1` selections.

| Offset | Length | Field | Canonical encoding |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | ASCII `PAF1` (`50 41 46 31`) |
| 4 | 2 | state codec version | unsigned little-endian integer, exactly `1` |
| 6 | 2 | reserved | exactly zero; any other value is invalid |
| 8 | 8 | sequence | unsigned 64-bit little-endian |
| 16 | 8 | deposit count | unsigned 64-bit little-endian |
| 24 | 8 | withdrawal count | unsigned 64-bit little-endian |
| 32 | 32 | pool instance ID | exact `PoolConfigFv1` identity output |
| 64 | 32 | note root | canonical selected note-accumulator root |
| 96 | 32 | nullifier root | canonical selected nullifier-set root |

No field is variable-length. There is no padding other than the two reserved
zero bytes, no byte-order alternative, no ignored suffix, and no version
downgrade path.

For ticket value `T = 10,000,000` satoshis, maximum lifetime deposits `C`, and
fixed state-carrier base `B`, every accepted state must satisfy:

```text
0 <= withdrawalCount <= depositCount <= C
outstandingTickets = depositCount - withdrawalCount
reserveSats = outstandingTickets * T
stateUtxoValueSats = B + reserveSats
```

All additions, subtractions, multiplications, and the final UTXO value must be
checked without wraparound and must remain valid BCH monetary values. `C` is a
lifetime append bound, not a maximum-live-ticket counter. Once
`depositCount == C`, new deposits reject permanently, even after withdrawals;
otherwise valid withdrawals remain enabled. This finite lifetime is accepted
for Fv1 simplicity and must be disclosed by deployment and wallet tooling. `C`
is constrained by the selected base value and current BCH rules, not the full
`uint64` range.

The genesis state uses sequence, deposit count, and withdrawal count zero; the
selected empty note and nullifier roots; and the immutable pool instance ID.
That ID is derived before the genesis transaction from a pre-existing deployment
anchor, the token category, and normalized protocol templates. It must not
commit the genesis state outpoint or concrete script bytes that contain the ID.
After genesis is constructed, its state/carrier outpoints and exact deployed
lock hashes are recorded as downstream recovery/audit data. Token issuance,
base value, empty roots, template instantiation, and the absence of a surviving
minting authority must be audited before deployment.

Transition rules are exact:

- deposit: `sequence += 1`, `depositCount += 1`, withdrawal count unchanged;
- withdrawal: `sequence += 1`, `withdrawalCount += 1`, deposit count unchanged;
- deposit changes only the note root;
- withdrawal changes only the nullifier root; and
- every successor commitment retains magic, version, reserved bytes, and pool
  instance ID exactly.

The decoded JSON representation is validated by
`pool-state-fv1.schema.json`. A codec implementation must additionally prove
that every decoded field exactly reserializes to `serializedHex`; schema
validation alone is not that proof.
