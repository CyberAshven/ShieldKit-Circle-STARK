# Argument = vk (nonstandard QM31 family)

```
family = circle-fri-m31-qm31-t64-b16-q36-g20-fri10-bc64c18b9b96e9cb9f692199d0513b7915167ca601f1621b7590a584e04f42fc
vk = (none until every RULES.md line holds)
rulesSha256 = bc64c18b9b96e9cb9f692199d0513b7915167ca601f1621b7590a584e04f42fc
```

ethSTARK (ePrint 2021/582) query conjecture is named, speculative, not Stwo-128. JS-only `checkBatchSpends` extra notes are unfinished (RULES §3). SHA round-gates (`assertHashTraceConstraints`) are not miner-run.

**Starting artifact:** [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/) ([`START.md`](START.md)). Chipnet `60d186de…` / 99043 B. FRI10, QM31 124-bit. Packed hex pins sibling RULES `de1f4dcf…`; live compiles pin this RULES. Not the named end (§6 / §7 open).

This family: **B = M31** (circle, Merkle, qTable, layer-0 pairs, inverses, AIR cells). **F_fri = QM31** (7 λ, post-fold layers 1–6, final). **H = SHA-256**. qTable / layer-0 are 4-byte. Live note-auth unlocking is silent. Miner EQUALVERIFYs 32 bit-AIR path-walks of `A[0:4]‖L[0:4]‖N[0:4]‖T` (T from fold shards) against leftover `hashBitRoot`; grind carries the full sibling paths; leftover stays pair-bind. Thirty-six extra 576-column hash-AIR inputs remain a measured option. SHA round-gates are JS `assertHashTraceConstraints`.

## Soundness worksheet

| knob | value | status |
|---|---|---|
| Field | QM31 \(\log_2 p^4 \approx 124\) | written |
| Query conjecture | \(36 \times 3 + 20 = 128\) at rate \(2/B\) | **speculative**, named; not Stwo-128 |
| SZ | TRACE 64 over QM31 | not tens of bits |
| Hash-RO | SHA-256 | |
| min | \(\min(128, 124, \ldots) \approx 124 \ge 100\) | floor |

n=32/q=8 is refused. d5 is not the fold alphabet.

## Sibling squeeze (evidence, different family)

`a598b1f` plus the depth-6 SHA-LDE revert in `research-lanes/ideal-bch-shielded-pool-stark`. 36 occupancy-query compact-merkle walks in fold leftover (bundle 16, depth 6, randomizer deg 600). Bundle 32 made value-SPLITS worse. 36-input SHA AIR extra **94788 B**; occupancy+AIR ≈ **194 kB** (100 KB miss, 1 MB fit). RULES §7 still open there too.

## Parent freeze (evidence, different family)

`survey/artifacts/argument-freeze/`, vk `circle-fri-m31-t64-b16-q36-g20-fri9`, Chipnet `58b7df7f…` 91598 B. M31 challenges. Not this product.

## Checks the miner must run

Numbered lock checks of the occupancy 18-input fused fold+R skeleton plus QM31 λ mix and QM31 post-fold pairs. Merkle leftover-binds layers 0–6; fold `EQUALVERIFY`s its pair shard against that leftover. Note-auth walks leaf/createdLeaf, chains nf, `OP_SHA256`-binds publics plus amountCommit, rebuilds `A[0:4]‖L[0:4]‖N[0:4]‖T` from unlocking publics and fold shards, and path-walks those leaves against leftover `hashBitRoot` — same loop as `verifyFri`. It does not push rho/owner/amount8. `verifyFri` is a lab oracle. Mixed leaf/nf/amount-auth, mixed SHA-LDE prefixes, and mutated λ or post-fold pair: JS-fail and VM-reject (P0). Occupancy-valid `swapShaBitAndRegrind` proofs re-open queries via `proveFromTLde` and re-open shaBit paths/shards; JS `verifyFri` of the encode/decode object fails `sha-bit walk`; fold kernels accept; note-auth rejects. 576-column SHA round-gates are not yet miner-run.

Stwo KATs: CM31 `(1+2i)(4+5i)=(p−6)+13i`; QM31 `(1,2,3,4)*(4,5,6,7)=(p−71,93,p−16,50)`; inverses.

No dummy pad / leftover-fill / packTo / KERNEL_UNLOCK_PAD. TRACE 64, q 36, grind 20, blowup 16. Tx ≤ 1_000_000 B. Unlocking/redeem ≤ 10_000 B.
