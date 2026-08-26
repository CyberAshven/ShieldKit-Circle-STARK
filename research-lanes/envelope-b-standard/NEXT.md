# Next (inner loop)

B is **136 095 B** (was 498 398). Completeness unchanged (FRI9, q=36, SHA-256, 36 unique orbits, on-chain foldPair/R/grind/algebraicC/bind-T). Dummy pad gone. standard=true fails only on size.

Checkpoints (save-and-continue, not done):

| mark | txBytes | inputs |
|---|---|---|
| `survey/artifacts/400000b` | 363237 |  |
| `survey/artifacts/300000b` | 298077 |  |
| `survey/artifacts/200000b` | 185523 | 39 |
| `survey/artifacts/150000b` | **136095** | 30 |

Named end remains ≤100 000 B + `createVirtualMachineBch2026(true)` accept. Only the human can declare that done.

## How 185 523 → 136 095

Chained domain points in fold ASM (one 10-bit scalar mul per query, then π / conditional (−x,−y) per layer) plus DEFINE lambda. That cut 2-fold op-cost ~2.94 M → ~1.65 M, so **4 unique-orbit folds per kernel** fit the standard density meter (in-context fold0 **98.3%** of op budget at 3953 unlocking). 9 fold kernels, not 18. 6-fold blows density even with packed ballast.

## Next construction (not landed)

Merkle payload is still ~58 kB (10 shards). JS unique-sibling table + compact paths is **~26 kB vs ~52 kB naive** (`test/merkle-multiproof.test.ts`). Isolated on-chain walker **accepts** 36 layer-0 openings at **35.5%** of the standard op budget (`scripts/proto-merkle-layer.ts`, 32-byte table items, `DEPTH-2-idx` OP_PICK). Production integration of layer-major kernels is not landed: thin layers (L5/L6) miss the density meter by **~400 ops** at ~2 kB unlocking (budget 800 ops/byte; extra redeem bytes also cost ~800 ops/byte via HASH256+push, so padding redeem does not help). Extra stack items above the unique-hash table shift OP_PICK and fail the walk.

Wall: layer-6 compact kernel **1 583 603 ops / 1 583 200 budget** (4 ops over at one point; ~400 over without redeem-tag). Next: a PICK formula that ignores ballast below the opening, or a concatenated-table SPLIT lookup whose copy cost scales with the small thin-layer tables — then bind-T single packed / R-slot loop if still over 100 kB.

4-fold cannot drop the packed density bind (98.3%). Do not add `KERNEL_UNLOCK_PAD_HIGH`. Production B remains the 10-shard 33-byte Merkle path at **136 095 B**.
