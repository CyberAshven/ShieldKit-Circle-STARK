# Completeness list (this ruleset)

**This lane’s completeness is [`RULES.md`](RULES.md).** No vk until every RULES line holds ([`ARGUMENT.md`](ARGUMENT.md)). Changing an item later is allowed. Changing it **silently** is not: edit this page in the same commit as the construction.

This is **B’s claim** (one consensus tx, ≤ 1 MB). A candidate that drops a row is a **different family** and a different vk, not “smaller B.”

**A** is a weaker lock. **C** is hops. The sibling 100 KB occupancy is a different box. None of those are this B.

## Must hold on B (one consensus transaction, ≤ 1 MB)

| # | Piece | Today on B | Allowed substitute |
|---|---|---|---|
| 1 | `FRI_VERSION` **11** | 11 | New family + new vk. No silent bump. |
| 2 | **36 unique first-fold orbits** | `FRI_QUERIES = 36`, rejection-sampled | Fewer orbits only with a new worksheet that still **≥ 100** conjectural bits, written here first |
| 3 | **On-chain foldPair** | 6 fused 6-query fold kernels | One orbit per redeem, if density holds without `KERNEL_UNLOCK_PAD`; fusion of fold+R for the **same** orbit, if density holds |
| 4 | **On-chain \(R\)** | fused leftover still vacuous N=0. Isolated packed leftover EQUALVERIFYs `(q−R)·Z` against booleanity C. Three extra kernels EQUALVERIFY opened T vs that C | Same check, cheaper fused ASM |
| 5 | **Grind 20** | grind kernel | Same bits, possibly in another kernel |
| 6 | **algebraicC** | residual interpolant point-check | Same binding |
| 7 | **bind-T** | Newton T interpolates `onChainCells`; cells match PAA1 | Same binding |
| 8 | **Note membership + nullifier + amount/auth on chain as SHA-256 AIR** | note-auth walks leaf/nf/createdLeaf and SHA-256-binds publics; unlocking silent (no rho/owner/amount8). Round-gates JS. Booleanity of occupancy T vs packed C is three extra kernels | Extra-input 576-column AIR; step-kernel equivalent for N notes; **not** leftover SHA-LDE |
| 9 | **Same-tx binds** | all 36 orbits see one PAA1 | Not C’s tape |
| 10 | Worksheet **≥ 100** conjectural bits | 128 = \(36\times(\log_2 16-1)+20\); field QM31 ~124 | 128 stays the **target**. Floor is 100. Do not keep the vk string if bits drop |
| 11 | **Consensus meters** | not yet this product | `createVirtualMachineBch2026(false)`: 1_000_000 B, 10_000 B unlocking/redeem. `standard=true` / Electrum is the sibling |
| 12 | **No dummy pad** | parent B padded high-index kernels to 6000 | Forbidden on a candidate that claims this list |
| 13 | **No preimage in unlocking** | note-auth unlocking is leaf/nf/amountCommit/createdLeaf; booleanity kernels carry LDE T, not TRACE-w | Required |

## Explicitly not on this list

- Policy 100 KB / Electrum. That is the sibling lane.
- Hidden pool TVL. `STATE_BASE`+reserve stays public.
- Lean HVZK theorem. Shipped \(R\) is not that theorem.

## Controls (must still compile)

- **A**: 4 R-slots, 1 fold, no note-auth, standard 100 KB.
- **C**: 19 standard hops, completeness split across txs.
- Sibling occupancy: 18-input fused skeleton ≤ 100 KB.

A candidate weaker than B and larger than C’s pay hop is neither.
