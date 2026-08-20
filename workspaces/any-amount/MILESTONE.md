# Chipnet milestones

**Network:** BCH Chipnet only. Never mainnet.  
**Unlocking + redeem:** ≤ 10 KB (Velma).  
Old txids stay. They are not relabeled.

## Now (2026-08-20)

Any-amount pool. Circle FRI is **plugin #1**, not the pool identity.

| Knob | Live | Notes |
| --- | --- | --- |
| `--envelope a` / `b` / `c` | A 100 KB (1 fold + 4 R-slots); B 1 MB 36-query R; C extra fold slices + pay hop = B | Dummy cargo is not the verifier. Unlocking 10 KB **per input** — chunk kernels. |
| `--hash sha256` / `blake2s` / `poseidon2-m31` | default **sha256** (CashVM `OP_SHA256`) | Poseidon2-M31 is toorik Grain (ePrint 2023/323), not a lock opcode. |
| `--plugin` | **circle-fri-m31** first; `hash-lab-v0` lab stub | Reserved sandwiches: `goldilocks-fri` (AIR+FRI), `air-whir` (AIR+WHIR), `spartan-whir` (Spartan+WHIR), `groth16` (pairing). `whir` is a PCS; `spartan` is an IOP. |

Envelope **B** is the hole-free statistical-soundness envelope (C pay hop is the same spend). One consensus tx, Circle FRI M31, TRACE=64, FRI_N=1024, **36 unique-orbit** queries, 20-bit grind, FRI_VERSION 8. CashVM kernels (chunked, 10 KB unlocking each):

| Kernel | On-chain check |
| --- | --- |
| Grind | SHA256(grindSeed \|\| nonce \|\| `"grind"`) has 20 leading zero bits; FS seed from packed AIR |
| FRI ×10 | Merkle auth of openings; L0 felt binds `qTable[slot]`; pair blob = merklized `left\|\|right` |
| Fold ×36 | Remaining FRI layers (`COMMITTED_LAYERS` = 7) + foldPair, one query per redeem |
| Bind-T | Newton T interpolates packed cells |
| algebraicC | Point checks (digest cell, seq+1, action 1\|2, UTXO conservation). Not a FRI interpolant rewrite (`FRI_VERSION` stays 8) |
| Slot ×36 | FS index recomputed; `R_on(i)+Z(i)·R_off(i)`; `(qTable−R)·Z` equals AIR numerator from T. Masked nTable cannot cancel R |
| Note-auth ×1 | SHA-256 note preimage → leaf; Merkle walk to NFT `noteRoot`; `nf = SHA256(instance\|\|owner\|\|rho)`; `SHA256(oldNfRoot\|\|nf)` (withdraw) or equal nfRoots (deposit). Change-note append when `createdSteps` is non-empty. A has no room for this kernel. |

**99 KB packing is not the verifier.** `packTo` defaults to **0**. Dummy `OP_DROP` leftover-fill cargo is not foldPair / C=QZ / R / note-auth. Density pad on high-index FS kernels (unlocking longer so `800×(41+unlocking)` covers the hash loop) is the VM meter, not cargo. Leftover 1 MB on B is unused headroom for more real kernels.

Envelope **C** has no separate soundness story: **pay hop = B**. Tape hops are extra real fold/R-slot slices (**18 hops × 2 queries** = 36 extra orbits), each ≤ 100 KB. They do not accumulate 36 same-tx binds across txs. Skip-tape still hits the B pay hop.

Envelope **A** is the 100 KB relay path: 1 fold + **4** R-slots + grind + algebraicC. Hole-free 36-query does not fit A; do not drop B’s 36 queries to make A look hole-free.

Compile size proof (not a land): A **98750 B** (unlock 2685), B **571997 B** (unlock 5405), 1 MB headroom **428003 B** unused (not cargo). Each unlocking ≤ 10 KB. Gating VM tests: honest 36-query B accepts; cooked viewing-commit / recooked Q/N / cooked pair blob reject; false AIR (`mutateTraceAndProve`) rejects on-chain; fake note preimage / cooked Merkle path / cooked nfRoot reject on the note-auth kernel.

### On Chipnet this session

These txs landed **before** grind/algebraicC kernels. `b6818bd2…` is the 479 KB 36-fold land, not the hole-free kernel. Do not relabel it. Next B/C land is a new txid.

**A — standard, Electrum, 82365 B**

| | |
| --- | --- |
| Successor | `05f17bf1374f8bab5718bc7e929abe991cc709d1f2c0e881ab0f05bacb28b55c` |
| Genesis | `dd3894fc1a5daf8620bbe36867b1674ef43bdb2d772a881f54b6546f45ddbfb5` |
| Kernels | `7b1e321be30309cab3a36c9e7eb6c2334d065c1cc88136cc298992b87f2738e9` |
| Prep | `c1c0f26d24be919211bd09a5ca94c43af0c48e62fb549cebcc7634d54b1ac09b` |

https://chipnet.imaginary.cash/tx/05f17bf1374f8bab5718bc7e929abe991cc709d1f2c0e881ab0f05bacb28b55c

**B — consensus, JSON-RPC mempool, 479356 B, 84 vin**

| | |
| --- | --- |
| Successor | `b6818bd260a9fff6803195fcd14d276116eedc25a36686b2eaba5655d788b002` |
| Path | local BCHN `sendrawtransaction` (`acceptnonstdtxn=1`). Public Electrum will not show it. |

**C — chained tape + last-hop pay (pre-pack land)**

| Hop | Role | Bytes | Payouts | Txid |
| --- | --- | --- | --- | --- |
| 0 | tape | 267 | 0 | `6d242fee88f61ee22af83902dccdb204d6d37a39a741376d416a5ab48a51d967` |
| 1 | tape | 267 | 0 | `ec4cd5b3a10a23ebc4b82786a1d06dc71bfffce5fdb5a81f2be2080d03df9601` |
| 2 | pay | 82506 | 1 | `6f9fd1d07594674cf3ec3d5c83312ee5e77a0df6597ddd97ae3f423486970b57` |

Genesis `5f9701e4f52c3e0c74bc07c405b5c0cb75080f774b465ef7b5917d656c5060d3`.  
https://chipnet.imaginary.cash/tx/6f9fd1d07594674cf3ec3d5c83312ee5e77a0df6597ddd97ae3f423486970b57

CLI: `pool land --envelope a|b|c|all`. C is not a 5-tx Core package.

## What compile + 2026 VM tests prove (not a new Chipnet land)

- Hole-free 36-query B: grind, Merkle + pair-blob bind, remaining fold layers, foldPair, `(q−R)·Z = N` from T, algebraicC point checks, on-chain R, note Merkle + nullifier chain + amount/auth preimage.
- False AIR rejected on the 36-query lock, not only by `verifyFri`. Fake note / cooked path / cooked nfRoot rejected on CashVM.
- A ≤ 100 KB (no note-auth kernel); B ≤ 1 MB; leftover unused, not cargo.
- C pay hop size is consensus (B); tape hops are real query slices ≤ 100 KB.

## What the Chipnet txs below prove (older kernels)

- CashTokens genesis from vout-0, P2SH32 five-point `PAA1`.
- Velma 10 KB unlocking + redeem.
- Packed AIR unlocking (no spent rho/owner).
- Standard fold spend on public Electrum.
- Consensus 36-fold spend via JSON-RPC + Chipnet miner (`b6818bd2…` is that land, **not** the hole-free kernel).
- Envelope C: tape hops do not pay; last hop pays; missing tape hop rejects the pay tx.

## What is still not claimed

- A new Chipnet land of the hole-free kernels (compile + VM only so far). Next B/C land is a **new txid**.
- Envelope A note/nullifier membership (A has no room; still `verifyFri`).
- Batch-exit extra notes (one-auth FRI + this kernel still walk the first spent note).
- algebraicC as the FRI interpolant (`FRI_VERSION` 8 stays).
- Dummy 99 KB cargo as a verifier (it never was).
- A Lean theorem that FRI openings hide the statement.
- Hidden pool-UTXO value (`STATE_BASE` + reserve is public TVL).
- Zcash / Monero / Voidify parity.
- Groth16 / WHIR / Spartan as a live verifier (reserved slots only).

## History (do not relabel)

| When | What | Tx / commit |
| --- | --- | --- |
| 2026-08-19 | Post-plugin standard **79525 B** + consensus **283992 B** | `23fd1b7dae7c10ac692113cf3e3bc3776cd42d4e6780d916032342fc73faaf59` / `9362df54203c560a34e105ec3a11442a2a50c750e82938191811f1bda3edc833` |
| 2026-08-19 | Hash-knob + Q/N pack, standard **79436 B** | `f14bff7baae1befc2f8becba04b968788b4e8bec65bc336b514a8d5977075671` |
| 2026-08-19 | Intermediate standard **99742 B** (T still interpolated cells+c) | `c40f49480997ecb00354766d4d31e4ec3d5811b61b8d66620ad3c321b12b87ad` |
| 2026-08-17 | Opening-mask standard **98979 B** + consensus **383031 B** | `617b102276fb79122bdd7ca36f902ad65e753845fddb168c0bb1aeb97bbb2ccc` / `b3ea8a75db4badfa1690bd9d8e98ce08565b360ddf8098e5ffade053adf643a3` |
| 2026-08-16 | Consensus **36-fold** **382203 B** @ 319402 | `b1415fafdc65e76d106956064667f94bc988a38da69e63c06acef1e8a1b9cb29` |
| 2026-08-16 | Standard 1-fold + 6 C=QZ **98831 B** | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |
| 2026-08-16 | 10-fold consensus **301279 B** @ 319278 | `18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6` |
| 2026-08-16 | 36-slot **no-fold** **270251 B** | `356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898` |

`18c74b49…` stays the 10-fold land. `356630bd…` stays no-fold.

Earlier 6-slot spends without the current fold lock: `b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f`, `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1`.
