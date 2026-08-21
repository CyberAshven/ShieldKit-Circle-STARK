# Chipnet milestones

**Network:** BCH Chipnet only. Never mainnet.  
**Unlocking + redeem:** ≤ 10 KB (Velma).  
Old txids stay. They are not relabeled.

## Now (2026-08-21)

Any-amount pool. Circle FRI is **plugin #1**, not the pool identity.

| Knob | Live | Notes |
| --- | --- | --- |
| `--envelope a` / `b` / `c` | A 100 KB (1 fold + 4 R-slots); B one consensus tx, 36-query R; C the same work chunked across 19 standard txs (18 tape + 1 pay), every hop ≤ 100 KB | Dummy cargo is not the verifier. Unlocking 10 KB **per input** — chunk kernels. |
| `--hash sha256` / `blake2s` / `poseidon2-m31` | default **sha256** (CashVM `OP_SHA256`) | Poseidon2-M31 is toorik Grain (ePrint 2023/323), not a lock opcode. |
| `--plugin` | **circle-fri-m31** first; `hash-lab-v0` lab stub | Reserved sandwiches: `goldilocks-fri` (AIR+FRI), `air-whir` (AIR+WHIR), `spartan-whir` (Spartan+WHIR), `groth16` (pairing). `whir` is a PCS; `spartan` is an IOP. |

Envelope **B** is the hole-free statistical-soundness envelope (C's pay hop runs the same kernels, but 4 R-slots instead of 36 — see Envelope C below). One consensus tx, Circle FRI M31, TRACE=64, FRI_N=1024, **36 unique-orbit** queries, 20-bit grind, FRI_VERSION 9. CashVM kernels (chunked, 10 KB unlocking each):

| Kernel | On-chain check |
| --- | --- |
| Grind | SHA256(grindSeed \|\| nonce \|\| `"grind"`) has 20 leading zero bits; FS seed from packed AIR |
| FRI ×10 | Merkle auth of openings; L0 felt binds `qTable[slot]`; pair blob = merklized `left\|\|right` |
| Fold ×36 | Remaining FRI layers (`COMMITTED_LAYERS` = 7) + foldPair, one query per redeem |
| Bind-T | Newton T interpolates packed cells |
| algebraicC | Point checks (digest cell, seq+1, action 1\|2, UTXO conservation). **Is** the FRI interpolant: C = interpolant(algebraicC residuals), Q = C/Z (`FRI_VERSION` 9). Off-trace airNumerator (`FRI_VERSION` 8) is prior art, not this statement |
| Slot ×36 | FS index recomputed; `R_on(i)+Z(i)·R_off(i)`; `(qTable−R)·Z` equals `C(z)`, the algebraicC residual interpolant (`FRI_VERSION` 9); honest C is the zero polynomial. Independent of nTable — masked nTable cannot cancel R |
| Note-auth ×1 | SHA-256 note preimage → leaf; Merkle walk to NFT `noteRoot`; `nf = SHA256(instance\|\|owner\|\|rho)`; `SHA256(oldNfRoot\|\|nf)` (withdraw) or equal nfRoots (deposit). Change-note append when `createdSteps` is non-empty. On **B and C's pay hop** (C funds it with `forceNoteAuth`). A has no room for this kernel. |

**99 KB packing is not the verifier.** `packTo` defaults to **0**. Dummy `OP_DROP` leftover-fill cargo is not foldPair / C=QZ / R / note-auth. Density pad on high-index FS kernels (unlocking longer so `800×(41+unlocking)` covers the hash loop) is the VM meter, not cargo. Leftover 1 MB on B is unused headroom for more real kernels.

Envelope **C** is B's work **chunked to stay standard**: 19 txs, every hop ≤ 100 KB, so
the whole chain relays on public Electrum with no JSON-RPC. Tape hops are real
fold/R-slot slices (**18 hops × 2 queries** = 36 orbits), 82814–87572 B each; the pay
hop is standard (`SLOT_KERNEL_COUNT` = 4 R-slots), **89338 B**. Chain total 1659128 B.
Skip-tape still rejects the pay tx.

The pay hop carries **the same completeness kernels as B**: bind-T, grind,
algebraicC, and the **note-auth kernel** (note Merkle + nullifier + amount/auth
preimage). `landC` funds it with `forceNoteAuth`, and the opened note is threaded
to the pay hop, so `wantNote` fires at 4 slots. Note/nullifier completeness is
**not** back in `verifyFri` for C.

What still differs from B is *binding*, not completeness: B runs all 36 R-slots in
one tx, C runs 4 on the pay hop with the other 32 orbits across the 18 tape hops.
So C does not accumulate 36 **same-tx** binds. Skip-tape rejects the pay tx.

Envelope **A** is the 100 KB relay path: 1 fold + **4** R-slots + grind + algebraicC. Hole-free 36-query does not fit A; do not drop B’s 36 queries to make A look hole-free.

Compile size proof (not a land): A **87611 B** (unlock 2685), B **498398 B** (unlock 5405), 1 MB headroom **501602 B** unused (not cargo). C: 19 hops, max **89338 B**, total **1659128 B**, none over the 100000 relay gate. Leftover-fill is stripped from A/B/C; unlocking bytes are unchanged. Each unlocking ≤ 10 KB. Gating VM tests: honest 36-query B accepts; cooked viewing-commit / recooked Q/N / cooked pair blob reject; false AIR (`mutateTraceAndProve`) rejects on-chain; fake note preimage / cooked Merkle path / cooked nfRoot reject on the note-auth kernel.

### On Chipnet 2026-08-21 (`FRI_VERSION` 9, leftover-fill stripped)

**A — standard, Electrum, 87470 B** (unlock 2685). First land of these kernels on
`FRI_VERSION` 9.

| | |
| --- | --- |
| Successor | `614b7077a768ae7ed1d7aa34d5efe53dea337eff1a7bc5bed4284d1d68323024` |
| Kernels | `834f8ca14ded7e15d3380678ce902f7cf7c16be53a9c9ec6fc3f1c8ab17d03a2` |
| Genesis | `b08420db6850ea725d7d852c95804edc67d27db5c07411fdd8abf407650eb6b7` |
| Prep | `c50663208b83e9b3eeaa472fabd2e3ee487e6e26468976df4bd0e6308a5f2a5e` |

https://chipnet.imaginary.cash/tx/614b7077a768ae7ed1d7aa34d5efe53dea337eff1a7bc5bed4284d1d68323024

**B — consensus, 498398 B** (unlock 5405, 36 folds + 36 R-slots + note-auth).
Accepted by the Start9 BCHN via JSON-RPC `sendrawtransaction` through `nsenter`
into the bitcoind netns (`acceptnonstdtxn=1`). Accepted at zero-conf by the lab
node, which is the bar for a consensus-size land here — same as `b6818bd2…`.
Public Electrum does **not** carry the successor (>100000 B does not relay);
it appears publicly once the lab miner includes it. Prep/genesis/kernels are public.

| | |
| --- | --- |
| Successor | `81bb2cefe40233f096f7a69c2f3b98aa60bf6e3fb969d2b9bb5f3f82f3ecdf83` |
| Kernels | `008eb3f70c16b1a1b350f75ee92caef585c657c2c64c9992d14496a1819cacf1` |
| Genesis | `8a0349efca9560fe50ef8bef1573deb270ffddc4cb1e06f51f2201d3f99b5aac` |
| Prep | `0e9c3de9dabe6ada2b382a953c5f7210e4054601af98827c5c8e235b1358385d` |

Needed `CONSENSUS_SUCCESSOR_FEE_SATS` 400000 → 600000: relay floor is 1 sat/byte
and the FRI 9 successor is 498398 B, so 400000 drew `min relay fee not met (code 66)`.

**C — 19 chunked standard txs, all on public Electrum.** 18 tape hops + pay hop,
total **1662714 B**, every hop under the 100000 relay gate. Genesis
`8e3c5e0b7890ba355dabe1072b2cd060cf612effc6350f72e96f6ed5c04cc30b` (20 outputs:
pool + change + 18 sibling NFTs), kernels
`e05deaf7a5302bcf4c43da15902e9e012ddd965611989c03f7a2b95b649013e7`.

| Hop | Role | Bytes | Txid |
| --- | --- | --- | --- |
| 0 | tape | 83011 | `e470649f4fb6c2ec4b1ce1ed114423b808fbb65409b2d7b610133472fd2371cc` |
| 1 | tape | 86021 | `5411ecf953bf357dacaf66f6748028a9067ae7aa0d0326095b44a61995960b96` |
| 2 | tape | 87769 | `077205ef33a971d1722beb06cb60770fa0a4f77beec313ebb9e2f2f6fd5db0fc` |
| 3 | tape | 87769 | `025698956db74611bd6dc39beb1b8c67359c28b6049cb150e828839a7a9616d1` |
| 4 | tape | 87769 | `41cda645fc1fec376f5d6dd38e6942218831504b74adada3176baebc38426fdb` |
| 5 | tape | 87769 | `03e082a3bd7a2f17f5c655d1031b7ced19f1255b7611bfbcb10aa52a603a2d5c` |
| 6 | tape | 87769 | `284361c71dbbc6cdd5cd60ab793be383c4066e6fdfb114f84a6c3edb3d84bd4f` |
| 7 | tape | 87769 | `028d3cd18ce1fc4c0b2a94303e197203dadd0b7a0ce3f1bb20352fe5c1426dcf` |
| 8 | tape | 87769 | `96febf7002b242f3fd5b9ee6f595bd78dd050f608267f7164f735dfdd2652bc9` |
| 9 | tape | 87769 | `fcee667086a5d121b8ec4592cb145f9a8f481c79810b50ff615b653410830f7c` |
| 10 | tape | 87769 | `79b28506b0e7ba4abd8ff58b4e4edbc59503d5e5e749909fdcaaa072d7abc6c9` |
| 11 | tape | 87769 | `3d6f0f2bf3dad75ea0912cf792f33218b6e1c3f978620b5a74c178153d030604` |
| 12 | tape | 87769 | `4b4e35fe8fc4ad90d95857ec79325c717f05304461b197ad37a0e0254c9d19dd` |
| 13 | tape | 87769 | `b378513f1ef848214523c0131eb525c17325000ce6502a58b2a88dd0fb437cad` |
| 14 | tape | 87769 | `856f30f901be814b317575937d4e1dd2918feb2687ba21a87a9ebd6cff062af6` |
| 15 | tape | 87769 | `51a28f2b72317150824f30d332a8f368994aa482ceebe79b49e69f39ba944c7c` |
| 16 | tape | 87769 | `1f068e334504e4a8bca695e95318c277f34810a2dcc64cfe207984bf3e2954bd` |
| 17 | tape | 87769 | `a0530c7f75c4b6e2cb3c73774fd4078051dbc5f7c67ed9375424f238ffa1a8bb` |
| 18 | **pay** | 89378 | `00f81b99421ce2433603efee1b8dc94608d14182bec2f5121685d0ec71b9b0cc` |

Three things this land required, none of which existed before:

- **Per-hop kernels.** `compileChainedWithdraw` takes them via `tapeKernels`;
  nothing supplied it, so every tape hop compiled against dummy prevouts and any
  node answered `Missing inputs`. One funder tx now mints 15 UTXOs per hop, with
  **absolute** fold/slot query indices (`queryStart + f`) - identical groups would
  compile and be permanently unspendable.
- **Sibling NFTs.** cqz's `bindPackedStmtToPaa1Asm` reads
  `<0> OP_UTXOTOKENCOMMITMENT` and splits at 64; a tokenless carrier made that an
  empty item (`Invalid OP_SPLIT range`). Genesis is the category genesis, so it
  mints 18 mutable siblings holding the OLD PAA1. Each hop mutates one to NEW on
  its output 0. The tape tip stays tokenless at output 1 - a token-carrying tip
  breaks P2PKH signing (NULLFAIL).
- **A pool lock that expects note-auth at 4 slots.** C's pay hop runs 4 slots, so
  `includeNoteAuth(4)` is false, but it carries a note-auth kernel anyway. The
  covenant compared input 14 against the fold lock, found note-auth, and failed
  `OP_EQUALVERIFY`. `forceNoteAuth` is committed at genesis and matched by the
  successor. A and B locks are byte-identical.

Covered by `test/chained-vm.test.ts` on the real VM with full transaction context.

### On Chipnet, earlier sessions

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

- Hole-free 36-query B: grind, Merkle + pair-blob bind, remaining fold layers, foldPair, `(q−R)·Z = C(z)` (honest C = 0), algebraicC point checks, on-chain R, note Merkle + nullifier chain + amount/auth preimage.
- False AIR rejected on the 36-query lock, not only by `verifyFri`. Fake note / cooked path / cooked nfRoot rejected on CashVM.
- A ≤ 100 KB (no note-auth kernel); B ≤ 1 MB; leftover unused, not cargo.
- C is 19 standard txs: 18 tape query slices + a standard pay hop (89338 B), none over 100 KB.

## What the Chipnet txs below prove (older kernels)

- CashTokens genesis from vout-0, P2SH32 five-point `PAA1`.
- Velma 10 KB unlocking + redeem.
- Packed AIR unlocking (no spent rho/owner).
- Standard fold spend on public Electrum.
- Consensus 36-fold spend via JSON-RPC + Chipnet miner (`b6818bd2…` is that land, **not** the hole-free kernel).
- Envelope C: tape hops do not pay; last hop pays; missing tape hop rejects the pay tx.

> Batch-exit note walks are specified in [`FRI10-BATCH-EXIT.md`](FRI10-BATCH-EXIT.md)
> as a **second plugin family beside FRI9**, not a `FRI_VERSION` bump. That file
> also fixes the copy-don't-mutate convention: FRI10 docs are `*-FRI10.md` copies,
> and these FRI9 documents are left alone.

## What is still not claimed

- A **confirmed block** for B's successor (accepted at zero-conf in the lab BCHN; depth follows from the lab miner).
- That C's 36 orbits are **same-tx** binds. C matches B on the completeness kernels — note-auth included — but 32 of the 36 orbits sit on tape hops; only 4 R-slots run on the pay tx.
- Envelope A note/nullifier membership (A has no room; still `verifyFri`).
- Batch-exit extra notes (one-auth FRI + this kernel still walk the first spent note).
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
