# Status (2026-08-16)

**Pre-release.** Off-chain TypeScript prover/verifier + a 2026 pool lock that
**binds** the new 128-byte PAA1 NFT and spends **10 FRI-kernel inputs** that
Merkle-walk packed openings. Default spend targets **100 KB relay** with **6**
distinct `C=Q·Z` slots (measured 95172 B before the fold input). A parallel
**consensus** path (one tx ≤ **1 MB**, unlockings still ≤ 10 KB) carries all
**36** slots. Chained txs can go larger.

**Milestone (agreed Chipnet proof):** 36-slot successor
`356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898`
(270251 B). Details: [`MILESTONE.md`](MILESTONE.md).

This is **not** ZK, **not** Lean, **not** mainnet. The shipped lock **requires**
a Circle fold kernel that foldPairs **1** FS query (2026 VM density: 2+ queries
in one redeem exceed ~800×script-length). C=QZ stays 6/36. Language: TypeScript /
CashScript / Rust.

## Passing

- Soundness worksheet: TRACE=64, blowup=16, FRI_N=1024, queries=36, grind=20, rate 2/B → **128 conjectural bits**. `sound: true`. Old n=32/q=8 fails the build.
- Prover FRIs \(Q=N/Z\) of the `onChainCells` interpolant (action/digest/roots/seq). Honest \(N\) vanishes on-trace so off-trace \(Q\) is not the zero polynomial. `plugin.verify` / `verifyFri` take **no private witness**: `proof.auth` carries the note preimage, so a fake nullifier + valid membership path is rejected (`nullifier preimage`). Amount conservation is `algebraicC(publicCells)` inside `verifyFri`, not in packed T.
- BCH 2026 VM (libauth CashAssembly, not OP_RETURN): packed T/N/Q interpolate `onChainCells` (action, digest, roots, seq only). Reserves/delta/note limbs are not in that interpolant; `verifyFri` still checks `publicCells` + `algebraicC` + auth. Successor unlocking is packed AIR + redeem only. Inputs 1..10 Merkle-walk packed `layerRoots` at **FRI_N path depth** (8-leaf dummy paths fail), require ≥1 layer-0 opening whose felt is in `qTable`. Input 11 binds Newton `T` to AIR cells and those cells to the statement. Inputs 12..17 run distinct slot `C=Q·Z` (slots 0–5) at recomputed Fiat–Shamir indices. Consensus spends use slots 0–35. Digest-only, dummy-short-path, dummy-no-L0, dummy-unbound, dummy-consistent, and cross-statement packed all fail. Shipped test: 36× slot-0 op-cost exceeds the 10KB density budget. The 100 KB spend checks slots 0–5 on chain; slots 6–35 compile on the 1 MB path. FRI *fold* stays on `verifyFri` (0zkbrewer #2: this is one bound prefix, not a full on-chain FRI fold).
- Proof 64278 B, **10 shards**, 252 Merkle openings, slot redeem **5618**, unlocking max **5853**, Chipnet 6-slot successor **95172 B** / pool unlocking **2437 B**. Consensus compile **270251 B** / pool unlocking **3637 B** (36-slot redeem). 1-slot successor was 66555 B.
- Any-amount one set; Pedersen-hidden note amounts. On-chain PAA1 zeros the reserve field; pool UTXO is `STATE_BASE` only. Reserve conservation is `verifyFri` / `algebraicC`, not packed T. `runMixSuccessor` still updates machine reserve, noteRoot, and nullifierRoot.
- Comparison table in `COMPARISON.md` (checkable axes only).

## Not done (honest)

- Full DEEP-ALI / 128-bit algebraic note-tree hash inside the AIR (note tree is still SHA-256; AIR binds public reserves/digest).
- More than one FS query folded per redeem (density). Statistical ZK / viewing keys.
- On-chain **value** hiding (pool UTXO sats remain public; only note amounts are committed).
- 100 faucet-funded Chipnet wallets. VM eval of the same bytecode is the on-chain bar.
- Formal paper proof. Rust worker still speaks the old n=32 wire (optional; TS is shipped).
- OPTN upstream. Merge to `upstream/main` only if both sides agree.

## Chipnet

Lab address stays in gitignored `.local/lab-wallet.json`.

**6-slot 100 KB lock** (Velma 10 KB script+input), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Self-send vout-0 prep | `9a67bb1caf1f52d67d3529c7223582a45800b23b858c9f363bee6df9dc948567` |
| Genesis P2SH32 PAA1 | `1234194d719291b31e9bcfec3cf80885954a8946f8e00fdb0a72438c0048e2f6` |
| 17 verifier-kernel carriers (10 FRI + bind-T + 6 slots) | `5c3d6102eebe58ce8217c1328b2326a24a0b53bc0eabb05293fbe95f614567ca` |
| Mix successor (95172 B, unlocking 2437, 6× C=Q·Z) | `b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f` |

Second 6-slot land (same lock, new mix), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Self-send vout-0 prep | `e42d0adaae8ec89690b90857f7a0ce07c41c3a8d6b4ff1ba372b043dee347826` |
| Genesis P2SH32 PAA1 | `b92f1a952c0a44582bd6b23db557b8b4e300ab78d18705eee4badf676eb6bf03` |
| 17 verifier-kernel carriers | `d65f679cc177fe223fda78f83cfc0cb6eee218403513e5f7ff9a32c9518d8ccb` |
| Mix successor (95172 B, unlocking 2437) | `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1` |

Previous 1-slot lock, Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Genesis P2SH32 PAA1 | `f8d363c0bc0b85e2d41cd76e12abcf1d8f58b06d767f3aa755089cd392273134` |
| 12 verifier-kernel carriers | `f2bd9454598f565ad4e623d5b40e119d0eabd77200fc85ed17af4b7daca6d47b` |
| Mix successor (66555 B, unlocking 2240) | `333701976ed045e778a69b8a11c798ed070c773701aec8093714097426c94be2` |

`b4d66312…` / `8ccad3b8…` still interpolated full `publicCells` into Newton T. `52b46dab…` published the spent preimage.

**36-slot consensus spend landed on Chipnet** after Start9 BCHN `acceptnonstdtxn=1` + local mine. Public Electrum has the raw 270251 B tx:

| Step | txid |
| --- | --- |
| Genesis | `006186da1d496abace49e1f1d8712c3c18d9bf522910aa8fb60b553be374cab5` |
| Kernels | `7a4e685d3bbfc39eb59f0f29ab11e05135eb76111e1c58a4f84ee2d13e32b8ba` |
| Successor (270251 B, 36× C=Q·Z) | `356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898` |

Block (3+ conf on local BCHN): `000000001abbed79d00f1d2d3e47c16a62114c40da6f559b6d24b438703636b7`

Public miners will not *relay* a 270 KB tx. This one got in because it was submitted to the lab BCHN mempool and mined. ASICSeer solo is pointed at that BCHN (`bitcoincashd.startos:48332`). Stratum for more hash: `start9oslinux.local:3333` (or `192.168.0.55:3333`), user `bchtest:qrzq5f9ltv70u4su7d40agd4nlnp8qlgqcma6x2tvp`.

**Fold-executing standard successor** (1 query fold + 6× C=QZ, 98831 B), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Prep vout-0 | `2a1a0c48e1a9128a466ca08e6e83e813b6002b5c2840736a97f3b34fc654a776` |
| Genesis | `c014f5aeef34774b3bdf17a1defb015a3c125239ff65d41b5874f1e5e1bba777` |
| Kernels | `5aef6160ef229e5a300e1d3e632544c9c1fe05290ce82c196a26fb5abdfbe5e4` |
| Successor (98831 B, fold on lock) | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |

Explorer: `https://chipnet.imaginary.cash/tx/<txid>`

Older txs `1973c065…` / `23ec0c8d…` / `86bd413f…` are a previous lock.
