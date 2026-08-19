# Status (2026-08-19)

**Pre-release.** Off-chain TypeScript prover/verifier + a 2026 pool lock that
**binds** the new 128-byte PAA1 NFT and spends **10 FRI-kernel inputs** that
Merkle-walk packed openings. Default spend targets **100 KB relay** with **6**
distinct `C=Q·Z` slots. A parallel
**consensus** path (one tx ≤ **1 MB**, unlockings still ≤ 10 KB) carries all
**36** slots. Chained txs can go larger.

**Milestones (Chipnet):** post-plugin standard successor `23fd1b7d…` (**79525 B**, 1 fold, Electrum) and consensus `9362df54…` (**283992 B**, 36 folds, JSON-RPC). Prior hash-knob land `f14bff7b…` (**79436 B**) stays recorded, as do `c40f4948…`, `617b1022…`, `b3ea8a75…`, `2acb1196…`, `b1415faf…`, `18c74b49…`, `356630bd…`. Details: [`MILESTONE.md`](MILESTONE.md).

Published note preimage is one-time-padded. **Not** a Lean theorem, **not** mainnet, **not** better-than-XMR, Zcash, or StarkWare-as-theorem. CashVM pays **one `OP_SHA256`**; Poseidon2/Monolith are prover-side hashes, not lock opcodes. The shipped lock **requires**
Circle fold kernels that foldPair **1** FS query **each** (2026 VM density: 2+
queries in one redeem exceed ~800×script-length). Standard 100 KB: **1** fold.
Consensus 1 MB: **36** folds (one 1-query kernel per FRI query). C=QZ stays 6/36.
On-chain redeem is still Circle fold/C=QZ (plugin switch is off-chain + registry;
`hash-lab-v0` is not private/sound). Language: TypeScript / CashScript / Rust.

## Three resume questions (honest)

| Ask | Shipped bar |
| --- | --- |
| On-chain Circle STARK verifier? | **Yes**, 2026 VM: Merkle (`OP_SHA256`) + foldPair + `C=Q·Z`. Honest successor accepts; false statement / digest-only / dummy membership reject. Not a pairing SNARK. |
| Statistical ZK openings? | **Shipped mask, not a Lean HVZK theorem.** Degree-3 SHA-256 \(R\) on prove/verify/packed Q; opened diffs are not plaintext \(Q\) diffs. The 10 KB lock does **not** evaluate \(R\) (it checks masked Q·Z=nTable). Not full ePrint 2024/1037 off-domain query-count-degree HVZK. |
| Confidential TX + aggregated pool? | **Notes + OTP + unlinked fee + one set.** Distinctive withdraw is not an output and not `feeUtxo−change`. Pool UTXO stays `STATE_BASE` (not Maxwell / not Zcash hidden output value). Two honest amounts share one Merkle set; fresh-rho change; spent-nullifier reuse rejects. |

## Passing

- Soundness worksheet: TRACE=64, blowup=16, FRI_N=1024, queries=36, grind=20, rate 2/B → **128 conjectural bits**. `sound: true`. Old n=32/q=8 fails the build.
- Prover FRIs \(Q=N/Z\) of the `onChainCells` interpolant (action/digest/roots/seq). Honest \(N\) vanishes on-trace so off-trace \(Q\) is not the zero polynomial. In-memory `verifyFri` (or `viewingKey`) checks the note preimage so a fake nullifier + valid membership path is rejected (`nullifier preimage`). Public `plugin.verify` of the encoded proof checks membership + FRI without the preimage. Amount conservation is `algebraicC(publicCells)` inside `verifyFri`, not in packed T.
- BCH 2026 VM (libauth CashAssembly, not OP_RETURN): packed T/N/Q interpolate `onChainCells` (action, digest, roots, seq only). Reserves/delta/note limbs are not in that interpolant; `verifyFri` still checks `publicCells` + `algebraicC` + auth + grind + the other query folds. Successor unlocking is packed AIR + redeem only (no rho/owner). Inputs 1..10 Merkle-walk packed `layerRoots` at **FRI_N path depth** (8-leaf dummy paths fail), require ≥1 layer-0 opening whose felt is in `qTable`. Input 11 binds Newton `T` to AIR cells and those cells to the statement. Next input(s) foldPair **1** query each (standard: 1 fold; consensus: **36** folds, one kernel per FS query). Remaining inputs run distinct slot `C=Q·Z` (slots 0–5 standard, 0–35 consensus) at recomputed Fiat–Shamir indices. Digest-only, dummy-short-path, dummy-no-L0, dummy-unbound, dummy-consistent, wrong-fold-index (including query 10), and cross-statement packed all fail. Shipped test: 36× slot-0 op-cost exceeds the 10KB density budget. Conservation stays in `verifyFri` — on-chain PAA1 zeros the reserve field. Published `encodeFriProof` one-time-pads rho/owner/amount under an 80-byte viewing key that is not in the encoding. FRI openings and packed Q/N use a **degree-3** SHA-256 mask polynomial \(R\) (ePrint 2024/1037-style opened-view isolation of a constant: opened[i]−opened[j] is not Q[i]−Q[j]). Packed nTable is N+R(i)Z so Q−N/Z is not R(i). This is **not** full 2024/1037 HVZK (off-domain randomizer of query-count degree). The slot lock still checks Q·Z=nTable without evaluating R. Packed Newton T is not the AIR interpolant (zero coeffs); packed cells carry seq only. That is a published-blob choice, not a drop of AIR: the prover still interpolates `onChainCells` on the circle (\(x^2+y^2=1\)), not classical Lagrange on \(X^N-1\). T-cell and T(action)-1|2 are not c. The slot lock checks Q·Z=nTable without subtracting c. Not a theorem that FRI openings hide the statement. Not better-than-XMR or Zcash.
- Proof 64310 B, **10 shards**, 252 Merkle openings. Standard successor compile stays ≤ **100000 B**; consensus ≤ **1000000 B**; every unlocking+redeem ≤ **10000 B**. Density stays 1 FRI query per fold redeem. Latest lands: standard `23fd1b7d…` (**79525 B**, 1 fold, Electrum) and consensus `9362df54…` (**283992 B**, 36 folds, JSON-RPC). Earlier `f14bff7b…` / `c40f4948…` / `617b1022…` / `b3ea8a75…` / `2acb1196…` / `b1415faf…` / `18c74b49…` / `356630bd…` are not relabeled.
- Any-amount one set; production note amounts are a tagged internal-hash commit (`PAA1-HASH-AMT-v1`, bound in `checkAuthRelation` / `verifyFri`). Internal hash is a drop-in knob: default SHA-256, alternate BLAKE2s (same-hash accept, mixed-hash reject). Poseidon2 and Monolith are not shipped. A later swap (SHA-256 → Poseidon2, or Poseidon2 → Monolith) is a table entry + `digest()`, not a Merkle/FS/note rewrite. On-chain `OP_SHA256` remains the SHA-256 backend of the default knob (not a second tree). Pedersen `C=vG+rH` is a comparison plugin only (not PQ, not production). `encodeStatement` commits the public deposit/withdraw net (`PAA1-HASH-NET-v1`) instead of writing the raw i64. Successor hex does not contain those note amounts, spent rho, or owner. On-chain PAA1 zeros the reserve field and requires seq+1. Reserve **value** conservation (`algebraicC` r0/r2/r3/r6) stays in `verifyFri` — publishing raw reserves would leak. Pool UTXO stays `STATE_BASE`. Successor miner/covenant fee is paid from a **separate funder input** (`feeUtxo − change`); no output value equals the withdrawn satoshis. `runMixSuccessor` still updates machine reserve, noteRoot, and nullifierRoot.
- ZKP plugin hook: `zkpPlugins` = `circle-fri-m31` (default, sound) + `hash-lab-v0` (lab digest). Plugin switch is off-chain + registry. `hash-lab-v0` is not private and not sound. Same `PoolStatement` for both; cross-family verify rejects. CLI `pool deposit` / `pool withdraw` call the selected plugin. Notes/nullifiers/reserve do not change with family id. On-chain redeem is still Circle fold/C=QZ — not a pairing SNARK, not family-agnostic bytecode in this increment.
- Comparison table in `COMPARISON.md` (checkable axes only).

## Not done (honest)

- Full DEEP-ALI / 128-bit algebraic note-tree hash inside the AIR (note tree uses the internal-hash knob, default SHA-256; AIR binds public reserves/digest). Poseidon2 and Monolith are not shipped.
- A CashAssembly interpreter for non-SHA-256 knob ids. Shipped redeem walks `OP_SHA256`. A blake2s-packed proof will not verify on the current lock.
- More than one FS query folded per redeem (density). Viewing-key delivery / wallet UX. Full ePrint 2024/1037 HVZK (off-domain mask of query-count degree, Lean theorem). Shipped prover uses a degree-3 SHA-256 \(R\); the 10 KB lock does not evaluate \(R\).
- On-chain **value** hiding of the pool UTXO (sats remain `STATE_BASE`). Note amounts are hash-committed; the public P2PKH net is committed in the statement digest, not published in successor fields.
- 100 faucet-funded Chipnet wallets. VM eval of the same bytecode is the on-chain bar.
- Formal paper proof. Rust worker still speaks the old n=32 wire (optional; TS is shipped).
- On-chain redeem that dispatches `Verify(family, …)` without a Circle-shaped kernel. Groth16 / Goldilocks / WHIR as a second production on-chain verifier.
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

**36-fold consensus successor landed on Chipnet** via BCHN JSON-RPC `sendrawtransaction` (not Electrum, not P2P `inv`). Size **382203**, 1+ conf:

| Step | txid |
| --- | --- |
| Prep vout-0 | `ea53c0e26a1cf3800199713c01ff5005c8c2e286df69f9234519a2517d1211ac` |
| Genesis | `169df22d347cfa7d7e2fb42152b83a764a4126a7b04ac05de078575ea4e86714` |
| Kernels | `7ea959b2d976b400f29640c7a218ee4c69c16c40b7ad81fa5d5ca80cbbd9296a` |
| Successor (382203 B, 36× C=Q·Z + **36** folds) | `b1415fafdc65e76d106956064667f94bc988a38da69e63c06acef1e8a1b9cb29` |

Block (1+ conf): `0000000000000e4df903b409aee4e31f33210fb13ee75afe6d77691ddfd6c421` height **319402**.

**Prior 10-fold consensus successor** (not the 36-fold land). Local BCHN size **301279**, 59 inputs:

| Step | txid |
| --- | --- |
| Genesis | `2469f87208114473733aee0e02d163901318e760fc8b6973c4cc76b1d475bfab` |
| Kernels | `ef334c4a8d7309cc898031c61a476d9d9b39a3c9e8b99fd79df1c15f077502f0` |
| Successor (301279 B, 36× C=Q·Z + **10** folds) | `18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6` |

Block (2+ conf): `0000000026955667a7e7468d40043e66e0d8890bc21f7162a5d8595d02aaceca` height **319278**. Do not relabel `356630bd…` as this fold land.

**Fold-executing standard successor** (1 query fold + 6× C=QZ, 98831 B), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Prep vout-0 | `2a1a0c48e1a9128a466ca08e6e83e813b6002b5c2840736a97f3b34fc654a776` |
| Genesis | `c014f5aeef34774b3bdf17a1defb015a3c125239ff65d41b5874f1e5e1bba777` |
| Kernels | `5aef6160ef229e5a300e1d3e632544c9c1fe05290ce82c196a26fb5abdfbe5e4` |
| Successor (98831 B, fold on lock) | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |

Explorer: `https://chipnet.imaginary.cash/tx/<txid>`

Older txs `1973c065…` / `23ec0c8d…` / `86bd413f…` are a previous lock.
