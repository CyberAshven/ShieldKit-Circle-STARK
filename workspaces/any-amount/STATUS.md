# Status (2026-08-16)

**Pre-release.** Off-chain TypeScript prover/verifier + a 2026 pool lock that
**binds** the new 128-byte PAA1 NFT and spends **10 FRI-kernel inputs** that
Merkle-walk packed openings. Default spend targets **100 KB relay**. A parallel
**consensus** path (one tx ≤ **1 MB**, unlockings still ≤ 10 KB) can carry all
36 `C=Q·Z` slots for a Chipnet miner. Chained txs can go larger. This is **not**
a full FRI fold, **not** ZK, **not** Lean, **not** mainnet. Language: TypeScript /
CashScript / Rust.

## Passing

- Soundness worksheet: TRACE=64, blowup=16, FRI_N=1024, queries=36, grind=20, rate 2/B → **128 conjectural bits**. `sound: true`. Old n=32/q=8 fails the build.
- Prover FRIs \(Q=N/Z\) of the `onChainCells` interpolant (action/digest/roots/seq). Honest \(N\) vanishes on-trace so off-trace \(Q\) is not the zero polynomial. `plugin.verify` / `verifyFri` take **no private witness**: `proof.auth` carries the note preimage, so a fake nullifier + valid membership path is rejected (`nullifier preimage`). Amount conservation is `algebraicC(publicCells)` inside `verifyFri`, not in packed T.
- BCH 2026 VM (libauth CashAssembly, not OP_RETURN): packed T/N/Q interpolate `onChainCells` (action, digest, roots, seq only). Reserves/delta/note limbs are not in that interpolant; `verifyFri` still checks `publicCells` + `algebraicC` + auth. Successor unlocking is packed AIR + redeem only. Inputs 1..10 Merkle-walk packed `layerRoots` at **FRI_N path depth** (8-leaf dummy paths fail), require ≥1 layer-0 opening whose felt is in `qTable`. Input 11 binds Newton `T` to AIR cells and those cells to the statement. Input 12 runs slot-0 `C=Q·Z` at a **recomputed** Fiat–Shamir index (spender `idx[0]` ignored) and binds packed stmt `noteRoot`/`seq` to the NFT. Digest-only, dummy-short-path, dummy-no-L0, dummy-unbound, dummy-consistent, and cross-statement packed all fail. Shipped test: 36× slot-0 op-cost exceeds the 10KB density budget. Remaining 35 FS slots and FRI *fold* stay on `verifyFri` (0zkbrewer #2: this is one bound prefix, not a full on-chain FRI fold).
- Proof 64278 B, **10 shards**, 252 Merkle openings, unlocking max **5717**, Chipnet successor **66555 B** / pool unlocking **2240 B**.
- Any-amount one set; Pedersen-hidden note amounts. On-chain PAA1 zeros the reserve field; pool UTXO is `STATE_BASE` only. Reserve conservation is `verifyFri` / `algebraicC`, not packed T. `runMixSuccessor` still updates machine reserve, noteRoot, and nullifierRoot.
- Comparison table in `COMPARISON.md` (checkable axes only).

## Not done (honest)

- Full DEEP-ALI / 128-bit algebraic note-tree hash inside the AIR (note tree is still SHA-256; AIR binds public reserves/digest).
- On-chain FRI *fold* of all layers / all 36 C=QZ slots (density). A 1024-wide tree that plants honest Q at the FS index is not rejected by Merkle+slot-0 alone.
- On-chain **value** hiding (pool UTXO sats remain public; only note amounts are committed).
- 100 faucet-funded Chipnet wallets. VM eval of the same bytecode is the on-chain bar.
- Formal paper proof. Rust worker still speaks the old n=32 wire (optional; TS is shipped).
- OPTN upstream. Merge to `upstream/main` only if both sides agree.

## Chipnet

Lab address stays in gitignored `.local/lab-wallet.json`.

**This lock** (`onChainCells` interpolant — T cannot recover reserves), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Genesis P2SH32 PAA1 | `f8d363c0bc0b85e2d41cd76e12abcf1d8f58b06d767f3aa755089cd392273134` |
| 12 verifier-kernel carriers | `f2bd9454598f565ad4e623d5b40e119d0eabd77200fc85ed17af4b7daca6d47b` |
| Mix successor (66555 B, unlocking 2240) | `333701976ed045e778a69b8a11c798ed070c773701aec8093714097426c94be2` |

`b4d66312…` / `8ccad3b8…` still interpolated full `publicCells` into Newton T. `52b46dab…` published the spent preimage.

Explorer: `https://chipnet.imaginary.cash/tx/<txid>`

Older txs `1973c065…` / `23ec0c8d…` / `86bd413f…` are a previous lock.
