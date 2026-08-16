# Status (2026-08-16)

Shipped: Circle FRI of the pool AIR (residual quotient) + a 2026 pool lock that
**binds** the new 128-byte PAA1 NFT and spends **10 FRI-kernel inputs** that
verify every Merkle opening of the ~64 KB proof. This is **not** a Lean theorem
and **not** a “better than XMR/Zcash/Aztec” cryptanalysis.

## Passing

- Soundness worksheet: TRACE=64, blowup=16, FRI_N=1024, queries=36, grind=20, rate 2/B → **128 conjectural bits**. `sound: true`. Old n=32/q=8 fails the build.
- Prover FRIs the residual quotient \(Q=C/Z\) (honest residuals vanish so \(Q=0\)). `plugin.verify` / `verifyFri` take **no private witness**: `proof.auth` carries the note preimage, so a fake nullifier + valid membership path is rejected (`nullifier preimage`). Query check is \(C(z)=Q(z)Z(z)\), not \(T(z)=\) public interpolant.
- BCH 2026 VM (libauth CashAssembly, not OP_RETURN): pool five-point + spent-note preimage; PAA1 NFT commitment is the public cell. Inputs 1..10 Merkle-walk packed `layerRoots`; input 11 recomputes slot-0 `N` from the public interpolant `T` (`L0·cons+L23·seq`) and checks `nTable[0]=N` and `qTable[0]·Z=N` with `Z≠0`. Cooking `nTable=Q'·Z` fails. Dummy 8-leaf kernels fail. Swapped dummy roots/`qTable` fail. Remaining: only FS slot 0 is checked (not all 36); even/odd Newton blobs are still spender-filled (not re-derived from the statement cells on-chain).
- Proof ~64 KB, **10 shards**, 252 Merkle openings, unlocking max 6414, Chipnet successor **63992 bytes**.
- Any-amount one set; Pedersen-hidden note amounts. On-chain PAA1 is the full state (reserve + sequence + roots). Public net is also the UTXO value (`STATE_BASE + reserve`). `runMixSuccessor` updates noteRoot, nullifierRoot, and reserve.
- Comparison table in `COMPARISON.md` (checkable axes only).

## Not done (honest)

- Full DEEP-ALI / 128-bit algebraic note-tree hash inside the AIR (note tree is still SHA-256; AIR binds public reserves/digest).
- On-chain **value** hiding (pool UTXO sats remain public; only note amounts are committed).
- 100 faucet-funded Chipnet wallets. VM eval of the same bytecode is the on-chain bar.
- Formal paper proof. Rust worker still speaks the old n=32 wire (optional; TS is shipped).
- OPTN upstream. Merge to `upstream/main` only if both sides agree.

## Chipnet

Lab address stays in gitignored `.local/lab-wallet.json`.
Mix successor on Chipnet (2026-08-16), Electrum-accepted, **10-kernel sharded FRI**:

| Step | txid |
| --- | --- |
| Genesis (PAA1 includes reserve+sequence) | `1973c06552a371a595872727d8edbe5a988c362c14c46d3bbee7da0e565f6958` |
| 10 FRI-kernel carriers | `23ec0c8d2e689e71df52025b5af2d1073999307ddcdc6998c40d706863998f0b` |
| Withdraw successor (64111 B, 252 openings) | `86bd413fad8606207f26eb69cb6391db27e966f76dd2202f3e4cbd62424792d9` |

Earlier 937 B / 1777 B / 64 KB cells without spent-note preimage / kernel-root bind / C=QZ kernel are **not** this lock. Dummy 8-leaf kernel openings against this statement’s `layerRoots` fail input 1. Swapping dummy roots + `qTable` into the pool unlocking fails input 11. Cooking `nTable[0]=Q'·Z` fails because the lock recomputes `N` from `T`. The lock rejects a fake nullifier. `verifyFri` checks \(N=QZ\) of the Lagrange AIR numerator (honest Q is not identically 0). On-chain C=QZ is still only slot 0.

Explorer: `https://chipnet.imaginary.cash/tx/<txid>`
