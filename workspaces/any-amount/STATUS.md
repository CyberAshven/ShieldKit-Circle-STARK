# Status (2026-08-16)

Shipped: Circle FRI of the pool AIR (residual quotient) + a 2026 pool lock that
**binds** the new 128-byte PAA1 NFT and spends **10 FRI-kernel inputs** that
verify every Merkle opening of the ~64 KB proof. This is **not** a Lean theorem
and **not** a “better than XMR/Zcash/Aztec” cryptanalysis.

## Passing

- Soundness worksheet: TRACE=64, blowup=16, FRI_N=1024, queries=36, grind=20, rate 2/B → **128 conjectural bits**. `sound: true`. Old n=32/q=8 fails the build.
- Prover FRIs the residual quotient \(Q=C/Z\) (honest residuals vanish so \(Q=0\)). `plugin.verify` / `verifyFri` take **no private witness**: `proof.auth` carries the note preimage, so a fake nullifier + valid membership path is rejected (`nullifier preimage`). Query check is \(C(z)=Q(z)Z(z)\), not \(T(z)=\) public interpolant.
- BCH 2026 VM (libauth CashAssembly, not OP_RETURN): pool five-point + spent-note preimage; PAA1 NFT is the public cell. Inputs 1..10 Merkle-walk packed `layerRoots` at **FRI_N path depth** (8-leaf dummy paths fail), require ≥1 layer-0 opening whose felt is in `qTable`. Input 11 binds Newton `T` to AIR cells and those cells to the statement. Input 12 runs slot-0 `C=Q·Z` at a **recomputed** Fiat–Shamir index (spender `idx[0]` ignored) and binds packed stmt `noteRoot`/`seq` to the NFT. Digest-only, dummy-short-path, dummy-no-L0, dummy-unbound, dummy-consistent, and cross-statement packed all fail. Shipped test: 36× slot-0 op-cost exceeds the 10KB density budget. Remaining 35 FS slots and FRI *fold* stay on `verifyFri` (0zkbrewer #2: this is one bound prefix, not a full on-chain FRI fold).
- Proof ~64 KB, **10 shards**, 252 Merkle openings, unlocking max 6414, Chipnet successor **63992 bytes**.
- Any-amount one set; Pedersen-hidden note amounts. On-chain PAA1 zeros the reserve field; pool UTXO is `STATE_BASE` only. Reserve conservation is in the AIR / `verifyFri`. `runMixSuccessor` still updates machine reserve, noteRoot, and nullifierRoot.
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

**This lock** (packed AIR + 10 FRI kernels + bind-T + slot-0 C=QZ + path-depth), Electrum-accepted 2026-08-16:

| Step | txid |
| --- | --- |
| Prep self-send (vout 0 for CashTokens genesis) | `f4969bcdfbe6887d4e0457d7d480b675ff9f728109cd6c93ac4e3933bb715ce2` |
| Genesis P2SH32 PAA1 | `2001ac68c61108b5403491e6a229851ec368853c3e317d5ae1ccf7666d113db5` |
| 12 verifier-kernel carriers (10 FRI + bind-T + slot) | `70b277637535a40a5fa9d6f1bb805d7b841b31e7fc0e09ff8713ac00768dee2d` |
| Mix successor (69115 B, 252 openings, plugin.verify ok) | `52b46dab18aaac03b15655c6154822f1c330a4513a5dad9f49b7c2084e910147` |

Explorer: `https://chipnet.imaginary.cash/tx/<txid>`

Older txs `1973c065…` / `23ec0c8d…` / `86bd413f…` are a previous lock.
