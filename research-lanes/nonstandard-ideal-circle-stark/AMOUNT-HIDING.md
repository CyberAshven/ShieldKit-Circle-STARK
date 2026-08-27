# Amount hiding vs Pedersen — occupancy handoff

Continue from this file. Live occupancy is **FRI11** Circle FRI (M31/QM31, 36 unique-orbit queries, 20-bit grind, TRACE 64). Do not throw the FRI work. Do not silently swap the amount tag (that is a new vk). Chipnet only. Never mainnet.

Language: TypeScript (strict), CashScript, or Rust prover. No new `.js`. Public git cites public URLs/papers/txids only.

Joint repo: `origin` = CyberAshven/ShieldKit-Circle-STARK, `upstream` = toorik2/ShieldKit-Circle-STARK, working ref `@ABLalgorithm`. Do not push `upstream/main` unless both sides agreed. Occupancy `RULES.md`: do not edit `workspaces/any-amount` for this track. Occupancy `--envelope a|b|c` is **this** directory’s CLI.

---

## 1. What is live (do not relabel)

Occupancy completeness **B** is ~147 KB JSON-RPC, not FRI9 `81bb2cef…` / 498398 B (different vk).

| Envelope | Bytes | Path | BCH explorer |
| --- | ---: | --- | --- |
| **A** leftover-bind | 97736 | Electrum | [18bc53d6…](https://bchexplorer.cash/chipnet/tx/18bc53d6c9899673b6d62cd1cc83032c41405136a18d1de7cda2074262c95909) |
| **B** leftover-bind | 147097 | JSON-RPC | [6b75a37d…](https://bchexplorer.cash/chipnet/tx/6b75a37d46fa3aeff7a20702f56b88e3e646fb6814fa124bc44556fc89fe3a9f) |
| **C** pay (nfRoot bind) | 92326 | Electrum | [8b7bdbad…](https://bchexplorer.cash/chipnet/tx/8b7bdbadc45bc3ca40cfcce4b909f250df9960c532da38aace7655542c527570) |
| **B** N=3 batch | 143204 | JSON-RPC | [a1c406aa…](https://bchexplorer.cash/chipnet/tx/a1c406aa95f7a4beddfcb9a7672331be68ec5ea27482d3ce1acd0ecbcd8c9d47) |

FRI9 2026-08-21 (`614b7077…` / `81bb2cef…` / `06a6078a…`) stays FRI9. Workflow: [`WORKFLOW.md`](WORKFLOW.md). CLI:

```bash
cd research-lanes/nonstandard-ideal-circle-stark
npx tsx src/cli.ts pool measure-tx --envelope a
npx tsx src/cli.ts pool land --envelope a|b|c
npx tsx scripts/chipnet-land-batch.ts 3 .local/chipnet-batch --dry
```

Fused leftover: miner-run `(q−R)·Z` EQUALVERIFY packed nTable in the fold rslot (`r-kernel.ts` / `fold-asm.ts`). Honest B 2026 VM-accepts; occupancy-only leftover + honest T rejects (`test/envelope-gating.test.ts`). Unlocking omits rho / ownerSecret / amount8 (`test/envelope-batch.test.ts`). Cqz binds packed nfRoot (offset 96) vs NFT (`test/chained-vm.test.ts`).

---

## 2. Three different “hiding” words (do not mix)

| Word | Object | Occupancy today |
| --- | --- | --- |
| **Commit hiding** | Does the on-chain amount blob look like `v`? | Computational: `H(tag ‖ amount8 ‖ rho)` in `src/amounts/hash-commit.ts` |
| **Unlocking leak** | Is `amount8` / rho / owner in the script? | No. Publics are leaf / nf / amountCommit |
| **Proof ZK** | Do FRI queries dump the trace? | Masked openings `R_on + Z·R_off` (ePrint [2024/1037](https://eprint.iacr.org/2024/1037)) |
| **UTXO sats / TVL** | Pool output value, payout value, `public_amount` | **Public on purpose** — conservation / no 21M hole |

Script cannot hide `STATE_BASE` or the fee UTXO. That needs a value-hiding CHIP (not CHIP [2025-05 ECADD/ECMUL](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570), which only adds point add/mul). A buggy **covenant** can steal the **pool bag**. It cannot mint BCH: nodes still sum input/output **sats**. On a transparent-backed pool, Pedersen binding-break is theft of the bag, not 21M inflation (unlike Monero, where the commit *is* the money).

`public_amount` is the visible delta (Voidify Nova-shaped). Weird numbers still correlate. [`any-amount-profile`](../../../Reference/prior-art/any-amount-profile.md) in the parent notebook; here: one set, not Classic denomination tiers.

---

## 3. Pedersen vs hash vs lattice (amount **tag**)

Circle FRI is the **argument**. The amount **tag** is a separate plugin. Do not throw FRI.

| Tag | Hiding | Binding | Homomorphic add | Fits occupancy now |
| --- | --- | --- | --- | --- |
| SHA `amountCommit` **(live)** | Computational | Hash (Shor-safe; Grover taxes SHA-256 toward ~128-bit preimage) | No — FRI proves the sum | Yes |
| Pedersen `vG+rH` | **Perfect** | Discrete log — QC reopens `v` | Yes (`ECADD`) | Needs CHIP or EC-in-AIR; **amount bind not hash-PQ** |
| CRHF statistically hiding (Naor–Yung / Halevi–Micali family) | **Statistical** | Hash | No — FRI still sums | Next **hash** profile; new vk; larger blob |
| Lattice (Ajtai, BDLOP, Lattice RingCT) | Statistical / IT-ish | SIS/LWE | Scheme-dependent | New AIR; hostile field/`q`; optional later if hash-only is dropped |

**Hash-PQ:** occupancy’s stack. Shor does not kill SHA/FRI. Grover discounts. Say “plausibly post-quantum under collision-resistant hashes,” not “QC cannot touch hashes.” That hedge is Grover, not a defect in this lane.

**Perfect hiding ∧ perfect binding** on one `C`: **impossible** (unbounded grind). Damgård–Nielsen [ePrint 2001/091](https://eprint.iacr.org/2001/091) title sounds like both; body is **either** a perfectly hiding **or** a perfectly binding UC instantiation.

**Same transaction, publish Pedersen `C` and `SHA(v‖r)`:** joint hiding collapses to the hash; Pedersen’s extra hiding is burned. **STARK of a Pedersen opening** does not PQ-bind `C`: QC finds `(v′,r′)` then proves the STARK honestly.

**“Series” inside one tx** = one transcript. Opcode order does not create a pre-QC era.

**True two-era series** (switch commitments, Proof-in-a-Bottle): freeze a fingerprint of `v` **while DL still uniquely determines the opening**, without putting `v` in the clear. Binding is time-dependent. Coins that skip the freeze stay DL-openable. Not occupancy FRI11. Monero Jamtis-PQ: PQ **encryption**; explicit **non-goal** is PQ **soundness** of Pedersen amounts.

---

## 4. Elevate hiding as far as hash+FRI allows

### Without a new vk (already the FRI11 bar)

1. No `amount8` / rho / owner in unlocking (keep tests).
2. Keep viewing-mask on FRI openings ([2024/1037](https://eprint.iacr.org/2024/1037) — FRI as a **perfectly hiding polynomial commitment** after randomization; **soundness still hash**).
3. Blinds for net/reserve commits stay **off** `encodeStatement` (`freshNetBlind`, `commitPublicNet`).
4. Do not add Pedersen or `SHA(amount)` **beside** the live tag in the same public encoding.

That is the maximum **without** bumping `FRI_VERSION`. Perfect Pedersen hiding is **not** available on the live SHA tag. Statistical hiding is **not** available on `H(tag‖v‖rho)` either — that string is computational hiding.

### Next profile (keep FRI, new vk) — preferred if lattices stay out

**Statistically hiding commitment from a collision-resistant hash** + existing occupancy FRI for conservation/membership/nf.

- Homomorphism is **redundant** (AIR already proves sums).
- Hiding: statistical (unbounded distinguisher advantage negligible). Not Pedersen-perfect.
- Binding: still hash / Grover-taxed. Matches “prefer hashes over lattices.”
- Construction family: Naor–Yung-style / Halevi–Micali / Damgård–Pedersen–Pfitzmann multi-bit from CRHF. Often extra setup bytes or rounds; Fiat–Shamir in a tx makes the **compiled** protocol computational-ROM — measure that; do not claim IT hiding after FS without a proof.
- New `amountCommit` width, packed AIR offsets, note-auth, booleanity-on-amount if the bit-AIR still keys off SHA(amount). **Size worksheet before land.** Envelope B must stay ≤ 1 MB, unlocking ≤ 10 KB.
- New Chipnet lands. Old SHA occupancy txs stay history (like FRI9).

### Optional later (if hash-only constraint is lifted)

Lattice amount tag + **same** Circle FRI argument (open lattice commit in the AIR). Statistical hiding + SIS bind. Heavy M31 gadgets. New vk. Do not treat as a patch on FRI11.

Pedersen amount tag + FRI argument: perfect hiding of `C` **only if** no `v`-dependent hash is public. Amount **binding** becomes DL. Needs ECADD or EC-in-AIR. Conflicts with “QC must not rebind amounts” unless the pool stays transparent-backed **and** that theft-of-bag is accepted.

---

## 5. Do not implement

- Pedersen + SHA of `v` in one tx as “best of both.”
- STARK-of-Pedersen as “PQ amount bind.”
- Silent edit of FRI11 amount tag.
- Relabel FRI9 498 KB as occupancy B.
- Claim Zcash/Orchard/Maxwell; tagged hash ≠ Bulletproofs.
- Claim Lean statistical-ZK theorem for occupancy (masking is not that theorem).
- Hide pool UTXO sats without a CT-style money CHIP (inflation design).
- Push `upstream/main` without agreement.
- New `.js`. Seeds in chat/argv.

---

## 6. Files to read first

| Path | Why |
| --- | --- |
| `RULES.md` | Constitution; §6 shielded = no preimage in unlocking; TVL public allowed |
| `PROMPT.md` / `GOAL.md` | Named end; only the human says done |
| `WORKFLOW.md` | CLI + BCH explorer links |
| `src/amounts/hash-commit.ts` | Live SHA amount / net / reserve tags |
| `src/amounts/pedersen.ts` | Comparison plugin only |
| `src/chain/note-auth-kernel.ts` / `note-auth-step-kernel.ts` | Publics not preimages; batch steps |
| `src/chain/r-kernel.ts` / `fold-asm.ts` | Leftover nTable bind |
| `test/envelope-gating.test.ts` | FRI11 params, leftover not N=0, B reject occupancy-only leftover |
| `test/envelope-batch.test.ts` | N≥2, unlocking omits rho/owner/amount8 |
| `test/chained-vm.test.ts` | Packed nfRoot bind |

Parent notebook (no GitHub remote): `Reference/prior-art/voidify.md`, `Reference/prior-art/any-amount-profile.md`, `Reference/literature/notes/zkp-agnostic-architecture.md`, `Reference/prior-art/bcr-privacy-threads.md`.

---

## 7. Verify before claiming a hiding upgrade

```bash
cd research-lanes/nonstandard-ideal-circle-stark
npx tsx --test --test-timeout 180000 test/envelope-gating.test.ts
npx tsx --test --test-timeout 180000 --test-name-pattern "3-note batch verifies" test/envelope-batch.test.ts
npx tsx src/cli.ts pool measure-tx --envelope a
```

A successor in (50000, 100000], 36 queries, unlock ≤ 10000. B ~147 KB ≤ 1000000. C hops in (20000, 100000]. Fused leftover asm must not be vacuous `OP_0`+`NUMEQUALVERIFY` on `(q−R)·Z`. Soundness still needs a false-statement reject, not only tampered-proof reject.

---

## 8. Citations (public)

- Haböck, Kindi — *A note on adding zero-knowledge to STARKs*, ePrint [2024/1037](https://eprint.iacr.org/2024/1037) (FRI perfectly hiding PCS after mask; computational soundness)
- CHIP 2025-05 EC arithmetic — [BCR 1570](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)
- Damgård, Nielsen — UC commits, ePrint [2001/091](https://eprint.iacr.org/2001/091)
- Circle STARK — ePrint [2024/278](https://eprint.iacr.org/2024/278)
- Voidify (Nova public_amount, Groth16 on Solana) — [docs](https://voidifycto.gitbook.io/whitepaper), [program](https://github.com/VoidifyCommunity/voidify-smart-contract-audit)
- Lattice RingCT (not this lane’s default) — ePrint [2018/379](https://eprint.iacr.org/2018/379)

---

## 9. Next construction (handoff)

1. Keep occupancy FRI11 SHA tags until a measured statistically hiding CRHF amount profile exists.  
2. Spec that profile: commit algorithm, public width, how note-auth/booleanity bind it, size vs 10 KB / 100 KB / 1 MB.  
3. Implement as a **new** `FRI_VERSION` / vk, tests first (gating leftover + batch silence + false-statement).  
4. Land Chipnet; table column **BCH explorer** `https://bchexplorer.cash/chipnet/tx/<txid>`.  
5. Do not call it Pedersen-perfect. Call it statistical hiding, hash binding, Circle FRI argument.

Only the human declares the named end. A wall is a number, then the next construction.
