# Envelope-B standard lane ruleset

**Work only in `research-lanes/envelope-b-standard`.** Do not edit `workspaces/any-amount` or `research-lanes/bch-shielded-pool-design` for this track.

Pinned BCH **May 2026** only (Upgrade 12 + May 2025 VM limits). Chipnet + Libauth 2026 VM. Never mainnet.

## 0. Product (do not compromise)

Every envelope — A, B, and C — is a **statistical Circle FRI STARK** of the **same** any-amount aggregated shielded pool. Not a digest, not dummy cargo, not `hash-lab-v0`.

1. **Family:** Circle FRI over M31 (`circle-fri-m31`), `FRI_VERSION` 9. Benchmark prover/verifier against **StarkWare Circle STARK / Stwo** (construction + timings). Do not switch family to Groth16, Nova, or Voidify’s circuits.
2. **Internal hash default is SHA-256** (`OP_SHA256` on chain). BLAKE2s / Poseidon2-M31 are prover-side knobs. Do not change the default. A blake2s-packed proof will not verify on the shipped lock — that is expected.
3. **On-chain membership, Merkle walk, and nullifier** are part of soundness, not optional cosmetics. B and C’s pay hop walk them in CashVM. Extra batch-exit notes still in `verifyFri` is a **known hole**, not a feature.
4. **Confidential transaction** = tagged SHA-256 note amounts + OTP on the proof + hiding net/reserve commits + unlinked fee. Pool UTXO sats = `STATE_BASE`+reserve (**public TVL**). Not Maxwell, not Orchard, not better-than-Voidify. Voidify is a **reference** (`Reference/prior-art/voidify.md`, COMPARISON.md), not a parity claim.
5. **Opt-in batch exit** stays opt-in (`--batch-exit`). Shared round; first waiter samples CSPRNG-uniform seconds in `[--batch-min, --batch-max]` (default 30..180). Fast withdraw remains the default. Tests that claim pool privacy/soundness must include this CLI path (`test/batch-exit.test.ts`, `test/envelope-batch.test.ts`, `pool withdraw --batch-exit`).
6. Lab bar: 2026 lock **and** JS `verifyFri` of the **same** proof the prover produced. Do not optimize a verifier that cannot check that prover.

## 1. Three envelopes (names are not interchangeable)

| | A | B | C |
|---|---|---|---|
| Shape | **one standard tx** | **one consensus tx** | **chained standard hops** |
| Size cap | **100 000 B** | **1 000 000 B** | **100 000 B per hop** (not 100 MB) |
| Completeness today | 4 R-slots, 1 fold, **no** note-auth | 36 folds + 36 R-slots + note-auth | 36 orbits split; pay hop ≈ B; tape hops smaller |
| Relay | Electrum | JSON-RPC / miner | Electrum, sequential parent-then-child |
| Role **now** | control + **later** shrink target | **strongest same-tx verifier** — soundness/privacy first | **standard-shaped completeness** — fund-safe hops |

7. **B is not A.** Shrinking B’s completeness into one 100 KB tx **is envelope A’s ambitious goal**, after B and C have nothing left on soundness/privacy that we can still do.
8. **C is not “standard B.”** Each hop ≤ 100 KB. Tape is sequential. **Rejection / skip-tape / `TAPE_TIMEOUT_CSV` reclaim must keep funds recoverable** if a hop fails (`C-BINDING.md`, `test/chained.test.ts`). Do not weaken that to save hops.
9. Order: **finish B and C (sound + private, measured) → then A.** Week-0 B byte/density survey is B-work. Do not start A-optimization while B still ships dummy pad or C’s fund-safety is untested on a change.

## 2. The 100 KB box (A, later)

When A-work opens, candidates use **standard** meters:

| Limit | Value |
|---|---|
| Tx | 100 000 B |
| Unlocking and redeem, each | 10 000 B |
| Bare P2S | 201 B → kernels **P2SH32** |
| Op-cost | `800 × (41 + unlocking)` |
| Hash iter | **0.5 / density-byte** |
| Cost / hash iter | **192** |
| Control stack | 100 |

10. Evaluate A-candidates with `createVirtualMachineBch2026(true)`. `standard=false` is a diagnostic, not a pass.
11. Do not use consensus hash meters (3.5 iter/byte, 64 cost) as A’s budget. Those are B’s.
12. Do not plan on a CHIP to move 100 KB or 10 KB.

## 3. Fill the box. No buffers.

13. Real verification only. Dummy prefixes, leftover-fill, `packTo`, `KERNEL_UNLOCK_PAD_HIGH`, and OP_DROP cargo are forbidden on any candidate that claims completeness.
14. If a kernel needs budget, grow **useful** unlocking/redeem toward 10 KB.
15. May 2026 VM: `OP_BEGIN`/`OP_UNTIL`, `OP_DEFINE`/`OP_INVOKE`, 128-byte PAA1, BigInt. CashScript first (`cashc` **0.14.0-next.4**).
16. Density is a budget to spend, not a wall to pad up to.

## 4. Completeness (B today)

See [`COMPLETENESS.md`](COMPLETENESS.md). In short: FRI9, 36 unique orbits, on-chain \(R\), grind 20, algebraicC, bind-T, on-chain note Merkle + nullifier, same-tx binds, worksheet ≥ 100 bits (128 target). Silent `FRI_VERSION` bump is a new family.

17. Step kernel is **N notes**, not fewer folds ([`TRACKS.md`](TRACKS.md)).
18. Do not drop membership/nullifier/Merkle from the lock to fit bytes.

## 5. Science

19. Proven / measured / speculative stay apart. A wall is a number, not a product.
20. Inner loop: per-input bytes, op-cost, hash-iter; VM-accept; delta. Outer loop: Chipnet land.
21. Always compile **A, B, and C on the same proof** as controls.
22. Falsifiers stay written. Do not tunnel by weakening §0 or [`COMPLETENESS.md`](COMPLETENESS.md).

## 6. Code / custody / Chipnet / LeanBCH

23. New code: **TypeScript (strict), CashScript, or Rust**. No new `.js`.
24. Secrets in `.local/` and `~/.grok/secrets/chipnet-wallet/` only.
25. Chipnet: `ssh layer1-node` (`159.195.80.214:2222`, key `~/.ssh/node_layer1`). BCHN 29.0.0, RPC 38332, Fulcrum 50001/50002/50004. `$bchn-rpc`. Fee = size + 1 sat. Success = mempool, not a confirmation wait. JSON-RPC for B; Electrum for A/C.
26. LeanBCH floors op-cost and peepholes **real** script. Not BCHN. Not dummy pad.

## Not a win

- First new byte-count wall, or “the lane cannot”
- Green tests on a weaker statement
- Relabeling C, or incomplete A, as B
- A 100 KB tx that only verifies with `standard=false`
- Density pad that greens the meter
- Dropping on-chain Merkle/nullifier/membership
- Changing the SHA-256 default
- Claiming Voidify/Zcash/XMR/StarkWare parity
- Weakening C’s reject/reclaim so a failed hop can lose funds
- Starting A-shrink while B/C still have unfinished soundness or on-chain privacy holes we can still close
