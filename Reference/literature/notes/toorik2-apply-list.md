# `@toorik2` vs `@ABLalgorithm`: inventory, papers, ranked apply-list

Public study of
[`toorik2/ShieldKit-Circle-STARK` `@toorik2`](https://github.com/toorik2/ShieldKit-Circle-STARK/tree/%40toorik2)
against the any-amount Chipnet lab on `@ABLalgorithm`
(`workspaces/any-amount/`). Fetched 2026-08-19.

**This memo does not implement the list.** It does not merge Fv1, copy `.mjs`
into the TypeScript lab, or push `upstream/main`.

HEAD studied: [`1b6e6facf6572b83cf0035b99f532a0558414c38`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/1b6e6facf6572b83cf0035b99f532a0558414c38)
(`feat: measure TRACE/LDE unlink on absorb-in-Q`).

ABL constraint bar (from [`workspaces/any-amount/STATUS.md`](../../../workspaces/any-amount/STATUS.md)):
per-input unlocking+redeem ≤ **10 KB**, standard tx ≤ **100 KB**, consensus tx
≤ **1 MB**, CashVM default **`OP_SHA256`**, any-amount one set, do not widen
sealed Fv1. Opening ZK is a shipped mask, **not** a Lean HVZK theorem.

---

## Inventory

### Provenance (public README)

Raw:
https://raw.githubusercontent.com/toorik2/ShieldKit-Circle-STARK/%40toorik2/README.md

The `@toorik2` README is a **collaboration mirror** of the Circle-domain FRI
shielded-pool research lane. It is a **research workspace, not a product
release**. Initial LABS provenance commit:
`c92e1f81176f6d196410e70564c50c2bdbd02cb9`.

The same README states the complete LABS lane validator is **not a clean-clone
entrypoint** because a source package under
`research-lanes/bch-shielded-pool-design/sources/` is excluded from the public
mirror. Documented start-here is `npm run lane:shielded-pool:research:test`.
`package.json` also exposes `circle-fri:test` for `test/circle-fri/*.test.mjs`.

On `1b6e6fa`, `circle-fri:test` is **92 pass / 0 fail** (Circle-FRI evidence).
The documented start-here `lane:shielded-pool:research:test` pins
`research/circle-fri-candidate-matrix.v1.json` at sha256
`44f1239ef942852e2cc111e7cbe105b2e4a20be2958f980e94082d309e10d02d`
(55194 B, LF, git blob on `upstream/@toorik2`). That pin **matches**. An LF
checkout of `1b6e6fa` runs that script **24 pass / 0 fail**. A Windows
working-tree copy of the same file is 56493 B with 1299 CR and hashes
`f4341a31…`; that is CRLF checkout, **not** sealed-lane drift. The public
README still says the complete LABS validator is not a clean-clone entrypoint
because a source package under `research-lanes/…/sources/` is excluded.

### Only on `@toorik2` (not on `@ABLalgorithm` HEAD)

`@ABLalgorithm` HEAD has **no** `src/circle-fri/`. The product prover lives in
`workspaces/any-amount/src/backends/circle/*.ts`.

All 34 files under
https://github.com/toorik2/ShieldKit-Circle-STARK/tree/%40toorik2/src/circle-fri
are toorik-only science. Named artifacts the plan asked to find:

| Artifact | Path | Commit (public) |
| --- | --- | --- |
| DEEP Re/Im (CM31; pinned **not** Stwo) | [`src/circle-fri/deep.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/deep.mjs) | strategy `circle-deep-re-im-v1` |
| DEEP even-x (Circle-FFT FRI of DEEP) | `src/circle-fri/deep-pi-native.mjs` | used by [`74e4779`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/74e477951348b4e81e4a27cf0aac802d601e5f99) |
| Stwo inner-product DEEP (rejected as dense) | `src/circle-fri/deep-stwo.mjs` | measured wall, not selected |
| E-only DEEP substitute | `src/circle-fri/deep-e-only.mjs` | not the CFFT codeword |
| Poseidon2-M31 permutation | `src/circle-fri/poseidon2-m31.mjs` | AIR hash, not a lock opcode |
| Poseidon2 four-predicate AIR | [`src/circle-fri/poseidon2-air.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/poseidon2-air.mjs) | [`74e4779`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/74e477951348b4e81e4a27cf0aac802d601e5f99), [`1b6e6fa`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/1b6e6facf6572b83cf0035b99f532a0558414c38) |
| Algebraic-hash AIR attempt | `src/circle-fri/algebraic-hash-air.mjs` | column interpolant-FRI wall |
| Batched q2 BCH kernel | [`src/circle-fri/bch-query-batch-kernel.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/bch-query-batch-kernel.mjs) | [`1b69a2b`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/1b69a2b68f32795f49a60ad977926cb11e411ce4) |
| q2 batch witness codec | `src/circle-fri/query-batch-witness.mjs` | same series |
| Canonical Merkle multiproofs | `src/circle-fri/query-multiproof.mjs`, `bch-multiproof-kernel.mjs`, `bch-multiproof4-kernel.mjs` | [`bd8de40`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/bd8de40), [`73709fe`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/73709fe) |
| TRACE/LDE unlink on absorb-in-Q | `poseidon2-air.mjs` + tests | [`1b6e6fa`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/1b6e6facf6572b83cf0035b99f532a0558414c38) |
| ZH·R LDE tail | [`src/circle-fri/stark-zk.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/stark-zk.mjs) | `zh-r-lde-tail-v1`; degree-0 Newton-T classified **failed** |
| 47-bit unselected union | `src/circle-fri/stark-soundness.mjs` | `SOUNDNESS_128_WALL`; not production |
| In-script AIR+DEEP size wall | `src/circle-fri/in-script-air-deep-wall.mjs` | HASH256 predicates leak rho/owner if compiled into the public redeem |
| Host-oracle split | `src/circle-fri/host-oracle-split.mjs` | Re/Im DEEP + HASH256 PAST stay host-side |
| Unique query / rejection sampling | `query-proof.mjs` / transcript | [`986f7a5`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/986f7a5), [`592253d`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/592253d), [`2569193`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/2569193) |
| Query coverage bound to input count | batch kernel | [`66c48f2`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/66c48f2), [`7b889d7`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/7b889d7) |
| J-fold kernel (inverse of 2y checked) | `src/circle-fri/bch-j-fold-kernel.mjs` | executable Circle fold core |
| Nested-coset measurement | `src/circle-fri/nested-coset.mjs` | `standardCoset(6) ∩ standardCoset(9)` is **0/64** |
| Topology table | `src/circle-fri/topology-table.mjs` | unrolled query derivation measured **23950 B** |
| PoolAction relation (Fv1-shaped) | `src/circle-fri/pool-action-relation.mjs` | sealed ticket relation, not any-amount |

Measured walls from `circle-fri:test` on `1b6e6fa` (same TRACE=64 / blowup=16 /
N=1024 / 36 queries as the ABL worksheet):

- Scaled **q2** (18 batched inputs): redeem 4457 B (fits 10 KB), each unlocking
  ≤ 10000, **tx 174794 B > 100000**. Input 9 also exceeds 2026 op-cost density
  by 1. Verdict `FAILED_ENVELOPE`. Speculative P2S estimate 94514 B was **not**
  taken: shrinking unlocking shrinks the density budget and input 9 already
  fails on P2SH32.
- Poseidon2 absorb-in-Q even-x q2 unlocking **11439–11759 B > 10000**.
- Unselected soundness union floor **47 bits** (`3/2^49`). Reaching 128 would
  require selecting a tuple or dropping queries; the DAG forbids both.
- TRACE/LDE unlink: public verify still accepts honest LDE absorb-in-Q plus a
  TRACE Merkle whose absorb rows are all-1s. Three mixed LDE openings do not
  bind 18 TRACE absorb rows. `labeledFriOfAir` dropped.

### Already shipped on `@ABLalgorithm` (do not re-clone)

| Item | ABL location | Overlap |
| --- | --- | --- |
| Circle-domain FRI over M31, TRACE=64, FRI_N=1024, 36 queries, grind 20, rate 2/B, 128 conjectural bits | `workspaces/any-amount/src/backends/circle/params.ts` | Same schedule toorik’s scaled q2 **failed to fit** in 100 KB as q2; ABL fits by **1 query per fold redeem** (standard 1 fold / 79525 B, consensus 36 folds / 283992 B) |
| `foldPair` on the circle | `src/backends/circle/fold.ts`, on-chain `fold-kernel.ts` | Same J-fold idea as `bch-j-fold-kernel.mjs` |
| Sibling-packed Merkle (`pairOrder`) | `fri.ts` `pairOrder` | Partial overlap with reverse-bit pairing; **not** a compact multiproof of many queries |
| ZH·R-style opening mask \(R_{\mathrm{on}}+Z R_{\mathrm{off}}\) deg 7/35 | `witness-mask.ts`, `FRI_VERSION` 6 | Same paper as toorik `stark-zk.mjs`; different encoding (poly mask vs 128-coset tail) |
| Degree-0 Newton-T classified as leak | packed Newton T zeroed; statistical-zk tests | Same “degree-0 failed” conclusion as `DEGREE0_MASK_KIND` |
| Plugin ABI, SHA-256 default, BLAKE2s alternate, Poseidon2 table slot empty | `internal-hash.ts`, `plugins/registry.ts` | Toorik **implemented** Poseidon2-M31 AIR; ABL only reserved the table |
| Any-amount notes / nullifiers / `STATE_BASE` / unlinked fee | `pool/`, `covenant-spend.ts` | Toorik’s relation is **Fv1 PoolAction**, not this profile |
| Sealed `research-lanes/bch-shielded-pool-design/` | present on both refs | Read-only; do not rewrite sealed hashes |
| Chipnet lands | `MILESTONE.md` (`23fd1b7d…`, `9362df54…`, …) | Product evidence; toorik branch has none of these txids |

### Shared tree, different jobs

| Path | `@toorik2` | `@ABLalgorithm` |
| --- | --- | --- |
| `research-lanes/bch-shielded-pool-design/` | science + sealed Fv1 | same sealed lane (do not widen) |
| `src/circle-fri/` | 34 `.mjs` files | **absent** |
| `workspaces/any-amount/` | absent | Chipnet product lab |
| Language | `.mjs` research | TypeScript / CashScript / Rust ([`language-policy.md`](../../language-policy.md): no new JS) |

---

## Papers

Fetched 2026-08-19 from the live URLs (not from memory).

### ePrint 2024/278 — Circle STARKs

- Landing: https://eprint.iacr.org/2024/278
- PDF: https://eprint.iacr.org/2024/278.pdf
- Haböck, Levit, Papini. Received 2024-02-19; last of 3 revisions 2025-02-20.

Defining mechanic: STARKs usually need a smooth multiplicative subgroup.
Circle STARKs use the **circle** \(x^2+y^2=1\) as the FFT/FRI domain. When
\(p+1\) is divisible by a large power of 2, this matches classical STARK cost.
Target field: Mersenne \(p=2^{31}-1\).

Both branches already sit on this domain. Copying Stwo or Plonky3 `circle` as
protocol authority is out of scope (see Non-goals).

### ePrint 2024/1037 — Adding zero-knowledge to STARKs

- Landing: https://eprint.iacr.org/2024/1037
- PDF: https://eprint.iacr.org/2024/1037.pdf
- Haböck, Kindi. Received 2024-06-26; last of 4 revisions 2025-02-22.

Defining mechanic: for small-field FRI STARKs, two techniques: **randomization
by basefield polynomials** (witness mask \(\hat T = T + Z_H\cdot R\)) and
**splitting the quotient into smaller-degree pieces** (a documented source of
implementation mistakes). Perfect ZK for permutation arguments is a later
addendum.

ABL ships \(R_{\mathrm{on}}+Z R_{\mathrm{off}}\) and does **not** claim a Lean
HVZK theorem. Toorik’s `stark-zk.mjs` uses a 128-point ZH·R **tail** and also
refuses to call degree-0 / Newton-T a mask. Neither is the full paper.

### Independent explainer — Vitalik, Exploring circle STARKs

- https://vitalik.eth.limo/general/2024/07/23/circlestarks.html (2024-07-23)

Defining mechanic: Mersenne31’s multiplicative group has size \(2^{31}-2\), so
classical \(x\mapsto x^2\) FRI folds only once. Circle FRI uses the circle
group of size \(p+1\): first fold pairs \((x,y)\) with \((x,-y)\), then
\(x\mapsto 2x^2-1\). The FFT objects are a Riemann–Roch space (polynomials
modulo \(x^2+y^2-1\)), not classical monomials. Pedagogy, not a protocol we
inherit.

### Extra (1037 mechanics, not a 278 substitute)

- Hexens, *Zero Knowledge in STARKs*, 2025-06-06:
  https://hexens.io/blog/zk-in-starks

States the entropy bound \(h \ge 2\cdot S\cdot(e\cdot n_D + n_F) + n_F\) and
that FRI folding **burns** mask entropy, so the DEEP composition polynomial
needs its own mask. Explicitly based on 2024/1037.

### Optional comparators (not applied)

- FRI: https://eprint.iacr.org/2018/046
- DEEP-FRI: https://eprint.iacr.org/2019/336
- ethSTARK bits: https://eprint.iacr.org/2021/582
- Poseidon2: https://eprint.iacr.org/2023/323
- Compact Merkle multiproofs: https://arxiv.org/abs/2002.07648
- Stwo (prior art): https://github.com/starkware-libs/stwo
- Plonky3 circle (prior art): https://github.com/Plonky3/Plonky3

---

## Ranked apply-list

Every row names a toorik path or commit SHA, the ABL envelope it hits, and
**apply-now** / **later** / **do-not-copy**. “Apply” means re-implement the
*idea* in TypeScript/CashAssembly on `@ABLalgorithm`. It never means copying
`.mjs` files.

### apply-now

| Idea | Toorik evidence | ABL constraint it hits | Why now |
| --- | --- | --- | --- |
| Unique first-fold FRI query orbits (rejection sample until distinct) | [`986f7a5`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/986f7a5), [`2569193`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/2569193), [`592253d`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/592253d) | Soundness of 36 queries on FRI_N=1024. ABL `queryIndices` in `fri.ts` is `(h[0]<<8\|h[1]) % n` with **no** uniqueness. Colliding queries silently drop bits. Fits 10 KB (FS already recomputed on-chain). | Cheap, same lock shape, real bit leak. |
| 2024/1037 entropy accounting for the off-domain mask degree | [`src/circle-fri/stark-zk.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/stark-zk.mjs) (`ZH_R_LOG = 7`); Hexens bound; ePrint [2024/1037](https://eprint.iacr.org/2024/1037) | ABL `OPEN_MASK_DEGREE=7`, `OPEN_MASK_OFF_DEGREE=35` is empirical, not the paper bound for \(n_F=36\), blowup 16, no DEEP (\(n_D=0\)). Lock still must **not** evaluate \(R\) (10 KB). Prover-side only. | Raises the shipped mask toward the paper without DEEP or Poseidon2. Not a Lean theorem. |
| Compact Merkle **multiproof** of several packed openings (shared frontier) | [`query-multiproof.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/query-multiproof.mjs), [`bd8de40`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/bd8de40), [`73709fe`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/73709fe); arXiv [2002.07648](https://arxiv.org/abs/2002.07648) | ABL spends **10** Merkle-kernel inputs and 252 openings (`STATUS.md`). Sibling `pairOrder` already packs one pair; it does not share a frontier across queries. Hash stays `OP_SHA256`. Must keep each unlocking ≤ 10 KB. | Biggest size win that still matches the shipped verifier family. Re-implement in TS, do not import `.mjs`. |
| Script-checked inverse of \(2y\) on J-fold | [`bch-j-fold-kernel.mjs`](https://github.com/toorik2/ShieldKit-Circle-STARK/blob/%40toorik2/src/circle-fri/bch-j-fold-kernel.mjs) (`(2*y)*inverseTwoY = 1`) | ABL `fold-kernel.ts` already foldPairs 1 query. Compare whether inverse is host-trusted. 10 KB still 1 query/redeem. | Small soundness hygiene if ABL currently trusts a felt inverse. |

### later

| Idea | Toorik evidence | ABL constraint it hits | Why later |
| --- | --- | --- | --- |
| Two-query batched FRI (q2) in one redeem | [`1b69a2b`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/1b69a2b), `bch-query-batch-kernel.mjs` | Same 64/16/1024/36 schedule: measured **174794 B > 100000**, input-9 density fail. ABL already fits 79525 B by keeping **1 query per fold**. STATUS: “2+ queries in one redeem exceed ~800× script-length.” | Copying q2 would *lose* the 100 KB relay path toorik could not close. Revisit only after a density model that beats that measurement. |
| DEEP even-x FRI of \((E(x)-E(\zeta_x))/(x-\zeta_x)\) | `src/circle-fri/deep-pi-native.mjs`, [`74e4779`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/74e477951348b4e81e4a27cf0aac802d601e5f99) | STATUS: Full DEEP-ALI **not done**. Re/Im DEEP is **not** a Circle-FFT low-degree codeword (`src/circle-fri/deep.mjs` wall). Extra openings blow 10 KB. | Correct science; size-unfit for the product lock this round. |
| Poseidon2-M31 as `InternalHash` table entry (prover-side) | `src/circle-fri/poseidon2-m31.mjs`, ePrint [2023/323](https://eprint.iacr.org/2023/323) | ABL table already allows a third digest; lock still `OP_SHA256`. Poseidon2-in-AIR even-x unlocking **>10 KB**. | Table swap is already designed. Do not put Poseidon2 in the redeem. |
| TRACE vs LDE bind tests (garbage absorb still verifies) | [`1b6e6fa`](https://github.com/toorik2/ShieldKit-Circle-STARK/commit/1b6e6facf6572b83cf0035b99f532a0558414c38) | ABL FRI is of `onChainCells` interpolant, not a Poseidon2 TRACE table. Nested coset intersection on toorik’s CFFT family is **0/64**. | Steal the *falsifier* (TRACE garbage vs LDE Q) when DEEP/AIR lands. Not a silent copy of absorb-in-Q. |
| Runtime topology table / unrolled FS in script | `src/circle-fri/topology-table.mjs` | Unrolled query derivation **23950 B > 10 KB**. ABL already recomputes FS index per slot in CashAssembly. | Keep slot-unrolled FS; do not unroll 36 queries into one redeem. |
| Host-oracle split as STATUS text | `src/circle-fri/host-oracle-split.mjs` | ABL already keeps algebraicC / reserves / preimage off the packed interpolant. | Optional doc alignment. Not a kernel. |
| ZH·R 128-coset **tail** instead of poly mask | `src/circle-fri/stark-zk.mjs` `applyZhR` | Doubles published domain (log 7 vs TRACE 6). Nested \(H\subset\mathrm{LDE}\) is **false** on their CFFT family. ABL poly mask already stops degree-0 Q diffs. | Alternative encoding; no evidence it fits 10 KB better. Keep poly mask unless a measurement says otherwise. |

### do-not-copy

| Idea | Toorik evidence | ABL constraint it hits | Why never (this product) |
| --- | --- | --- | --- |
| Copy `src/circle-fri/*.mjs` into the any-amount lab | whole tree | [`language-policy.md`](../../language-policy.md): new code is TypeScript / CashScript / Rust; **no new JS** | Research notebooks stay on `@toorik2`. Re-implement ideas in `.ts`. |
| Poseidon2 / absorb-in-Q **in the lock** | `src/circle-fri/poseidon2-air.mjs`, unlocking 11439–11759 B | 10 KB; CashVM pays `OP_SHA256`; STATUS: Poseidon2 is not a lock opcode | Measured overshoot. |
| HASH256 note/nullifier predicates in the **public** redeem | `src/circle-fri/in-script-air-deep-wall.mjs` | Would put owner\|\|rho in unlocking; contradicts shipped OTP / mask | Toorik’s own wall text. |
| Relabel 47-bit unselected union as 128-bit systemic | `src/circle-fri/stark-soundness.mjs` `SOUNDNESS_128_WALL` | ABL worksheet is 36×(log2(16)−1)+20 = 128 **conjectural** bits on rate 2/B, not toorik’s 4-query DAG | Different accounting. Do not mix. Do not drop queries to fake 128. |
| Stwo DEEP / inner-product as the protocol | `src/circle-fri/deep.mjs` comment: “Not Stwo's two-point conjugate opening”; `src/circle-fri/deep-stwo.mjs` dense | Circle FRI (2024/278) is the family; Stwo is prior art | Toorik already rejected it as the selected DEEP. |
| Widen sealed Fv1 / `PoolActionFv1` | `src/circle-fri/pool-action-relation.mjs`, `research-lanes/…/spec/pool-action-fv1.json` | Product is **any-amount**, one set. Fv1 stays the joint size gate | AGENTS.md / stark-agnostic-pool skill. |
| Treat a failed/absent LABS complete validator as empty science | README excluded-source paragraph | Public `circle-fri:test` is green (92/92) | README already warns the complete validator is not a clean-clone entrypoint. |
| P2S-shrink of q2 to “make 100 KB” while density already fails | `src/circle-fri/bch-query-batch-kernel.mjs` scaled q2 `whyNotTaken` | 10 KB density budget shrinks with unlocking | Toorik stopped. Do not take the speculative path. |
| Groth16 / pairing / Maxwell CHIP / Lean theorem this round | — | Non-goals of this study | Unchanged. |

---

## What would actually make the lab better

The “big time” items that fit the envelopes are **not** Poseidon2-in-script and
**not** q2. Toorik already measured those walls at the same 64/16/1024/36
schedule ABL ships, and they miss 10 KB or 100 KB.

The items that move the product:

1. **Unique FS queries** (soundness hygiene).
2. **1037 mask-degree accounting** (opening ZK toward the paper, still not Lean).
3. **Merkle multiproofs** (cut the 10-input / 252-opening Merkle tax without
   folding two FRI queries in one redeem).

DEEP even-x and Poseidon2-as-`InternalHash` stay later. Fv1, `.mjs`, and
Poseidon2-in-lock stay out.
