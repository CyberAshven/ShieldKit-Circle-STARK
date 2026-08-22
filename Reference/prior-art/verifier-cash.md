# Prior art: verifier.cash (Groth16 on BCH, not STARKs)

Site: https://www.verifier.cash/  
Read 2026-08-16. **This is pairing Groth16.** It is not Circle FRI, not a STARK, not PQ, and it needs a per-circuit trusted setup. Still the best public map of *how BCH actually hosts a proof verifier*.

The Any-amount Chipnet lab stays hash-STARK / Circle FRI first. Use this page for packaging, not as a backend swap.

## What it is

A public leaderboard for **the same Groth16 verifier** expressed many ways on the BCH 2026 VM. Score = **total on-chain bytes** (locking + unlocking + tx overhead). Lower wins because bytes are fees.

Correctness is a gate: accept a valid proof, reject tampered / worst-case / off-curve witnesses, or it is not listed.

Two curve lines (do not compare bytes across them):

- **BN254** — 32-byte field elements (Ethereum pairing curve)
- **BLS12-381** — 48-byte elements (nChain / many “serious” SNARK setups)

Two *categories* (different artifacts):

| Category | Meaning |
| --- | --- |
| Singleton / “smallest” | One input, fewest bytes. Usually **busts op-cost**. Cannot run on BCH. Charts the byte floor. |
| BCH-native | Split across inputs (and maybe txs) so each stays ≤ 10 KB unlocking and ≤ ~8M op-cost. **This is what can run.** |

Op-cost budget is `(41 + unlockingLength) × 800` (≈ 8.0M at the 10 KB cap). Padding buys compute. The 10 KB wall and the op-cost wall are the same wall.

## Numbers on the page (BN254, 2026-08-16)

| Label | Size | Structure | Runs on BCH? |
| --- | ---: | --- | --- |
| Smallest full verifier (BLS12-381) | 3,715 B | 1 input | no |
| Byte floor (Toorik `groth16-singleton-genpow`) | 4,651 B | 1 input | no (op-cost) |
| mr-zwets opcode-optimized singleton | 6,584 B | 1 input | no |
| **Best BCH-native** (Toorik `groth16-intratx-pairfold5-pevalfuse`) | **39,691 B** | **5 inputs, 1 tx** | **yes, standard** |
| Same family, 5-input PairFold | 44,968 B | 5 inputs | yes |
| 7-input PairFold | 54,483 B | 7 inputs | yes |
| mr-zwets `bch-spec` (TXv5-shaped 100 KB scripts) | 58,760 B | 4 inputs | not current BCH |
| kallisti residue intra-tx | 86,950 B | 11 inputs | yes |
| kallisti chunked-covenant-residue | 93,802 B | 12 txs × 1 input | yes |
| sCrypt BN256 baseline (BSV, 2022) | 11.7 MB | 1 input | no |

~8.5× between the 4.7 KB floor and the 40 KB fitting verifier is the **price of the per-input VM**, including the floor’s “bytes for compute” cheat.

History on the site: best *fitting* verifier down **98%** since the first native build (Jun 19 → Aug 11 2026).

## How they split (this is the note that matters for STARKs)

A full pairing check (Fp → Fp2 → Fp6 → Fp12, Miller loop, final exp) does not fit one input. They use the same two wirings we already named for FRI shards:

1. **Intra-tx** — many inputs in **one** standard tx. Inputs bind each other with `OP_INPUTBYTECODE`. Best when the whole graph stays ≤ 100 KB.
2. **Covenant / multi-tx** — one (or a few) inputs per tx. Running state in a **CashToken NFT**. Commitment is only 128 B, so they store `hash256(full state)` and the next spender re-supplies the preimage.
3. **Grouped** — intra-tx *inside* a handful of standard txs, NFT hand-off *between* them. For graphs that overflow one 100 KB tx but must still relay.

Secondary tricks that actually moved the score:

- **residue** — replace the final-exp hard part with a witnessed `c^λ` check (biggest single win).
- **PairFold / pevalfuse** — Toorik’s current 5-input winner.
- **GLV** — endomorphism-split MSM on the residue builds.
- **minop vs genpow** — spend bytes to cut op-cost, or spend op-cost to cut bytes (Pareto, not one “the singleton”).

## Runtime proof vs baked chunks

The bench is honest about this (`proofBinding`):

- **Runtime-general** (singletons, BSV references): proof is push-only in the unlocking. One deployed program, many proofs.
- **Instance-specific** (most chunked / intra-tx / grouped): proof material is **baked into the chunk scripts**. A new proof means regenerate chunks.

Both verify on-chain. They are not the same product. A shielded pool wants the first kind if users prove locally. Our Circle FRI plugin is closer to runtime-general off-chain; on-chain shards are still closed.

## GitHub: they all land in one repo

**Every submission is a PR to** https://github.com/mr-zwets/zk-verifier-bench — not a new GitHub repo per solver.

Recipe ([CONTRIBUTING.md](https://github.com/mr-zwets/zk-verifier-bench/blob/main/CONTRIBUTING.md)):

1. Vectors JSON in `src/bch/` (compiled hex; this is the reviewable artifact).
2. One module `src/implementations/bch-<id>.ts` (metadata + construction notes + locking sha256).
3. One line in `REGISTRY` in `src/harness/benchmark.ts`.

CashScript source / compiler forks **may stay private**. The harness grades *behavior* (valid accept, tamper reject, multiproof if `proofBinding: 'runtime'`, worst-case proof, off-curve inputs, **cross-stage staple** on intra-tx). Do not regenerate `results.json` in the PR; maintainer re-exports.

Companion (not the inbox):

| Repo | Job |
| --- | --- |
| https://www.verifier.cash/ | Site; reads the bench JSON |
| https://github.com/mr-zwets/groth16_cashscript | Shared Groth16 statement, CashScript oracles, mint tools |
| https://github.com/mr-zwets/cashscript/tree/feat/reusable-functions | Optional compiler fork |
| https://github.com/toorik2/ShieldKit-SDK | Product. Chipnet SNARK pool uses PairFold from this bench — not Circle FRI |

`REGISTRY` (full Groth16 + pairing + vk_x milestones + BSV refs). Each file is under `src/implementations/`:

- BSV refs: `nchain`, `scrypt-bn256`
- BN254 singletons: `bch-groth16-singleton`, `-opcode-optimized`, `-genpow`, `-minop`
- BLS12-381 singletons: same four + `-fs`
- Chunked / covenant: `bch-groth16-chunked`, `-chunked-covenant`, `-chunked-covenant-residue` (+ BLS twins)
- Intra-tx: `bch-groth16-intratx`, `-direct-state-public`, `-authenticated-p2s`, `-residue`, `-residue-large` (bch-spec), `-crown8-rawchain`, `-pairfold7`, `-pairfold5`, `-pairfold5-pevalfuse`, `-general` (+ BLS `intratx` / `-residue` / `-fs` / `-residue-large`)
- Grouped: `bch-groth16-grouped`, `-grouped-residue` (+ BLS twins)
- Partials: `bch-vkx-*`, `bch-pairing-*`
- Demo: `bch-multistep-demo`

Harness extras we should copy: **P2SH20 is disallowed** (~2^80 collision); use P2SH32 or P2S. Intra-tx entries get a **cross-stage staple** test (splice proof #0’s first k inputs onto proof #1’s rest — must reject). Covenant/grouped NFT hand-off is `tokenSafetyEnforced` or it is scored as not pinned.

## What this is not (for our lab)

- Not a STARK. Pairings + trusted setup. Quantum breaks it. The site says this out loud and points at hash STARKs / Quantumroot as the long run.
- Not a 128-bit on-chain Circle FRI measurement. Goldilocks **sound** FRI wiring already measured ~120 KB; Groth16 **fitting** is ~40 KB. Different family, different statement, different “baked vs runtime.” Do not score them as one race.
- Toorik’s live Chipnet SNARK pool is prior art for *covenant + plugin Verify*, not a reason to drop Circle FRI.

## What we should steal (packaging only)

- Intra-tx first while the graph is ≤ 100 KB; grouped/NFT chain if it is not.
- NFT carries a **hash of state**, not the whole witness (128 B Layla commitment).
- Score full serialized tx, not a component script.
- False-statement / tamper / worst-case / off-curve rejects in the harness — same discipline as `verifyFri` false-statement tests.
- Say `proofBinding` out loud: runtime vs regenerate-chunks.
- Op-cost padding is real. A 4.7 KB script that needs 649 inputs of budget is not a verifier.

## Why they picked Groth16 anyway

Smallest proofs (128–192 B compressed), constant-time verify, most deployed SNARK (Zcash original, Tornado, many rollups). With no pairing precompile, the *verifier* is huge field-tower Script — so they compete on **verifier bytes**, not proof bytes. Hash STARKs invert that: fat proofs, leaner hash loops, no setup.

A Groth16 *proof* is tiny. A Groth16 *BCH verifier* is 40 KB when it fits. A Circle FRI *proof* is already 7.6 KB in our bench (`n=32`, unsound); a sound on-chain shard set is the open problem this leaderboard does not measure.
