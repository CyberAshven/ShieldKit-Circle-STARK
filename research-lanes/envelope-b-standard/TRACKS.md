# Tracks (they do not share a bottleneck)

**Order:** B and C sound + private first. The 100 KB shrink is **envelope A**, later.

## Track 0 — B and C (now)

**Question:** is the 1 MB B successor, and C’s fund-safe tape, actually statistical Circle FRI + on-chain membership/nullifier/Merkle + confidential notes, including `--batch-exit`?

Known holes (not closed): dummy pad on B; note-auth unlocking publishes preimage (anonymity set 1); batch-exit extra notes still in `verifyFri`; A has no note-auth.

Scoreboard: `survey/`, `test/hole-free-b.test.ts`, `test/onchain-privacy.test.ts`, `test/batch-exit.test.ts`, `test/chained.test.ts`, `C-BINDING.md`.

## Track 1 — 100 KB / 36 queries (envelope **A**, later)

**Question:** can FRI9’s **36 unique-orbit** verifier (fold + R + grind + algebraicC + bind-T + on-chain note-auth) sit in **one standard tx**?

Bottleneck: **query kernels** (36 folds + 36 R-slots), Merkle openings, **density pad**, standard **hash meters**.

Not a lever: step kernel. Adding N note-auth inputs does not shrink fold/slot count.

Scoreboard: `survey/b-input-bytes.md`, `survey/density-law.md`, then later candidates vs 100 000 B + `standard=true`.

## Track 2 — N notes in one tx (step kernel)

**Question:** can B walk **N notes** on chain in one transaction?

Bottleneck: audited note-auth reads both nullifier roots at **absolute input 0**, so N copies collide. Step kernel bakes \((R_{\mathrm{in}},R_{\mathrm{out}})\) into the redeem; the covenant pins each by index.

Not a lever: 100 KB. Step kernels add inputs. Room on **consensus B** is ~hundreds of notes by bytes; on **standard 100 KB** it is a later, smaller N.

Scoreboard: `test/note-auth-step-kernel.test.ts`, `test/envelope-batch.test.ts`. FRI9 bytecode stays identical (`FRI_VERSION` untouched).

## How they run

| | Track 1 | Track 2 |
|---|---|---|
| Edit | fold / R-slot / Merkle / pad removal | `note-auth-step-kernel.ts` + covenant pin |
| Do not edit for the other track | step kernel | fold/slot ASM |
| Shared | FRI9 params, packed AIR, PAA1, RULES completeness rows 1–10 |
| Merge | only at a candidate that already has a 100 KB story **or** an honest wall |

Week-0 work is **track 0 measurement** (B byte table + density law). Track 1 (A) waits. Track 2 stays parked behind its existing tests.
