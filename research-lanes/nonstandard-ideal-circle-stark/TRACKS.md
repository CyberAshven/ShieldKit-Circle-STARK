# Tracks (they do not share a bottleneck)

**Order:** SHA AIR in the lock first. Unfuse only if density holds without pad. Walk-in batch after §6 is in script. The 100 KB shrink is the **sibling** lane, not this one.

## Track 0 — SHA-256 AIR on extra inputs (now)

**Question:** can the 576-column note-auth AIR sit on 36 extra inputs in one consensus tx, with mixed publics VM-reject and no preimage in unlocking?

Bottleneck: per-input 10 KB + density `800×(41+unlocking)`, not policy 100 KB. Extra is 94788 B. Occupancy+AIR ≈ 194 kB.

Not a lever: leftover SHA-LDE, bundle size, retry-prove to 100 KB.

Scoreboard: `START.md`, `survey/artifacts/qm31-fri10/`, `src/chain/note-auth-air.ts`, `test/note-auth-air.test.ts`, `test/shielded-unlocking-b.test.ts`.

## Track 1 — full 36-orbit unfused skeleton (later)

**Question:** can B run one orbit per fold redeem (36 folds + 36 R) without `KERNEL_UNLOCK_PAD`, still under 1 MB?

Bottleneck: density on high-index kernels. Fusion of 6 queries per fold is an allowed substitute if density holds.

Not a lever: 100 KB.

## Track 2 — N notes in one tx (step kernel)

**Question:** can B walk **N notes** on chain in one consensus transaction?

Bottleneck: audited note-auth reads both nullifier roots at absolute input 0, so N copies collide. Step kernel bakes \((R_{\mathrm{in}}, R_{\mathrm{out}})\) into the redeem; the covenant pins each by index.

Not a lever: 100 KB. Room on consensus B is hundreds of notes by bytes.

Scoreboard: `test/note-auth-step-kernel.test.ts`, `test/envelope-batch.test.ts`.

## How they run

| | Track 0 | Track 1 | Track 2 |
|---|---|---|---|
| Edit | note-auth AIR kernels + extra inputs | fold / R-slot ASM | `note-auth-step-kernel.ts` + covenant pin |
| Do not edit for the others | step kernel | AIR columns | fold/slot ASM |
| Shared | FRI10 params, packed AIR, PAA1, RULES completeness |
| Merge | only at a candidate that already has a 1 MB story **or** an honest wall |
