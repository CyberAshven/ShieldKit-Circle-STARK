# ShieldKit Circle STARK

**Pre-release lab** on `@ABLalgorithm`. Product: **Any-amount Chipnet lab**.
Language: **TypeScript, CashScript, Rust** — no new JavaScript.

## Start here (the lab)

```bash
cd workspaces/any-amount
npm ci
npm test
npx tsx src/cli.ts --help
```

| Piece | Status |
| --- | --- |
| Off-chain Circle FRI prover + verifier | TypeScript `proveFri` / `verifyFri`. False reserve / fake note / fake nullifier fail. |
| Optional Rust prove worker | `crates/circle-fri-worker` — old n=32 wire; TS is the shipped path. |
| On-chain 2026 lock | P2SH32 five-point `PAA1` + 10 FRI Merkle kernels + bind-T + slot `C=Q·Z` (default 1 slot / 100 KB; consensus profile 36 slots / 1 MB). |
| Not in this pre-release | Full FRI fold, ZK, Lean, mainnet, OPTN builtin register. |

Lab notes: [`workspaces/any-amount/STATUS.md`](workspaces/any-amount/STATUS.md),
[`DESIGN.md`](workspaces/any-amount/DESIGN.md).
OPTN screen stub (not wired into OPTN upstream):
[`addons/optn-shielded-pool/`](addons/optn-shielded-pool/).

## Sealed Fv1 research lane

[`research-lanes/bch-shielded-pool-design/`](research-lanes/bch-shielded-pool-design/)
is the joint 0.1-ticket size-gate lane. This branch does **not** edit it.
Do not merge `@ABLalgorithm` to `main` unless both sides agreed.

```bash
npm ci
npm run lane:shielded-pool:research:test
```

## Reference

Public prior-art notes live in [`Reference/`](Reference/).
Start at [`Reference/00-INDEX.md`](Reference/00-INDEX.md). Cite public URLs only.
