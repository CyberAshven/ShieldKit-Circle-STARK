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
| On-chain 2026 lock | P2SH32 five-point `PAA1` + 10 FRI Merkle kernels + bind-T + **6** slot `C=Q·Z` (100 KB) or **36** (1 MB). |
| Chipnet proof | 36-slot successor **270251 B** `356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898` — see [`workspaces/any-amount/MILESTONE.md`](workspaces/any-amount/MILESTONE.md). |
| On-chain fold | Shipped lock requires `fold-kernel.ts`. VM accepts honest fold and rejects a flipped FS index. Density: **1** folded query per redeem (2+ exceed 2026 cost). |
| Not this pre-release | ZK masking, Lean, mainnet, OPTN builtin register, hidden pool-UTXO value. |

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
