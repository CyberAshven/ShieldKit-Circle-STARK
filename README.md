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
| On-chain 2026 lock | P2SH32 five-point `PAA1` + 10 FRI Merkle kernels + bind-T + fold kernels + slot `C=Q·Z`. Standard: **1** fold + **6** slots (≤ 100 KB). Consensus: **10** folds + **36** slots (≤ 1 MB). One query per fold redeem (density). |
| Chipnet fold lands | Standard **98831 B** `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0`. Consensus **301279 B** `18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6`. Earlier 36-slot **no-fold** proof: `356630bd…`. See [`workspaces/any-amount/MILESTONE.md`](workspaces/any-amount/MILESTONE.md). |
| Consensus land path | Compile locally. Tx ≤ 100000: Electrum. Tx > 100000: HTTP JSON-RPC `sendrawtransaction` (not Electrum, not P2P `inv`). Public miners will not relay 301 KB. |
| Not this pre-release | Statistical ZK, Lean, mainnet, OPTN builtin register, hidden pool-UTXO value, 36/36 query folds. |

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
