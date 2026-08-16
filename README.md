# ShieldKit Circle STARK

**Pre-release lab** on `@ABLalgorithm`. Product: **Any-amount Chipnet lab**.
Language: **TypeScript, CashScript, Rust** — no new JavaScript.  
Rolling GitHub pre-release tag: **`v0.0.1`** (overwritten on each `@ABLalgorithm` push until real versioning).

## Latest

FRI openings and packed Q are offset by a degree-0 mask; the **standard 100 KB and consensus 1 MB** slot locks subtract that felt before `C=Q·Z`. Published rho/owner/amount stay one-time-padded. Chipnet 36-fold land `b1415faf…` (height 319402) is the lock **before** this opening-mask compile. Scoreboard: [`workspaces/any-amount/STATUS.md`](workspaces/any-amount/STATUS.md). Accumulating lands: [`MILESTONE.md`](workspaces/any-amount/MILESTONE.md). Ciphertext vs proof: [`Reference/literature/notes/ciphertext-vs-circle-stark.md`](Reference/literature/notes/ciphertext-vs-circle-stark.md).

## Start here (CLI navigator)

```bash
cd workspaces/any-amount
npm ci
npm test
npx tsx src/cli.ts --help
npx tsx src/cli.ts status
npx tsx src/cli.ts wallet new
npx tsx src/cli.ts wallet show
npx tsx src/cli.ts faucet
npx tsx src/cli.ts balance
npx tsx src/cli.ts pool create
npx tsx src/cli.ts pool deposit --sats 12000
npx tsx src/cli.ts pool withdraw --sats 5000
npx tsx src/cli.ts pool measure-tx
npx tsx src/cli.ts lab e2e
npx tsx src/cli.ts lab demo --wallets 2
npx tsx src/cli.ts bench
npx tsx src/cli.ts serve
```

Chipnet (funded lab wallet only): `pool chipnet-covenant` then `pool chipnet-mix`. Tx ≤ 100000 → Electrum. Tx > 100000 → JSON-RPC `sendrawtransaction`. Never mainnet. Seeds stay in `.local/`.

| Piece | Status |
| --- | --- |
| Off-chain Circle FRI prover + verifier | TypeScript `proveFri` / `verifyFri`. False reserve / fake note / fake nullifier fail. |
| Optional Rust prove worker | `crates/circle-fri-worker` — old n=32 wire; TS is the shipped path. |
| On-chain 2026 lock | P2SH32 five-point `PAA1` + 10 FRI Merkle kernels + bind-T + fold kernels + slot `C=Q·Z`. Standard: **1** fold + **6** slots (≤ 100 KB, measured 98979 B with opening mask). Consensus: **36** folds + **36** slots (≤ 1 MB, measured 383031 B). One query per fold redeem (density). |
| Chipnet fold lands | Standard `2acb1196…` (98831 B, 1 fold). Consensus **36-fold** `b1415faf…` (382203 B, height 319402). Prior 10-fold `18c74b49…`. No-fold `356630bd…`. See [`workspaces/any-amount/MILESTONE.md`](workspaces/any-amount/MILESTONE.md). |
| Consensus land path | Compile locally. Tx ≤ 100000: Electrum. Tx > 100000: HTTP JSON-RPC `sendrawtransaction` (not Electrum, not P2P `inv`). Public miners will not relay 301 KB. |
| Note amounts | Tagged SHA-256 commit bound by `checkAuthRelation`. Public net committed in `encodeStatement`. Pool UTXO stays `STATE_BASE`. |
| Published witness | `encodeFriProof` one-time-pads rho/owner/amount. FRI openings/packed Q are offset by a degree-0 mask the lock subtracts. Viewing key is not in the encoding. |
| Not this pre-release | Lean, mainnet, OPTN builtin register, hidden pool-UTXO value, better-than-XMR. |

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
