# ShieldKit Circle STARK

**Pre-release lab** on `@ABLalgorithm`. Product: **Any-amount Chipnet lab**.
Language: **TypeScript, CashScript, Rust** — no new JavaScript.  
Rolling GitHub pre-release tag: **`v0.0.1`** (overwritten on each `@ABLalgorithm` push until real versioning).

## Latest

Envelopes: **A** occupancy standard tx (FRI10 QM31, may be incomplete) in [`research-lanes/sha-in-occupancy-c`](research-lanes/sha-in-occupancy-c/); **B** completeness at consensus size; **C** B as chained standard hops. Contract: [`workspaces/any-amount/ENVELOPES.md`](workspaces/any-amount/ENVELOPES.md). FRI9 Chipnet txids are not relabeled.

ZKP plugin hook is **off-chain + registry**: default `circle-fri-m31`, second family `hash-lab-v0` (**not private**, **not sound**) on the same statement. On-chain redeem is still Circle fold/C=QZ. Internal hash is a drop-in knob (default SHA-256, BLAKE2s and Poseidon2-M31 alternates). Poseidon2-M31 is prover-side only; Monolith is not shipped. On-chain `OP_SHA256` is the SHA-256 backend of the default knob, not a second tree. On-chain Circle verifier is Merkle+fold+C=QZ (`OP_SHA256`). Openings use \(R_{\mathrm{on}}+Z R_{\mathrm{off}}\) (SHA-256; not a Lean HVZK theorem). Confidential bar is notes+OTP+unlinked fee+hiding net/reserve commits; pool UTXO stays `STATE_BASE` (script cannot Maxwell-hide it). One-set aggregated pool. Latest Chipnet lands: standard `23fd1b7d…` (79525 B, Electrum) and consensus `9362df54…` (283992 B, JSON-RPC). Not better-than-XMR or Zcash. Scoreboard: [`workspaces/any-amount/STATUS.md`](workspaces/any-amount/STATUS.md). Accumulating lands: [`MILESTONE.md`](workspaces/any-amount/MILESTONE.md). Ciphertext vs proof: [`Reference/literature/notes/ciphertext-vs-circle-stark.md`](Reference/literature/notes/ciphertext-vs-circle-stark.md).

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
npx tsx src/cli.ts pool deposit --sats 12000   # optional --hash blake2s|poseidon2-m31 --plugin circle-fri-m31|hash-lab-v0
npx tsx src/cli.ts pool withdraw --sats 5000   # optional --batch-exit [--batch-window 180]
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
| On-chain 2026 lock | P2SH32 five-point `PAA1` + 10 FRI Merkle kernels + bind-T + fold kernels + slot `C=Q·Z`. Standard: **1** fold + **6** slots (≤ 100 KB). Consensus: **36** folds + **36** slots (≤ 1 MB). One query per fold redeem (density). Plugin switch is off-chain; redeem stays Circle fold/C=QZ. `OP_SHA256` is the default hash-knob backend. |
| Chipnet lands | Latest standard `23fd1b7d…` (79525 B) and consensus `9362df54…` (283992 B). History in [`workspaces/any-amount/MILESTONE.md`](workspaces/any-amount/MILESTONE.md). Do not relabel `356630bd`, `18c74b49`, `2acb1196`, `b1415faf`, `617b1022`, `b3ea8a75`, `c40f4948`, `f14bff7b`. |
| Consensus land path | Compile locally. Tx ≤ 100000: Electrum. Tx > 100000: HTTP JSON-RPC `sendrawtransaction` (not Electrum, not P2P `inv`). Public miners will not relay 301 KB. |
| Note amounts | Tagged internal-hash commit (default SHA-256, BLAKE2s / Poseidon2-M31 prover-side) bound by `checkAuthRelation`. Poseidon2 is not a lock opcode. Monolith is not shipped. Public net committed in `encodeStatement`. Pool UTXO stays `STATE_BASE`. |
| ZKP plugins | Default `circle-fri-m31`. Second family `hash-lab-v0` (not private/sound). Switch is off-chain + registry. |
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
