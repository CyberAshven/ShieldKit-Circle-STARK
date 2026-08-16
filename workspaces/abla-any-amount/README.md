# Any-amount Chipnet lab

New profile on `@ABLalgorithm`. **Does not edit** the sealed Fv1 lane
(`research-lanes/bch-shielded-pool-design/`). Fv1 stays the joint 0.1-ticket
size gate. This workspace is the product profile: one set, any amount.

## What is live vs what is not

| Piece | Status |
| --- | --- |
| Plugin ABI `Verify(family, vk, statement, proof)` | Live (TypeScript) |
| `hash-lab-v0` backend | Live. Merkle notes **off-chain**; covenant is a **lab-gated conservation cell**. **Not private.** |
| `circle-fri-m31` backend | Live prove/verify: M31 + circle domain + fold + Merkle + 8 queries. **`sound: false`** (n=32). Not a 128-bit STARK. |
| CashToken 128-byte `PAA1` state + 5-point successor | Live in libauth 2026 VM tests |
| Chipnet genesis / deposit | Attempted by `pool create` / `pool deposit` when a faucet-funded lab wallet exists |
| Hidden amounts / confidential assets | **Not built.** `public_amount` is visible. |
| Sound Circle FRI membership on chain | **Not built.** P2 circle/query/prover in the joint lane is still closed. |
| OPTN builtin register | **Not done.** Zero-touch: addon talks to `http://127.0.0.1:17432` if `pool serve` is running. |

If you wake up and a Chipnet txid is in `STATUS.md`, that is a **conservation-cell** spend, not a sound shielded withdraw.

## Why a lab gate

A covenant that lets anyone rewrite `noteRoot` without a proof is stealable.
Until Circle FRI `Verify` fits, Chipnet spends are authorized by the **local
lab wallet key** *and* the five-point + reserve checks. The plugin still runs
off-chain so swapping in Circle FRI later does not change the statement.

## Commands

```bash
cd workspaces/abla-any-amount
npm ci
npm test
npx tsx src/cli.ts wallet new
npx tsx src/cli.ts faucet
npx tsx src/cli.ts pool create
npx tsx src/cli.ts pool deposit --sats 12000
npx tsx src/cli.ts pool withdraw --sats 5000
npx tsx src/cli.ts serve
```

Wallet files stay under `.local/` (gitignored). Never pass a seed on the command line.

## Plugins

- `hash-lab-v0` — SHA-256 note commitments + incremental Merkle. Lab only.
- `circle-fri-m31` — M31 Circle FRI. Prove/verify run; `sound` stays false until parameters justify more.
