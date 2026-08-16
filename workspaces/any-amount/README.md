# Any-amount Chipnet lab

**Does not edit** the sealed Fv1 lane
(`research-lanes/bch-shielded-pool-design/`). Fv1 stays the joint 0.1-ticket
size gate. This workspace is the product profile: one set, any amount.

## What is live vs what is not

| Piece | Status |
| --- | --- |
| Plugin ABI `Verify(family, vk, statement, proof)` | Live (TypeScript; this is a **pre-release**) |
| `hash-lab-v0` backend | Live. Merkle notes **off-chain**; covenant is a **lab-gated conservation cell**. **Not private.** |
| `circle-fri-m31` backend | Live AIR + residual-quotient Circle FRI. `plugin.verify` needs no private witness. Worksheet **128 conjectural bits**. |
| CashToken 128-byte `PAA1` state + 5-point successor | Live. Lock binds instance id, noteRoot (equal or append), nfRoot. Rewritten `noteRoot` fails the 2026 VM. |
| Chipnet genesis / successor | `pool chipnet-covenant` / `pool chipnet-mix` when funded. Not an OP_RETURN digest. |
| Hidden amounts / confidential assets | Pedersen in the note leaf. PAA1 NFT reserve bytes are 0. Pool UTXO **sats** stay public. |
| On-chain FRI prefix | Pool lock + **10** Merkle kernels + bind-T + **6** `C=Q·Z` slots in the 100 KB spend (all **36** in the 1 MB consensus spend). Unlocking **and** redeem ≤ **10 KB**. **Not** full fold / ZK. |
| OPTN builtin register | **Not done.** Zero-touch: addon talks to `http://127.0.0.1:17432` if `pool serve` is running. |

## Why the lock binds the NFT cell

A covenant that lets anyone rewrite `noteRoot` is stealable. The executed 2026
redeem checks the new 128-byte PAA1 against the old cell (append or equal
noteRoot, nfRoot update). `plugin.verify` binds the nullifier to the opened
leaf preimage in the proof. Prove stays off-chain.

## Commands

```bash
cd workspaces/any-amount
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
- `circle-fri-m31` — M31 Circle FRI of the pool AIR. `sound` follows the worksheet (≥100 bits).
