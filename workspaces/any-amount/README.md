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
| Chipnet genesis / successor | `pool chipnet-covenant` / `pool chipnet-mix` when funded. Consensus-size lands use JSON-RPC `sendrawtransaction`, not Electrum/P2P. Not an OP_RETURN digest. |
| Hidden amounts / confidential assets | Tagged SHA-256 note-amount commit (AIR-bound). Public net is committed in `encodeStatement`. Published proof one-time-pads rho/owner/amount (viewing key not in the encoding). Unlocking is packed AIR + redeem only. Pool UTXO **sats** stay public (`STATE_BASE`). Pedersen is a comparison plugin only. |
| On-chain Circle FRI prefix | Pool lock + **10** Merkle kernels + bind-T + fold + `C=Q·Z`. Standard: **1** fold + **6** slots, **98979 B** compile (≤ 100 KB). Consensus: **36** folds + **36** slots, **383031 B**. Chipnet lands `2acb1196…` / `b1415faf…` are the pre-mask lock. Prior 10-fold land `18c74b49…` is not that land. Unlocking **and** redeem ≤ **10 KB**. Published note preimage is one-time-padded. FRI openings are offset (not raw Q). |
| OPTN builtin register | **Not done.** Zero-touch: addon talks to `http://127.0.0.1:17432` if `pool serve` is running. |

## Why the lock binds the NFT cell

A covenant that lets anyone rewrite `noteRoot` is stealable. The executed 2026
redeem checks the new 128-byte PAA1 against the old cell (append or equal
noteRoot, nfRoot update). `plugin.verify` binds the nullifier to the opened
leaf preimage in the proof. Prove stays off-chain.

## Latest

Opening-mask compile (standard **and** consensus): packed Q / FRI openings are `Q+c`; slot redeem subtracts `c` from offset 812. Same 100 KB path as the 6-slot Electrum land — new compiles use the new redeem hash. Historical Chipnet txids stay in [`MILESTONE.md`](MILESTONE.md).

## Commands (navigator)

```bash
cd workspaces/any-amount
npm ci
npm test
npx tsx src/cli.ts --help
npx tsx src/cli.ts status
npx tsx src/cli.ts wallet new          # .local/lab-wallet.json
npx tsx src/cli.ts wallet show
npx tsx src/cli.ts faucet
npx tsx src/cli.ts balance
npx tsx src/cli.ts pool create
npx tsx src/cli.ts pool deposit --sats 12000
npx tsx src/cli.ts pool withdraw --sats 5000
npx tsx src/cli.ts pool measure-tx     # must stay ≤100000 / ≤1000000
npx tsx src/cli.ts lab e2e
npx tsx src/cli.ts lab demo --wallets 2
npx tsx src/cli.ts bench
npx tsx src/cli.ts serve               # 127.0.0.1:17432 OPTN stub
# funded Chipnet only:
npx tsx src/cli.ts pool chipnet-covenant
npx tsx src/cli.ts pool chipnet-mix
```

Chipnet fold txs and the JSON-RPC land path: [`MILESTONE.md`](MILESTONE.md), [`STATUS.md`](STATUS.md).  
Next four increments: [`ROADMAP.md`](ROADMAP.md).

Wallet files stay under `.local/` (gitignored). Never pass a seed on the command line.

## Plugins

- `hash-lab-v0` — SHA-256 note commitments + incremental Merkle. Lab only.
- `circle-fri-m31` — M31 Circle FRI of the pool AIR. `sound` follows the worksheet (≥100 bits).
