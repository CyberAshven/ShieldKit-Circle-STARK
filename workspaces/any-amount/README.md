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
| Hidden amounts / confidential assets | Tagged internal-hash note-amount commit (AIR-bound; default SHA-256). Public net is committed in `encodeStatement`. Published proof one-time-pads rho/owner/amount (viewing key not in the encoding). Unlocking is packed AIR + redeem only. Pool UTXO **sats** stay public (`STATE_BASE`). Pedersen is a comparison plugin only. |
| On-chain Circle FRI prefix | Pool lock + **10** Merkle kernels + bind-T + fold + `C=Q·Z`. Standard: **1** fold + **6** slots (≤ 100 KB). Consensus: **36** folds + **36** slots (≤ 1 MB). Historical Chipnet txids stay in [`MILESTONE.md`](MILESTONE.md). Unlocking **and** redeem ≤ **10 KB**. Internal hash is a selectable knob (default SHA-256; BLAKE2s alternate). Packed Newton T interpolates masked cells; the opening-mask felt is derived, not stored. |
| OPTN builtin register | **Not done.** Zero-touch: addon talks to `http://127.0.0.1:17432` if `pool serve` is running. |

## Why the lock binds the NFT cell

A covenant that lets anyone rewrite `noteRoot` is stealable. The executed 2026
redeem checks the new 128-byte PAA1 against the old cell (append or equal
noteRoot, nfRoot update). `plugin.verify` binds the nullifier to the opened
leaf preimage in the proof. Prove stays off-chain.

## Latest

Internal-hash knob + opening-mask packing: Merkle / Fiat–Shamir / note / nullifier / amount-net share one selectable hash (default **SHA-256**, alternate **BLAKE2s**). Packed Q is Q+c and packed N is N+cZ; packed Newton T is not the AIR interpolant. Slot lock is Q·Z=nTable. Standard Chipnet land `f14bff7b…` (**79436 B**, 1 fold, Electrum). Historical txids stay in [`MILESTONE.md`](MILESTONE.md).

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
npx tsx src/cli.ts pool deposit --sats 12000   # optional --hash blake2s
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
- `circle-fri-m31` — M31 Circle FRI of the pool AIR. `sound` follows the worksheet (≥100 bits). Internal hash default SHA-256; BLAKE2s is the off-chain alternate. Poseidon2 is not an option.
