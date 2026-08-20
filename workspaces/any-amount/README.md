# Any-amount Chipnet lab

**Does not edit** the sealed Fv1 lane
(`research-lanes/bch-shielded-pool-design/`). Fv1 stays the joint 0.1-ticket
size gate. This workspace is the product profile: one set, any amount.

## What is live vs what is not

| Piece | Status |
| --- | --- |
| Plugin ABI `Verify(family, vk, statement, proof)` | Live (TypeScript; this is a **pre-release**) |
| `hash-lab-v0` backend | Live off-chain + registry. Statement digest only. **Not private**, **not sound**. |
| `circle-fri-m31` backend | Live AIR + residual-quotient Circle FRI. `plugin.verify` needs no private witness. Worksheet **128 conjectural bits**. |
| CashToken 128-byte `PAA1` state + 5-point successor | Live. Lock binds instance id, noteRoot (equal or append), nfRoot. Rewritten `noteRoot` fails the 2026 VM. |
| Chipnet genesis / successor | `pool chipnet-covenant` / `pool chipnet-mix` when funded. Consensus-size lands use JSON-RPC `sendrawtransaction`, not Electrum/P2P. Not an OP_RETURN digest. |
| Hidden amounts / confidential assets | Tagged internal-hash note-amount commit (AIR-bound; default SHA-256, BLAKE2s alternate). Public net and reserve are hiding tagged hashes in `encodeStatement` (blind stays off the encoding; not Bulletproofs/Orchard). Published proof one-time-pads rho/owner/amount (viewing key not in the encoding). Unlocking is packed AIR + redeem only. Pool UTXO **sats** are public (`STATE_BASE` + reserve TVL). Pedersen is a comparison plugin only. Poseidon2 and Monolith are not shipped. |
| On-chain Circle FRI prefix | Pool lock + **10** Merkle kernels + bind-T + fold + `C=Q·Z`. Standard: **1** fold + **6** slots (≤ 100 KB). Consensus: **36** folds + **36** slots (≤ 1 MB). Plugin switch is **off-chain + registry**; redeem is still Circle fold/C=QZ. Historical Chipnet txids stay in [`MILESTONE.md`](MILESTONE.md). Unlocking **and** redeem ≤ **10 KB**. Internal hash is a drop-in knob (default SHA-256; BLAKE2s alternate). On-chain `OP_SHA256` is the SHA-256 backend of that default (not a second tree). Packed Newton T is not the AIR interpolant; packed N is N+cZ; slot lock is Q·Z=nTable. |
| OPTN builtin register | **Not done.** Zero-touch: addon talks to `http://127.0.0.1:17432` if `pool serve` is running. |

## Why the lock binds the NFT cell

A covenant that lets anyone rewrite `noteRoot` is stealable. The executed 2026
redeem checks the new 128-byte PAA1 against the old cell (append or equal
noteRoot, nfRoot update). `plugin.verify` binds the nullifier to the opened
leaf preimage in the proof. Prove stays off-chain.

## Latest

ZKP plugin hook is **off-chain + registry**. CLI deposit/withdraw call `zkpPluginByFamily` then `plugin.prove` / `plugin.verify`. Default family is **circle-fri-m31**; **hash-lab-v0** is a second plugin on the same statement (cross-family proofs reject; **not private**, **not sound**). On-chain redeem is still Circle fold/C=QZ. Internal hash is a drop-in knob (default **SHA-256**, alternate **BLAKE2s**). Poseidon2 and Monolith are not shipped; a later swap is a table entry + `digest()`, not a Merkle/FS/note rewrite. On-chain `OP_SHA256` is the SHA-256 backend of the default knob, not a second tree. AIR + Circle FRI stay (packed Newton T is not the interpolant). On-chain verifier is Merkle+fold+C=QZ (`OP_SHA256`). Openings use \(R_{\mathrm{on}}+Z R_{\mathrm{off}}\) (SHA-256; not a Lean HVZK theorem; lock does not evaluate \(R\)). Confidential bar is notes+OTP+unlinked fee+hiding net/reserve commits+paying UTXO; pool sats = `STATE_BASE`+reserve (public TVL, not Maxwell). CHIP 2025-05 / BCR 1570 is later-if-lands. One-set aggregated pool. Latest Chipnet lands: standard `23fd1b7d…` (**79525 B**) and consensus `9362df54…` (**283992 B**). Historical txids stay in [`MILESTONE.md`](MILESTONE.md). Not better-than-XMR or Zcash.

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
npx tsx src/cli.ts pool deposit --sats 12000   # optional --hash blake2s --plugin circle-fri-m31|hash-lab-v0
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

- `circle-fri-m31` — default ZKP plugin. M31 Circle FRI of the pool AIR. `sound` follows the worksheet (≥100 bits). Internal hash default SHA-256; BLAKE2s alternate. Poseidon2 and Monolith are not shipped. On-chain lock is this family's fold/C=QZ.
- `hash-lab-v0` — second registered plugin (off-chain). Statement digest only; **not private**, `sound: false`. Same note/nullifier/reserve statement. A Circle proof does not verify as hash-lab and vice versa.
