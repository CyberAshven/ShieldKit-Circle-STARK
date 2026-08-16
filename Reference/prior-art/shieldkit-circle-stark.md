# Prior art: ShieldKit-Circle-STARK

## Remotes

- Upstream (joint): https://github.com/toorik2/ShieldKit-Circle-STARK
- Your fork: https://github.com/CyberAshven/ShieldKit-Circle-STARK
- Local: `repos/ShieldKit-Circle-STARK`
- Product: Any-amount Chipnet lab (`workspaces/any-amount/`)
- Personal git ref (legacy name, not the product): `@ABLalgorithm`
- Other branch: `@toorik2`
- Provenance: ShieldKit-LABS commit `c92e1f81176f6d196410e70564c50c2bdbd02cb9`

`git remote`: `origin` = your fork, `upstream` = toorik2.

## What the repo is

A **public collaboration mirror** of one research lane:

`research-lanes/bch-shielded-pool-design/`

It is not a product release. The Telegram source package under `sources/telegram-2026-07-29/` is intentionally absent. Validation that still binds to that private package will not pass on a clean clone.

## Frozen product (do not silently widen)

From `analysis/design-options.md` and the lane README:

- Profile: `fixed-ticket-serial-pool`
- Ticket: 0.1 BCH (10,000,000 sats)
- One user action, one proof, one standard transaction
- No private transfers, variable amounts, or user batching
- Proof family: **Circle-domain FRI**
- Stwo / Cairo / Goldilocks FRI / Groth16 / WHIR = comparators, not implementation bases
- 128-bit soundness target, 100-bit floor, ≤100,000-byte tx
- Desktop prove &lt; 60 s; first client is a local CLI; GUI / mobile / browser / required remote prover are out of scope (see `client-and-usage.md`)
- Pool relation (`PoolActionFv1`) is **backend-neutral**; Circle FRI is the selected family, not a baked-in Stwo circuit

This matches the STARK-agnostic pool rule at the *relation* layer, while picking Circle FRI as the first family so the lane has a kill-gate.

## What is actually implemented vs closed

Done / pinned:

- P0 semantic freeze (state, action, threat model, tx binding)
- P1 codecs, relation oracle, empty transaction shells
- P2 M31 base arithmetic on Libauth + BCHN + LeanBCH
- Field certificates for M89-d2, M61-d3, M31-d5, M31-d6 (irreducibility only)
- Lowering-arm IR and source-set bytecode *for field arithmetic kernels*, not for FRI

**Still closed** (lane README, 2026-08):

- Gate B1, Circle domain, DEEP, sampler, FRI, query implementation
- Attempt-001
- Any candidate tuple selection
- Prover

P1 shell result that matters: under 35-byte P2SH32 fixture locks, the **10 KB per-input cap** binds first; the 100 KB tx cap starts binding at **nine** persistent carriers. That is topology, not a Circle-FRI size estimate.

## State codec (Fv1)

`spec/pool-state-fv1.md` — exact 128-byte mutable-NFT commitment:

| Offset | Field |
| ---: | --- |
| 0 | `PAF1` magic |
| 4 | version = 1 |
| 6 | reserved 0 |
| 8 | sequence u64 |
| 16 | deposit count u64 |
| 24 | withdrawal count u64 |
| 32 | pool instance id 32 B |
| 64 | note root 32 B |
| 96 | nullifier root 32 B |

Deposit changes only the note root. Withdrawal changes only the nullifier root. Reserve = outstanding tickets × ticket value, stored as the state UTXO's sats.

Compare with the Chipnet diagram (`confidential-state-cell.md`): that demo used a 4×32 CEv1 carrier (control, lineage, state, recovery). Fv1 collapsed to a single 128-byte native commitment. Same *size class*, different layout.

## How to work here

```text
cd repos/ShieldKit-Circle-STARK
git checkout @ABLalgorithm
# after npm ci (needs Node >= 20.10)
npm run lab:test
```

Push the personal ref or `origin`. Do not merge `main` without toorik.

The lane style is extremely conservative (content-addressed seals, "this is not evidence" banners). When adding Circle FRI research, match that: pin sources, do not promote a microbench into a complete-tx claim.
