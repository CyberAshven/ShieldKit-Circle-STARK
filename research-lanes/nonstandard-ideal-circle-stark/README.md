# Research lane: nonstandard ideal Circle STARK

**Work only here.** Constitution: [`RULES.md`](RULES.md). Named end: [`GOAL.md`](GOAL.md). Goal prompt: [`PROMPT.md`](PROMPT.md). Argument/vk: [`ARGUMENT.md`](ARGUMENT.md). Next construction: [`NEXT.md`](NEXT.md).

**Start:** occupancy FRI10 / QM31 124-bit ([`START.md`](START.md), pack `survey/artifacts/qm31-fri10/`, Chipnet `60d186de…`). Live lock is that skeleton. Leftover SHA-LDE is not wired.

Sibling `ideal-bch-shielded-pool-stark` is the 100 KB / Electrum squeeze. This lane’s product is the same cryptographic object **without** policy 100 KB.

vk changes if any RULES line changes. There is **no vk yet**.

## What this is

A Chipnet lab for one consensus May-2026 transaction that is B under RULES: Circle FRI, QM31 SecureField, SHA-256 note-auth AIR in the lock, shielded unlocking, walk-in batch. Land path is lab BCHN JSON-RPC. Public Electrum will not relay it.

| | Role |
|---|---|
| **B** | this object: one consensus tx ≤ 1 MB, full completeness, field+query+SZ+hash ≥ 100, SHA AIR in the lock, shielded unlocking, walk-in batch |
| **A** | weaker lock (RULES §8) |
| **C** | fund-safe hops ≤ 100 KB; not a substitute for B |
| sibling ideal | 100 KB / Electrum box; leftover SHA-LDE; not this product |

Consensus still binds unlocking/redeem at **10 000 B** each and op-cost at `800 × (41 + unlocking)`. Dropping 100 KB does not drop those. It lets the SHA AIR sit on **extra inputs** (~95 kB extra, ~194 kB with occupancy) instead of leftover shards.

**Occupancy B is ~147 KB** (Chipnet `62c1d6b9…` / 146168 B), not FRI9 498 KB. Commands: [`WORKFLOW.md`](WORKFLOW.md).

## Run

```bash
cd research-lanes/nonstandard-ideal-circle-stark
npm ci
npx tsc --noEmit
npm test
```

Chipnet only. Never mainnet. Tx > 100000 B → JSON-RPC `sendrawtransaction`, not Electrum.

## Outside this lane (do not edit for this track)

| Path | Use |
|---|---|
| `research-lanes/ideal-bch-shielded-pool-stark` | sibling 100 KB squeeze |
| `research-lanes/envelope-b-standard` | 91 KB freeze evidence |
| `research-lanes/batch-exit-walkin` | generic-step / walk-in prior for RULES §7 |
| `workspaces/any-amount` | frozen ABL snapshot |
| `research-lanes/bch-shielded-pool-design` | sealed Fv1 |
