# Research lane: ideal BCH shielded-pool STARK

**Work only here.** Constitution: [`RULES.md`](RULES.md). Named end: [`GOAL.md`](GOAL.md). Argument/vk: [`ARGUMENT.md`](ARGUMENT.md).

Parent 91 KB freeze in `research-lanes/envelope-b-standard` (Chipnet `58b7df7f…`, 91598 B) is **evidence**. It is not this product. vk changes if any RULES line changes. There is **no vk yet**.

## What this is

A Chipnet lab copied from the freeze parent so constructions that could satisfy RULES §1–10 have a tree to live in. Envelope A and C stay as **controls**. They are not B.

| | Role |
|---|---|
| **B** | this object: one standard tx, full completeness, field+query+SZ+hash ≥ 100, shielded unlocking, walk-in batch |
| **A** | weaker lock (RULES §8) |
| **C** | fund-safe hops ≤ 100 KB; not a substitute for B |

## Run

```bash
cd research-lanes/ideal-bch-shielded-pool-stark
npm ci
npx tsc --noEmit
```

Chipnet only. Never mainnet.

## Outside this lane (do not edit for this track)

| Path | Use |
|---|---|
| `research-lanes/envelope-b-standard` | 91 KB freeze evidence |
| `research-lanes/batch-exit-walkin` | generic-step / walk-in prior for RULES §7 |
| `workspaces/any-amount` | frozen ABL snapshot |
| `research-lanes/bch-shielded-pool-design` | sealed Fv1 |
