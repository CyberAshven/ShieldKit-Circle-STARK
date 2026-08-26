# Research lane: SHA in occupancy C

**Work only here.** Constitution: [`RULES.md`](RULES.md). Named end: [`GOAL.md`](GOAL.md). Argument/vk: [`ARGUMENT.md`](ARGUMENT.md). Start: [`START.md`](START.md).

Sibling HASH_BIT host in `research-lanes/ideal-bch-shielded-pool-stark` (Chipnet `5de68272…`, 99144 B) is **evidence**. It is not this product. vk changes if any RULES line changes. There is **no vk yet**.

## What this is

A Chipnet lab copied from the occupancy + HASH_BIT host so the SHA-in-occupancy-C construction has a tree to live in. The 1 MB SHA-AIR fork is a sibling box, not this one. This object is one standard tx, full completeness, field+query+SZ+hash ≥ 100, SHA residuals in occupancy C, silent unlocking.

## Run

```bash
cd research-lanes/sha-in-occupancy-c
npm ci
npx tsc --noEmit
```

Chipnet only. Never mainnet.

## Outside this lane (do not edit for this track)

| Path | Use |
|---|---|
| `research-lanes/ideal-bch-shielded-pool-stark` | HASH_BIT leftover walks; `5de68272…` evidence |
| `research-lanes/nonstandard-ideal-circle-stark` | 1 MB SHA AIR on own inputs |
| `research-lanes/envelope-b-standard` | 91 KB freeze evidence |
| `research-lanes/batch-exit-walkin` | do not edit for this track |
| `workspaces/any-amount` | frozen ABL snapshot |
| `research-lanes/bch-shielded-pool-design` | sealed Fv1 |
