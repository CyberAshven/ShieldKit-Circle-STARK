# Cardano eUTXO — why shards exist (and why they are not a local pool)

Public: https://docs.cardano.org/about-cardano/learn/eutxo-explainer  
Also cited on BCR 1724: sharding leans into UTXO parallelism. Quantumroot makes the same point for BCH.

## The contention fact

In eUTXO / BCH, **one UTXO can be spent by only one transaction per block**. If the whole pool is one state cell, every deposit and withdraw races on that outpoint. Losers rebuild and retry. Cardano apps hit this on DEX/order-book UTXOs. Hydra (L2 heads) and “many UTXOs” are their throughput answers — they do **not** automatically share one anonymity set.

A shard selector (hash of category + outpoint + receiver → shard index) is a **contention** tool. Shards are fine **if** the ZKP still names a **unified** Merkle/accumulator. Per-shard note roots = several tiny pools.

## What we take

- Parallelism is a UTXO feature; use it when the serial cell is the bottleneck
- Deterministic shard index, no coordinator
- Do not confuse “many UTXOs” with “many anonymity sets”

## What we do not take

- Hydra as a privacy design
- Cardano Plutus as a verifier
- Sharding Fv1 before measuring mempool races

See `shared-vs-global-state.md`.
