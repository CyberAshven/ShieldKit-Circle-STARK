# Aztec Network (the L2) — how *that* system is built

This file is **Aztec**, a privacy smart-contract L2 on Ethereum. It is **not** the scalability design of our BCH shielded pool. Pool throughput, races, and tree growth live in `shielded-pool-scalability.md`.

Official overview: https://docs.aztec.network/developers/docs/foundational-topics

Steal note/nullifier *ideas* and (later) compact non-membership. Do **not** treat their sequencer/rollup as our scale plan.

## How Aztec is put together

```text
wallet / aztec.js
    → PXE (client): run private functions, hold keys/notes, prove
    → node: Public VM (AVM) runs public functions
    → sequencer: order txs, build block
    → rollup circuit: one proof that many kernel proofs + tree updates are valid
    → Ethereum: verify the rollup proof, store roots
```

Private runs first on the device. Public cannot call private. PXE and AVM do not see each other.

**Kernel circuit** (protocol, not the app): folds one user’s private call stack into one proof + note hashes + nullifiers. **Rollup circuit**: batches many kernels. That is *their* answer to “how do 10,000 private txs fit on L1.”

They need that stack because they settle many private *contract* calls on Ethereum. Our pool is one covenant action per BCH transaction. Different product.

## Trees (this is the useful Aztec bit)

| Tree | Shape | Job |
| --- | --- | --- |
| Note hash | Append-only Merkle | Commitments to private UTXOs |
| Nullifier | **Indexed Merkle tree** (depth ~32) | Non-membership + insert |
| Public data | Ordinary sparse/public | Account-like public state |

Indexed Merkle Tree (https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree, paper ePrint **2021/1263**):

- Sparse tree indexed by the nullifier value would be **depth ~254** → ~500 hashes per insert. Too fat for circuits.
- Indexed tree: leaf = `{value, next_index, next_value}` (sorted linked list). Non-membership = show the “low” leaf that straddles the new value. **Depth 32**. ~8× cheaper inserts. Supports **subtree / batch** inserts in the rollup.
- Node must keep a sorted view to find the low leaf (more storage, fewer circuit hashes).

**For BCH Fv1:** we only store **roots** on chain. The wallet/prover must still *do* non-membership. If the nullifier set is a sparse SHA-256 tree, proofs get tall. An **indexed** (or other compact) nullifier accumulator is the right later upgrade for proof size — same reason Aztec invented it. Do not implement it before Circle FRI exists. Pin the algorithm in `PoolConfigFv1` so we can change it in a new profile.

Note tree stays append-only. That matches us.

## How they find notes (scalability of *wallets*, not consensus)

https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery

- Brute-force trial-decrypt of every log: dies as the set grows.
- Off-chain handoff: needs a side channel.
- **Default: note tagging.** Log = `[tag, …]`, `tag = poseidon2(shared_secret, index)`, then kernel-siloed by contract. Recipient queries `getPrivateLogsByTags`. Sliding window so you do not scan all indexes.
- Handshake (non-interactive = on-chain ephemeral; interactive = recipient signs, nothing on-chain).
- Node still sees **which tags you ask for** + IP. OMR/PIR would fix that; they say it is not production-cheap yet.

**For us:** Plane B (fixed 12× ML-KEM packets on the same tx) is *one-shot delivery*, not a growing global log. Recipients do not scan the chain for tags. That is simpler and more UTXO-native. If we ever do Aztec-style *transfers* (notes created for third parties without a packet plane), we will need tagging or an out-of-band channel. Fv1 has no transfers.

Keys Aztec splits: nullifier key, incoming viewing, outgoing viewing. We can stay simpler (one spend secret + ML-KEM) until transfers exist.

## What “scale” means on Aztec vs BCH

| Problem | Aztec answer | BCH answer (this repo) |
| --- | --- | --- |
| Prove without leaking witness | PXE on laptop (~2.5 s V5 claim) | Same: desktop CLI &lt; 60 s target |
| Many private txs / block | Sequencer + rollup circuit | One L1 tx per action; BCH block is already huge |
| Nullifier non-membership cost | Indexed Merkle, batch insert | Roots only on chain; IMT later if FRI bytes blow up |
| One hot state cell | They have a global tree updated in the rollup (no UTXO race) | Serial continuation UTXO; **shards later** if mempool races |
| Note discovery at millions of logs | Tagging + handshake | Plane B packets; no global log |
| Public + private in one app | AVM + PXE | We only need public roots + private notes |
| L1 verify cost | One pairing/Honk-style rollup proof on ETH | Whole Circle FRI verifier in the BCH tx (100 KB) |

Their hybrid zk-rollup exists because **Ethereum is expensive and sequential**. BCH is cheap and parallel **except** for the one state outpoint. So our only real scale research left is:

1. **State contention** — already in `shared-vs-global-state.md` / `cardano-eutxo.md`
2. **Proof bytes / op-cost** — Circle FRI measurement (ShieldKit P2/P3)
3. **Nullifier accumulator** — IMT vs sparse vs other, after (2)
4. **Verifier input sharding** — 10 KB cap, not user batching

We do **not** need a sequencer, kernel/rollup circuit pair, or AVM to “be like Aztec.”

## What we still do *not* have locally

- Full Aztec protocol circuit repo (huge; not cloned)
- Noir / Honk internals
- Measured IMT vs SHA-256-sparse proof sizes **on BCH**

Those wait until Fv1 Circle FRI is specified. Official index: https://docs.aztec.network/llms.txt
