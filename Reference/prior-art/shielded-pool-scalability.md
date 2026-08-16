# Shielded / confidential *pool* scalability

This is **not** Aztec. Aztec is an L2 with a sequencer and a rollup (`aztec.md`, `aztec-scalability.md`). This file is the **mixer / confidential pool** we are building on BCH: one covenant, one anonymity set, deposits and withdraws.

Pool scale = how many **actions per block**, how large the **set** can grow, how fat the **proof/tx** gets, how wallets **sync**. Different problem from “how does an L2 batch 10k private smart-contract calls onto Ethereum.”

## The bottlenecks (ours)

| Bottleneck | What hurts | Fv1 stance |
| --- | --- | --- |
| **State contention** | One continuation UTXO → one spend per block (or a race) | Accept races + retry. Physical shards **later**, same `poolId` + **one** logical accumulator |
| **Tx / proof bytes** | Standard 100 KB, 10 KB per input | Circle FRI must fit; shard the *verifier*, not the users |
| **Op-cost / loops** | FRI queries × field ops in CashVM | Measure in P2/P3; do not guess from Aztec gas |
| **Anonymity set vs throughput** | Global set wants everyone in one tree; one tree wants one writer | Do not split the set to go faster |
| **Tree growth** | Note tree append-only; nullifier set grows forever | Roots only on chain; wallet rebuilds from public inserts. Lifetime cap `C` in Fv1 |
| **Non-membership cost** | Proving “this nullifier is new” gets expensive in a sparse tree | Later: compact accumulator (IMT is *one* candidate, from a paper Aztec also uses — still a pool primitive, not an L2) |
| **Prover time** | Desktop &lt; 60 s for one withdraw | Local prove; no required remote prover |
| **Wallet restore / sync** | Must rebuild trees + find notes | Public inserts + Plane B packets; no full-chain trial-decrypt |
| **Relayer / broadcast** | Not a scale primitive | Optional; cannot be the throughput plan |
| **Amount-hiding extras** | Range proofs (BP or STARK) add bytes | Fv1 tickets are public; hide amounts in a later profile |

## What other *pools* do (not L2s)

| System | How the pool itself scales | Lesson |
| --- | --- | --- |
| Tornado Classic | One contract, one tree per denomination, nullifier **map** | Map is O(1) on ETH; we cannot have a map. Per-denom trees **split** the set |
| Voidify Classic | Same, depth 20, PDA per nullifier | Account-model scale |
| Voidify Nova | One tree per token, depth **26**, 100-root history, rolling note | Flexible amounts; still one writer (the Solana program) |
| Zcash | Consensus value pools + frontier trees | Global set is consensus; we cannot add a consensus pool |
| ShieldKit Fv1 | One serial UTXO, roots in 128 B, ticket `T`, lifetime `C` | Honest UTXO pool: **throughput = ~1 action / block / instance** until we shard writers |

A Solana/ETH pool “scales” because **one program** updates a tree every slot/block with no UTXO race. We do not get that for free. That is the whole Cardano/BCH point (`cardano-eutxo.md`).

## Scale levers we are allowed

1. **Bigger blocks / cheap fees** — BCH already; not a protocol change.
2. **Verifier input split** — many P2SH32 inputs, one action. Needed for 10 KB. Does not raise actions/block.
3. **Shorter proofs** — Circle FRI params, later WHIR only if measured.
4. **Cheaper nullifier proofs** — better accumulator, same global set.
5. **Many writer UTXOs, one set** — only if the proof binds a unified root; otherwise you made local pools.
6. **Many deployments** — extra instances, **smaller** sets. Not a scale-up of *this* pool.
7. **Aggregation later** — batch many users in one proof. BCR/bitjson treat this as an optional market, not the base path. Fv1 is one user, one tx.

Do not use: sequencer, rollup-to-L1, “just be Aztec.”

## Fv1 number to remember

Until shards or aggregation exist, **capacity ≈ 1 pool action per block per instance** (plus whatever races lose). At 10-minute blocks that is fine for a first shielded ticket pool. It is **not** an L2 TPS claim. When it hurts, open the shard-writer design — do not open a second anonymity set.

## Related (different files)

- *What* the pool is: `utxo-native-pool.md`, `shared-vs-global-state.md`
- *Aztec the L2*: `aztec.md`, `aztec-scalability.md`
- *Proof size family*: `zkp-family-map.md`
