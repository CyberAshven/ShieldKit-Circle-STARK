# Global pool vs shared state vs shards

Short answer: **you want a global anonymity set and shared public roots. You do not want Ethereum-style global mutable account state. You do not want wallet-local friend pools as the default.**

Three words people mash together:

| Phrase | Meaning | Needed? |
| --- | --- | --- |
| **Global pool** | One protocol instance; every user of that instance hides in the **same** note/nullifier set | **Yes** — this is the product |
| **Shared state** | On-chain commitment everyone proves against (`noteRoot` + `nullRoot` + reserve) | **Yes** — otherwise there is no set |
| **Global account state** | One Solidity/Solana account everyone writes | **No** — BCH has UTXOs |
| **Local / wallet-owned pool** | Each wallet or friend group has its own tiny set | Allowed as a *forked instance*, dead as the default (tiny anonymity set) |
| **State shards** | Several covenant UTXOs updated in parallel | **Later**, only if one serial UTXO contends; must not split the anonymity set |
| **Verifier shards** | Several inputs in *one* tx that check one proof | **Yes as needed** — 10 KB cap; not user batching |

Proofnote/APNT is a public **no-pool** design (ordinary UTXOs as backing cells, no global private-value UTXO). That is a different product. It does not falsify the pool choice here. See `prior-art/proofnote.md`.

## Ideal design (what the old talk already had)

1. Wallet is a frontend. The pool lives on BCH as a covenant. No validators, no sequencer.
2. Everyone using **this deployment** (same token category / `pool instance ID`) shares one note set and one nullifier set. That is the anonymity set. CashFusion still needs “enough players this round.” A global pool does not.
3. Shared state on chain is **small**: roots + counts + reserve in one 128-byte CashToken commitment. The trees live off-chain and are reconstructed from public inserts. Same idea as Tornado/Aztec/Voidify, but the carrier is a UTXO, not an account map.
4. One action spends the current state outpoint and creates the sole successor. Two txs race; one wins; loser rebuilds and retries. That *is* shared state under UTXO rules. ShieldKit Fv1 already froze this as `fixed-ticket-serial-pool`.
5. Anyone can deploy **another** instance (new category). That is a different pool with its own set — like a second Tornado contract. Useful for experiments. Not a substitute for the main instance.

## What Fv1 already decided

From ShieldKit `analysis/design-options.md`:

- One continuation UTXO holds reserve **and** the 128-byte state
- One user action per transaction
- No coordinator
- Verifier may be split across inputs; that is not state sharding

So Fv1 **already has shared global state** in the only UTXO-legal form: a single serial state cell. You do not need a second “global state” layer on top.

## When shards are OK

Cardano-style eUTXO contention is real: if many people try to spend the same state UTXO every block, most retry. Then you may split **execution** across several UTXOs that share:

- the same covenant
- the same `pool instance ID`
- **one** logical note/nullifier accumulator (the proof names the unified roots)

If each shard has its **own** note root, you have several local pools wearing a trench coat. That kills the point.

Do not shard Fv1 until a measured mempool shows the serial cell is the bottleneck. 100 KB / 10 KB will bite first. Full pool-scale list: `shielded-pool-scalability.md`.

## What not to mix in

- **Plane B / stealth / Nostr** — delivery and discovery, not the set
- **CashFusion** — optional pre-mix of the *funding* UTXO; still not the set
- **Voidify DAO / treasury / oracle** — extra shared *policy* state; not required for a mixer
- **Aztec public data tree** — they have public *and* private trees because they are a general L2. We only need note + nullifier roots plus reserve sats

## Decision for this repo

| Layer | Choice |
| --- | --- |
| Anonymity set | **Global per deployment** |
| On-chain shared state | **One serial continuation UTXO** (`PoolStateFv1`) |
| Extra instances | Allowed, smaller sets, not the default UX |
| Physical state shards | Closed until contention is measured |
| Proof plugin | Independent of all of the above |

Local pools were the “wallet L2 / mix with friends” idea. Keep them as a possible second profile if someone wants a private covenant. The ideal confidential-asset design is the **shared global set** enforced by one immutable covenant.
