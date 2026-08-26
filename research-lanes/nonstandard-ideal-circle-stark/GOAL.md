# Lane: nonstandard ideal Circle STARK

**Work only here.** Sibling 100 KB / Electrum squeeze lives in `research-lanes/ideal-bch-shielded-pool-stark` (commit `a598b1f`, then the depth-6 SHA-LDE revert). Parent freeze in `research-lanes/envelope-b-standard` is evidence. Walk-in generic-step prior in `research-lanes/batch-exit-walkin` is construction notes for RULES §7, not this product.

## Named end (only the human declares done)

One Chipnet-mined transaction that is **B** under [`RULES.md`](RULES.md): one consensus May-2026 tx ≤ 1_000_000 B, unlocking/redeem ≤ 10_000 B, `createVirtualMachineBch2026(false)`, lab BCHN includes it; soundness min(FRI-query, field, SZ, hash-RO) ≥ 100; miner runs every numbered check; Circle FRI + SHA-256; on-chain money relation; leaf↔nf↔amount in the lock; unlocking silent (no rho/owner/amount); encoding ≡ spec. Walk-in batch is later.

That object does not exist yet. Do not say shielded until §6 holds in script.

The scientific question is in [`PROMPT.md`](PROMPT.md): the most elegant, BCH-native organisation of the occupancy verifier so the money relation is miner-run and the unlocking is silent — without a second unmanageable machine, and without a tx that is large because the argument was not. Inner beauty, in places no one will screenshot. A wall is a number, then the next construction. Only the human declares done.

## Starting artifact

[`START.md`](START.md) / [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/). Frozen at `008dd6b`. FRI **10**, QM31 **124-bit** field, min ≥ 100. Chipnet `60d186de…` / 99043 B. That start published amount/rho/owner. Live lock keeps the occupancy skeleton, silent unlocking, leftover pair-bind, and miner-run SHA-LDE compact walks in note-auth with all 36 prefixes EQUALVERIFYd. Not a default dump of 36 extra inputs. Not the named end.

## Why this lane exists

The sibling was trying to put leaf↔nf↔amount in the on-chain STARK **inside the policy 100 KB / 10 KB / Electrum box**. The 576-column SHA AIR extra is **94788 B** (36 inputs × (41 + 576×4 + 9×32)); occupancy + AIR ≈ **194 kB**. That is a 100 KB miss and a 1 MB fit. Bundle-32 leftover SHA-LDE made density worse; depth-6 leftover walks were tens of ops over a 10 KB unlocking. Those are walls on the sibling’s box.

This lane drops policy 100 KB and Electrum. It keeps consensus 1 MB and the 10 KB script bound (that bound is consensus). The product is the Circle STARK the sibling wanted, without the leftover squeeze.

## Evidence (not this product)

| Object | What it is |
|---|---|
| Occupancy `60d186de…` / 99043 B | **starting artifact** (FRI10, 124-bit). Not the named end. |
| hashLeaves `1c41bbb1…` / 98863 B | pin, not the AIR |
| XOR-PRF `f320b606…` / 99575 B | pin |
| vector-hash `d6fb88e1…` / 98583 B | SHA256 of a 128-leaf vector |
| `a598b1f` SHA-LDE leftover | 36 occupancy-query compact-merkle walks in fold leftover; 100 KB construction |
| Depth-6 / bundle 16 | sibling revert after bundle 32 made value-SPLITS worse |
| 36-input SHA AIR extra 94788 B | a measured option, not the default aesthetic |

## vk

No vk string until a construction satisfies every RULES line. Then the vk **includes** the SHA-256 of `RULES.md`. Editing RULES is a new family.

Sibling occupancy vk and parent freeze vk `circle-fri-m31-t64-b16-q36-g20-fri9` stay those objects’ names. Do not reuse them here.

## Out of scope as product (controls stay in-tree)

- Envelope A
- Envelope C as a substitute for one consensus B tx
- Relabeling the 91 KB freeze, the sibling 100 KB occupancy, ABL’s 12-note A, or walk-in Chipnet as this named end
- Fitting 100 KB / Electrum (that is the sibling lane)
