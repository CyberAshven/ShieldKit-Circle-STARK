# Lane: ideal BCH shielded-pool STARK

**Work only here.** Parent freeze in `research-lanes/envelope-b-standard` is evidence. Walk-in generic-step prior in `research-lanes/batch-exit-walkin` is construction notes for RULES §7, not this product.

## Named end (only the human declares done)

One Chipnet Electrum transaction that is **B** under [`RULES.md`](RULES.md): one standard May-2026 tx, soundness min(FRI-query, field, SZ, hash-RO) ≥ 100, miner runs every numbered check, Circle FRI + SHA-256, on-chain money relation, shielded unlocking (no rho/owner/amount preimage), walk-in batch exit with N on-chain walks, encoding ≡ spec.

That object does not exist yet. Occupancy `60d186de…` / 99043 B, hashLeaves pin `1c41bbb1…` / 98863 B, XOR-PRF `f320b606…` / 99575 B, and vector-hash Electrum `d6fb88e1…` / 98583 B are evidence. Live construction: SHA witness opened at the 36 occupancy queries (32-leaf tree, bundle 32, depth 5, randomizer deg 1130 so TRACE does not interpolate); miner compact-merkle walks vs grind-bound `hashBitRoot` and prefix-checks vs unlocking A/L/N. Same walk in JS. Fold leftover-sources pairs; unlocking 1200 B is a SHA-LDE shard. TRACE w / HASH_MSG / viewing-commit XOR of the preimage are not in unlocking. Mixed `proveFromTLde` + matching pin + matching hashLeaves + copied honest or junk hashBit cargo must JS-fail and VM-reject on the relation. Occupancy FRI is still algebraicC, not the 576-column SHA AIR (that extra is 193162 B). Unique-table oversize: retry `proveFri`, do not pad. Do not say shielded. RULES §7 still open.

## Why a new lane

- Parent freeze fits §1’s box and a query worksheet of 128, **on M31**. RULES §2 forbids claiming 100 bits while the field is ~31.
- Parent note-auth / baked step kernels publish amount/rho/owner. RULES §6: anonymity set 1 is not shielded.
- Baked Option B paints `(rIn, rOut, prevNf)` at genesis. RULES §7: walk-in deposits then one N-note exit.
- Envelope A and C hops are types. RULES §8: they are not B.

## vk

No vk string until a construction satisfies every RULES line. Then the vk **includes** the SHA-256 of `RULES.md`. Editing RULES is a new family.

Parent freeze vk `circle-fri-m31-t64-b16-q36-g20-fri9` stays that freeze’s name. Do not reuse it here.

## Out of scope as product (controls stay in-tree)

- Envelope A
- Envelope C as a substitute for one standard B tx
- Relabeling the 91 KB freeze, ABL’s 12-note A `ce421f05…`, or walk-in Chipnet `e63ccf03…` as this named end
