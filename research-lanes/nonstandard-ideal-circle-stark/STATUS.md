# Status (this lane)

**Constitution:** [`RULES.md`](RULES.md). **No vk yet.** See [`ARGUMENT.md`](ARGUMENT.md) and [`GOAL.md`](GOAL.md).

Copied 2026-08-25. **Starting artifact:** occupancy FRI10 / QM31 124-bit (`008dd6b`, pack `survey/artifacts/qm31-fri10/`, Chipnet `60d186de…` / 99043 B). That start still published the preimage. Not B under this RULES.md.

**Live construction:** occupancy 18-input fused fold+R, leftover pair-bind, silent unlocking. AmountCommit SHA-256 **96-col bit-AIR** is a 256-leaf LDE (depth 8). 32 full merkle paths live in grind (unlocking 8635). Six fold kernels carry T shards (2048 B, unlocking 9683–9712, VM-accept). Note-auth rebuilds `A[0:4]‖L[0:4]‖N[0:4]‖T` and path-walks hashBitRoot (EQUALVERIFY, unlocking 5198, redeem 4001, ~80% op headroom). Occupancy FRI is unchanged (Q_pub + mask, q=36). Round-function next-row gates stay JS `assertHashTraceConstraints`. 36 extra hash-AIR inputs are not in the lock.

**Last Chipnet JSON-RPC:** successor `c8de3f2b…` / 123861 B (bit-AIR paths, silent unlocking, mempool-included). Start occupancy `60d186de…` stays the start artifact. Only the human declares done.

**Land path:** lab BCHN JSON-RPC. `createVirtualMachineBch2026(false)`. Tx ≤ 1_000_000 B. Unlocking/redeem ≤ 10_000 B.
