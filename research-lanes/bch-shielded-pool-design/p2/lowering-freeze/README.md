# Direct arithmetic lowering freeze v1

This directory is an additive, pre-execution contract for the four schedule-freeze direct fields and their 14 ordered arms. It binds the four v2 descriptor files, the current schedule bytes/schema, and the 14 descriptor-derived arm digests. It also enumerates 42 relation targets (14 arms × three relations).

The contract freezes the direct-power-basis wire/codec rule, the exact parser micro-template (including `OP_1 OP_1 OP_XOR`), stack ABI and relation-specific push order, typed IR vocabulary, normalization/range-ledger policy, scalar lowering policy (`OP_DIV` forbidden), and no-CSE/no-dead-node DAG policy. Tower coordinates are schedule-internal only and never wire or codec coordinates.

This is not evidence and does not claim executable lowering, bytecode, cost, VM limits, selection, or protocol suitability. Execution remains closed. Source implementation is authorized only to produce later content-addressed source/bytecode artifacts; campaign execution and metrics remain closed. Every source slot, metric, and downstream v2 binding is therefore explicitly pending/null here. The bound v1 campaign/run schemas are legacy context only and cannot satisfy a v2 execution gate. A failure can affect only the exact construction+codec+algorithm+track; it can never eliminate an entire `(p,d)` family.

Provenance binds BCHN commit `864c53ee34924cca6c6b6d96607ff2cedcdccf02`, `src/script/script.h`, and its pinned SHA-256. `OP_1=0x51` through `OP_16=0x60` support dedicated small-integer constants. `K=16` is design rationale only, not a measured-cost or lower-bound claim.

Run `node generate.mjs --write` only when intentionally refreshing the frozen bytes, then `node generate.mjs`, `node validate.mjs`, and `node --test lowering-freeze.test.mjs`. The final files use UTF-8 canonical JSON with one LF.
