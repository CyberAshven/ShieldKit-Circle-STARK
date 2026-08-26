# Argument = vk (QM31 SecureField family)

```
vk = circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22
rulesSha256 = de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22
```

Pack: [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/). Occupancy Chipnet `60d186de…` (99043 B) is evidence, not this object.

§6 in flight (not the named end): SHA-LDE openings at the 36 occupancy queries, 32-leaf tree (bundle 32, depth 5, randomizer deg 1130 so TRACE does not interpolate). Fold leftover-sources pair shards; unlocking 1200 B is a SHA-LDE shard. Miner compact-merkle walks vs grind-bound `hashBitRoot` and prefix-checks vs unlocking A/L/N. Vector-hash Electrum `d6fb88e1…` / 98583 B (SHA256 of the 128-leaf vector + prefix leaf 0) is evidence, not this check. Mixed `proveFromTLde` + matching pin + matching hashLeaves + copied honest or junk hashBit cargo must JS-fail and VM-reject on the relation. Spec-aware viewing-commit XOR and TRACE-w unpack of unlockings must not recover the preimage. Occupancy FRI remains algebraicC; 36-input bit AIR extra still **193162 B**. Unique-table variance: retry `proveFri` until ≤100000. `f320b606…` / `1c41bbb1…` / `60d186de…` / `d6fb88e1…` are evidence. RULES §7 still open. Do not say shielded.

Occupancy: **B = M31** (circle, Merkle, qTable, layer-0 pairs, inverses, AIR cells). **F_fri = QM31** (7 λ, post-fold layers 1–6, final). **H = SHA-256**. qTable / layer-0 are 4-byte.

## Soundness worksheet

| knob | value | status |
|---|---|---|
| Field | QM31 \(\log_2 p^4 \approx 124\) | written |
| Query conjecture | \(36 \times 3 + 20 = 128\) at rate \(2/B\) | **speculative**, named; not Stwo-128 |
| SZ | TRACE 64 over QM31 | not tens of bits |
| Hash-RO | SHA-256 | |
| min | \(\min(128, 124, \ldots) \approx 124 \ge 100\) | floor |

n=32/q=8 is refused. d5 is not the fold alphabet.

## Parent freeze (evidence, different family)

`survey/artifacts/argument-freeze/`, vk `circle-fri-m31-t64-b16-q36-g20-fri9`, Chipnet `58b7df7f…` 91598 B. M31 challenges. Not this product.

## Checks the miner must run

Numbered lock checks of the 18-input fused fold+R skeleton plus QM31 λ mix and QM31 post-fold pairs. Merkle leftover-binds layers 0–6. Fold leftover-sources those pairs (unlocking 1200 B is a SHA-LDE shard). Note-auth compact-merkle walks the 36 occupancy-query SHA-LDE openings vs hashBitRoot and prefix-checks vs A/L/N. `verifyFri` is a lab oracle. Mutated λ or post-fold pair: JS-fail and VM-reject (P0). Mixed publics with matching hashLeaves and copied/junk hashBit cargo: JS-fail and VM-reject.

Stwo KATs: CM31 `(1+2i)(4+5i)=(p−6)+13i`; QM31 `(1,2,3,4)*(4,5,6,7)=(p−71,93,p−16,50)`; inverses.

Leftover is layer-major `[L6]…[L1][L0]` (7200 B). Merkle leftover-binds layers 0–6. Compact-path PICK bounded. No dummy pad / leftover-fill / packTo / KERNEL_UNLOCK_PAD. TRACE 64, q 36, grind 20, blowup 16.
