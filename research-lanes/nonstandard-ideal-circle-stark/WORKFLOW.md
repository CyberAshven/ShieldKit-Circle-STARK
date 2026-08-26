# Occupancy Chipnet workflow (FRI11)

This lane is the occupancy compiler. **B is ~147 KB**, not FRI9’s 498 KB.

Chipnet only. Never mainnet. Unlocking/redeem ≤ 10 KB.

## Envelopes

| Envelope | What | Size class | Land (2026-08-26) |
| --- | --- | ---: | --- |
| **A** | 36 unique-orbit fused folds, standard Electrum. Omits B booleanity + note-auth. | ≤ 100000 B (~98 KB) | [0ce65254…](https://bchexplorer.cash/chipnet/tx/0ce652547723ce7a94efd343694e64745e4e5f169d1770cdc1953bbaa299ec41) 97632 B |
| **B** | Occupancy completeness: 36q + 3 booleanity kernels + note-auth. JSON-RPC (not Electrum). | ≤ 1000000 B (**~147 KB**) | [62c1d6b9…](https://bchexplorer.cash/chipnet/tx/62c1d6b956f2bf431a56622c0c2b96180bb1a5d80c9488920807f2af3a2f6541) **146168 B** |
| **C** | Same completeness as B, 19 standard hops, counted-tip + cqz nfRoot/instance bind. | each hop (20000, 100000] | pay [cbfe3e19…](https://bchexplorer.cash/chipnet/tx/cbfe3e19720e92a92cfab00a641a25ee6c5a333e0fd776fe37630f48fd20e19c) 92011 B |

FRI9 2026-08-21 (`614b7077…` / `81bb2cef…` 498398 B / `06a6078a…`) is a **different** vk. Do not relabel.

## Commands (this directory)

```bash
cd research-lanes/nonstandard-ideal-circle-stark
# Chipnet wallet is .local/lab-wallet.json (gitignored). wallet import is a hidden prompt.

npx tsx src/cli.ts wallet show
npx tsx src/cli.ts balance

# Occupancy 36q compile (A ~98 KB, B ~147 KB, C hops 73–92 KB)
npx tsx src/cli.ts pool measure-tx --envelope a
npx tsx src/cli.ts pool measure-tx --envelope b
npx tsx src/cli.ts pool measure-tx --envelope c

# Broadcast. A and C: Electrum. B: Start9 BCHN JSON-RPC (acceptnonstdtxn).
npx tsx src/cli.ts pool land --envelope a
npx tsx src/cli.ts pool land --envelope b
npx tsx src/cli.ts pool land --envelope c
npx tsx src/cli.ts pool land --envelope all
```

`workspaces/any-amount` CLI is still FRI9 4-slot until that freeze is lifted. Occupancy `--envelope a|b|c` is **this** binary.

## Tests

```bash
npx tsx --test --test-timeout 180000 test/envelope-gating.test.ts
npx tsx --test --test-timeout 180000 --test-name-pattern "3-note batch verifies" test/envelope-batch.test.ts
npx tsx --test test/onchain-privacy.test.ts test/note-auth-step-kernel.test.ts
```

Explorer: Melroy `https://bchexplorer.cash/chipnet/tx/<txid>` and Paytaca `https://chipnet.bchexplorer.info/tx/<txid>`. B > 100 KB will 404 on public Electrum until the lab miner includes it.
