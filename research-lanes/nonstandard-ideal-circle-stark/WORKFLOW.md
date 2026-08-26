# Occupancy Chipnet workflow (FRI11)

This lane is the occupancy compiler. **B is ~147 KB**, not FRI9’s 498 KB.

Chipnet only. Never mainnet. Unlocking/redeem ≤ 10 KB.

## Envelopes

| Envelope | What | Size class | Land (2026-08-27) |
| --- | --- | ---: | --- |
| **A** | 36 unique-orbit fused folds, standard Electrum. Omits B booleanity + note-auth. | ≤ 100000 B (~98 KB) | [ab367c76…](https://bchexplorer.cash/chipnet/tx/ab367c767fc2e7b7f97c9f9bb0dc957edc81800c53b3db4bbc5eff4f74fcd973) 98112 B |
| **B** | Occupancy completeness: 36q + 3 booleanity kernels + note-auth. JSON-RPC (not Electrum). | ≤ 1000000 B (**~147 KB**) | [3a99aeaf…](https://bchexplorer.cash/chipnet/tx/3a99aeaf48e59b3482ab163b544377337715f92056ef5d5294e6d7c5d58c9572) **147110 B** |
| **C** | Same completeness as B, 19 standard hops, counted-tip + cqz nfRoot/instance bind. | each hop (20000, 100000] | pay [8b7bdbad…](https://bchexplorer.cash/chipnet/tx/8b7bdbadc45bc3ca40cfcce4b909f250df9960c532da38aace7655542c527570) 92326 B |
| **B** N=3 | Silent step kernels (leaf/nf/amountCommit). Compact CAT+SHA pin. JSON-RPC. | **~141 KB** | [58030256…](https://bchexplorer.cash/chipnet/tx/58030256a1d3b5c817da50044f8a3fa4a8c42aea4642bc8a274356d4b47decf8) 144273 B |

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

# Occupancy B, N silent step kernels (JSON-RPC). Dry-run first: a failed live run can leave genesis on chain.
npx tsx scripts/chipnet-land-batch.ts 3 .local/chipnet-batch --dry
npx tsx scripts/chipnet-land-batch.ts 3 .local/chipnet-batch
```

`workspaces/any-amount` CLI is still FRI9 4-slot until that freeze is lifted. Occupancy `--envelope a|b|c` is **this** binary.

## Tests

```bash
npx tsx --test --test-timeout 180000 test/envelope-gating.test.ts
npx tsx --test --test-timeout 180000 --test-name-pattern "3-note batch verifies" test/envelope-batch.test.ts
npx tsx --test test/onchain-privacy.test.ts test/note-auth-step-kernel.test.ts
```

Explorer: Melroy `https://bchexplorer.cash/chipnet/tx/<txid>` and Paytaca `https://chipnet.bchexplorer.info/tx/<txid>`. B > 100 KB will 404 on public Electrum until the lab miner includes it.
