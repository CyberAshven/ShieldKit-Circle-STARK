# Envelopes A / B / C

Chipnet only. Unlocking + redeem ≤ 10 KB. FRI9 Chipnet txids are not relabeled.

Size is not the product identity. Three scenarios, same pool:

| Envelope | Relay | What it is | What it may leave open |
| --- | --- | --- | --- |
| **A** | One **standard** tx ≤ 100 KB, Electrum | Occupancy packing from Optimization: FRI10, QM31 after fold, 18 inputs, 6 fused folds × 6 queries, leftover L0–L6 pair-bind. Work surface: [`research-lanes/sha-in-occupancy-c`](../../research-lanes/sha-in-occupancy-c/). Parent 91 KB freeze: [`research-lanes/envelope-b-standard`](../../research-lanes/envelope-b-standard/). | **Incomplete is allowed.** Miner SHA-in-C is not forced (lock N is leftover vanish `<0>`). Occupancy Chipnet `60d186de…` still publishes note-auth amount/rho/owner. Named RULES §6 (silent unlocking + leaf‖nf‖amount in occupancy C) is still the lane job. |
| **B** | One **consensus** tx ≤ 1 MB, JSON-RPC | The completeness spend. Pays for every numbered check even if the tx is large: 36 unique-orbit folds + 36 R-slots (FRI9 land `81bb2cef…` / 498398 B), grind, algebraicC, note-auth, bind-T. Later: miner-forced SHA-in-C, silent unlocking, batch extra notes on-chain. | Size. Public Electrum will not relay > 100 KB. |
| **C** | **Many** standard txs, each ≤ 100 KB, Electrum | Same completeness as **B**, chunked. Counted-tip tape bind. Not 36 **same-tx** binds. | Binding vs B (tape vs one evaluation). |

CLI `--envelope a|b|c` in this workspace is still the FRI9 4-slot / 36-slot / chained compilers until occupancy is wired here. Run occupancy A from the lane:

```bash
cd research-lanes/sha-in-occupancy-c
npm ci
npx tsc --noEmit
```

Do not drop q / grind / TRACE to make A look finished. Do not add 36 SHA-AIR inputs (~94788 B extra). Do not put amount/rho/owner back in the unlocking to “fix” SHA.
