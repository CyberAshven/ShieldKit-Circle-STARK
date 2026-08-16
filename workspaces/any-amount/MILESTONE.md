# Milestone: 36-slot Chipnet successor

**Date:** 2026-08-16  
**Envelope:** consensus (one tx ≤ 1 MB, unlockings ≤ 10 KB)  
**Network:** BCH Chipnet only. Not mainnet.

This is the agreed proof that a 36-slot `C=Q·Z` + Merkle + bind-T successor
can land on Chipnet when the lab BCHN has `acceptnonstdtxn=1` and a local
miner includes the tx. Public Electrum will not *relay* 270 KB.

## Proof transaction

| | |
| --- | --- |
| Successor txid | `356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898` |
| Size | 270251 bytes |
| On-chain checks | 10 FRI Merkle kernels + bind-T + **36** slot `C=Q·Z` |
| Genesis | `006186da1d496abace49e1f1d8712c3c18d9bf522910aa8fb60b553be374cab5` |
| Kernel fund | `7a4e685d3bbfc39eb59f0f29ab11e05135eb76111e1c58a4f84ee2d13e32b8ba` |
| Block (local BCHN 3+ conf) | `000000001abbed79d00f1d2d3e47c16a62114c40da6f559b6d24b438703636b7` |

Explorer: `https://chipnet.imaginary.cash/tx/356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898`

## What this tx proves

- CashTokens genesis from vout-0, P2SH32 five-point `PAA1`.
- Velma 10 KB unlocking + redeem (old ~1650 box is gone).
- Consensus-size verifier spend included by a Chipnet miner.

## Fold (this tree, not `356630bd…`)

The successor lock **requires** `fold-kernel.ts`. Isolated + VM tests accept
an honest fold and reject a flipped FS index. Density allows **1** folded query
per redeem. Standard pins **1** fold input. Consensus pins **10** (one first
query per FRI shard). `algebraicC` / auth / grind stay in `verifyFri`.

Fold-executing Chipnet land (standard 98831 B, Electrum-accepted):

| | |
| --- | --- |
| Successor | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |
| Genesis | `c014f5aeef34774b3bdf17a1defb015a3c125239ff65d41b5874f1e5e1bba777` |
| Kernels | `5aef6160ef229e5a300e1d3e632544c9c1fe05290ce82c196a26fb5abdfbe5e4` |

Do **not** relabel `356630bd…` as fold.

## What `356630bd…` does **not** prove

- On-chain Circle FRI **fold** of layers.
- Statistical ZK / witness masking.
- Hidden pool-UTXO value (output is `STATE_BASE`; note amounts are Pedersen
  commitments only).
- Zcash / Monero / Voidify parity.

Standard 100 KB path (6 slots) already landed earlier:
`b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f`
and `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1`.
