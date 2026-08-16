# Chipnet milestones

**Network:** BCH Chipnet only. Not mainnet.  
**Unlockings / redeem:** ≤ 10 KB (Velma).

Two fold-executing successors are on Chipnet. An earlier 36-slot spend
without fold stays recorded so it is not relabeled.

## Current: fold-executing lands

The shipped lock **requires** `fold-kernel.ts`. Density allows **1** folded
query per redeem. Standard pins **1** fold input. Consensus pins **36** (one
1-query kernel per FRI query). `algebraicC` / auth / grind stay in `verifyFri`.

### Standard (≤ 100 KB, public Electrum)

| | |
| --- | --- |
| Successor | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |
| Size | 98831 bytes |
| On-chain | 10 Merkle + bind-T + **1** fold + **6** `C=Q·Z` |
| Genesis | `c014f5aeef34774b3bdf17a1defb015a3c125239ff65d41b5874f1e5e1bba777` |
| Kernels | `5aef6160ef229e5a300e1d3e632544c9c1fe05290ce82c196a26fb5abdfbe5e4` |

Explorer: `https://chipnet.imaginary.cash/tx/2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0`

### Consensus (≤ 1 MB, JSON-RPC + local mine)

Public Electrum and P2P `inv` reject `tx-size` above 100000 even with
`acceptnonstdtxn=1`. Shipped land path: compile locally, then HTTP
`sendrawtransaction` (`src/chain/broadcast-tx.ts`).

| | |
| --- | --- |
| Successor | `18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6` |
| Size | 301279 bytes (59 inputs) |
| On-chain | 10 Merkle + bind-T + **10** folds + **36** `C=Q·Z` |
| Genesis | `2469f87208114473733aee0e02d163901318e760fc8b6973c4cc76b1d475bfab` |
| Kernels | `ef334c4a8d7309cc898031c61a476d9d9b39a3c9e8b99fd79df1c15f077502f0` |
| Block | `0000000026955667a7e7468d40043e66e0d8890bc21f7162a5d8595d02aaceca` |
| Height | 319278 |

Explorer: `https://chipnet.imaginary.cash/tx/18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6`

`18c74b49…` is 36 C=QZ + **10** shard folds. The lock now compiles **36** fold
kernels (measured **382203 B**). A new Chipnet 36-fold land is recorded below
when JSON-RPC + mine succeed; until then do not treat `18c74b49…` as 36-fold.

## Earlier: 36-slot no-fold proof

Agreed size/envelope proof (no fold kernel on that lock):

| | |
| --- | --- |
| Successor | `356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898` |
| Size | 270251 bytes |
| On-chain | 10 Merkle + bind-T + **36** `C=Q·Z` (no fold) |
| Genesis | `006186da1d496abace49e1f1d8712c3c18d9bf522910aa8fb60b553be374cab5` |
| Kernels | `7a4e685d3bbfc39eb59f0f29ab11e05135eb76111e1c58a4f84ee2d13e32b8ba` |
| Block | `000000001abbed79d00f1d2d3e47c16a62114c40da6f559b6d24b438703636b7` |

Explorer: `https://chipnet.imaginary.cash/tx/356630bd10c6bf9b3d4bbd6d1835ed3baed430641f168c2ad1e1f534a3080898`

Do **not** relabel `356630bd…` as fold.

## What these txs prove

- CashTokens genesis from vout-0, P2SH32 five-point `PAA1`.
- Velma 10 KB unlocking + redeem (old ~1650 box is gone).
- Successor unlocking is packed AIR + redeem only (no spent rho/owner).
- Fold-executing standard spend relayed by public Electrum.
- Fold-executing consensus spend included by a Chipnet miner after JSON-RPC.

## What they do **not** prove

- On-chain fold of all 36 FRI queries.
- Statistical ZK / witness masking.
- Hidden pool-UTXO value (output is `STATE_BASE`; note amounts are Pedersen).
- Zcash / Monero / Voidify parity.

Earlier standard 6-slot spends without the current fold lock:
`b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f`
and `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1`.
