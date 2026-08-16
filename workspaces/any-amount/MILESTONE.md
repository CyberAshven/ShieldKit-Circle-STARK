# Chipnet milestones

**Network:** BCH Chipnet only. Not mainnet.  
**Unlockings / redeem:** ≤ 10 KB (Velma).  
This file **accumulates**. Old txids stay. New rows are added; they do not replace earlier lands.

Two fold-executing successors are on Chipnet. An earlier 36-slot spend
without fold stays recorded so it is not relabeled.

## Log (newest first)

| When | What | Commit / tx |
| --- | --- | --- |
| 2026-08-17 | Opening-mask lock landed: standard **98979 B** `617b1022…` + consensus **36-fold 383031 B** `b3ea8a75…` (JSON-RPC mempool; existing miner). | this land |
| 2026-08-16 | FRI openings + packed Q offset by degree-0 mask; slot lock subtracts packed felt (standard **and** consensus compiles). Newton T still public. | `95c2311` |
| 2026-08-16 | Consensus **36-fold** Chipnet land (382203 B) via JSON-RPC | `b1415faf…` @ height 319402 |
| 2026-08-16 | Published preimage OTP (rho/owner/amount); viewing key not in encoding | `9d2c41a` |
| 2026-08-16 | Production hash/PQ amount commit; public net committed | `f6653da` |
| 2026-08-16 | On-chain seq+1 and PAA1 reserve field = 0; no rho/owner in successor | `4414ff3` |
| 2026-08-16 | Consensus lock compiles 36 folds | `ade9999` |
| 2026-08-16 | 10-fold consensus Chipnet land | `18c74b49…` @ 319278 |
| 2026-08-16 | Standard 1-fold + 6 C=QZ Electrum land | `2acb1196…` |
| 2026-08-16 | 36-slot **no-fold** size proof | `356630bd…` |

## Current: opening-mask lock (2026-08-17)

Same redeem as `95c2311`: packed Q / openings are `Q+c`; slot lock subtracts `c`.
JSON-RPC `sendrawtransaction` into lab BCHN (`acceptnonstdtxn=1`). Existing pool miner; no new miner started.

### Standard (≤ 100 KB)

| | |
| --- | --- |
| Successor | `617b102276fb79122bdd7ca36f902ad65e753845fddb168c0bb1aeb97bbb2ccc` |
| Size | 98979 bytes |
| On-chain | 10 Merkle + bind-T + **1** fold + **6** `C=Q·Z` + opening mask |
| Prep | `2173d8134a04418f257e0c906fa0e57c4ecc67a0e58ab7db369293d597056fe5` |
| Genesis | `b63cfe0bfb8aea598bf94e8b8691c0c178c1535f978a10b28c200603a05f87be` |
| Kernels | `3e49bb52810ebd378b9c07b92392b9871cbb9d45fd81f246d6e1f8b93e8b66ca` |

Explorer: `https://chipnet.imaginary.cash/tx/617b102276fb79122bdd7ca36f902ad65e753845fddb168c0bb1aeb97bbb2ccc`

### Consensus 36-fold (≤ 1 MB)

| | |
| --- | --- |
| Successor | `b3ea8a75db4badfa1690bd9d8e98ce08565b360ddf8098e5ffade053adf643a3` |
| Size | 383031 bytes |
| On-chain | 10 Merkle + bind-T + **36** folds + **36** `C=Q·Z` + opening mask |
| Prep | `b12cda84574e2fe427c745a83e518a3c084b11276c818184a7527943e55f8b9c` |
| Genesis | `d5113df28bd3c0ab6fa48e34df8521a32366743c628157d8be86ebe55e97b762` |
| Kernels | `7962f2cffa2d48d036c9d17461aba6ad28fe8bcf2bebb209f0dbe41784423bb7` |

Explorer: `https://chipnet.imaginary.cash/tx/b3ea8a75db4badfa1690bd9d8e98ce08565b360ddf8098e5ffade053adf643a3`

## Prior: fold-executing lands (pre-opening-mask lock)

The shipped lock **requires** `fold-kernel.ts`. Density allows **1** folded
query per redeem. Standard pins **1** fold input. Consensus pins **36** (one
1-query kernel per FRI query). `algebraicC` / auth / grind stay in `verifyFri`.

### Standard (≤ 100 KB, public Electrum) — pre-mask

| | |
| --- | --- |
| Successor | `2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0` |
| Size | 98831 bytes |
| On-chain | 10 Merkle + bind-T + **1** fold + **6** `C=Q·Z` |
| Genesis | `c014f5aeef34774b3bdf17a1defb015a3c125239ff65d41b5874f1e5e1bba777` |
| Kernels | `5aef6160ef229e5a300e1d3e632544c9c1fe05290ce82c196a26fb5abdfbe5e4` |

Explorer: `https://chipnet.imaginary.cash/tx/2acb1196589b32fb1179f57dafc402dcb747f2698f364633d90dec180ab446e0`

### Consensus 36-fold (≤ 1 MB, JSON-RPC) — pre-mask

Public Electrum and P2P `inv` reject `tx-size` above 100000 even with
`acceptnonstdtxn=1`. Shipped land path: compile locally, then HTTP
`sendrawtransaction` (`src/chain/broadcast-tx.ts`).

| | |
| --- | --- |
| Successor | `b1415fafdc65e76d106956064667f94bc988a38da69e63c06acef1e8a1b9cb29` |
| Size | 382203 bytes |
| On-chain | 10 Merkle + bind-T + **36** folds + **36** `C=Q·Z` |
| Prep | `ea53c0e26a1cf3800199713c01ff5005c8c2e286df69f9234519a2517d1211ac` |
| Genesis | `169df22d347cfa7d7e2fb42152b83a764a4126a7b04ac05de078575ea4e86714` |
| Kernels | `7ea959b2d976b400f29640c7a218ee4c69c16c40b7ad81fa5d5ca80cbbd9296a` |
| Block | `0000000000000e4df903b409aee4e31f33210fb13ee75afe6d77691ddfd6c421` |
| Height | 319402 |

Explorer: `https://chipnet.imaginary.cash/tx/b1415fafdc65e76d106956064667f94bc988a38da69e63c06acef1e8a1b9cb29`

### Prior: 10-fold consensus land

| | |
| --- | --- |
| Successor | `18c74b49731c1914425ba10804233bb208c524e5af943c8bafc55751b007f3e6` |
| Size | 301279 bytes (59 inputs) |
| On-chain | 10 Merkle + bind-T + **10** folds + **36** `C=Q·Z` |
| Genesis | `2469f87208114473733aee0e02d163901318e760fc8b6973c4cc76b1d475bfab` |
| Kernels | `ef334c4a8d7309cc898031c61a476d9d9b39a3c9e8b99fd79df1c15f077502f0` |
| Block | `0000000026955667a7e7468d40043e66e0d8890bc21f7162a5d8595d02aaceca` |
| Height | 319278 |

`18c74b49…` stays the 10-fold land. Do not relabel it as 36-fold.

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
- Consensus **36** 1-query fold kernels on Chipnet (`b1415faf…`, 382203 B).

## What they do **not** prove

- A theorem that FRI openings hide the statement (degree-0 offset is recoverable from packed Newton T).
- A theorem that the whole STARK is statistically ZK. Published note preimage is one-time-padded; FRI openings stay on public `onChainCells`.
- Hidden pool-UTXO value (output is `STATE_BASE`). Note amounts are tagged SHA-256 commits; the public net is committed in `encodeStatement`.
- Zcash / Monero / Voidify parity.

Earlier standard 6-slot spends without the current fold lock:
`b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f`
and `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1`.
