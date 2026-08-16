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

## What this tx does **not** prove

- On-chain Circle FRI **fold** of layers (that kernel is in this tree; a new
  land is required before claiming fold-on-Chipnet).
- Statistical ZK / witness masking.
- Hidden pool-UTXO value (output is `STATE_BASE`; note amounts are Pedersen
  commitments only).
- Zcash / Monero / Voidify parity.

Standard 100 KB path (6 slots) already landed earlier:
`b6069db772455de4b247bbd50e1dea14244900e7517739157a1a9d53deeb9a7f`
and `a408709c8fca1eca942548437ea9cdee054aa909215705a2c83842e54b7679d1`.
