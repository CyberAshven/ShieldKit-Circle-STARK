# Quantumroot (public)

- Blog: https://blog.bitjson.com/quantumroot/
- Code: https://github.com/bitjson/quantumroot
- OPTN flow (read-only): `D:\OPTNWallet-Desktop\docs\quantumroot-flow.md`

**Job: protect keys / authorize a spend shape after ECDSA is unsafe. Not mixing. Not note delivery.**

## Shape

From one seed:

1. **Receive address** — share this. Spend paths: Schnorr (today) or token-delegated post-quantum.
2. **Quantum Lock** — hidden auth UTXO. Spend paths: LM-OTS, or introspection to sweep/aggregate.

Post-quantum path: a CashToken **category** delegates authorization; LM-OTS signs the **expected transaction shape**, not each coin; token rotates to the next Quantum Lock.

Aggregation is a design goal (same receive address pre-quantum; token-spend + lock together post-quantum).

## For this pool

- Optional later wrap: payout / fee keys as Quantumroot.
- Fee input is still a **transparent** Chipnet coin in Fv1 / any-amount.
- Do not require Quantumroot to deposit or withdraw.
- Do not call the pool “post-quantum” while settlement signatures are Schnorr.

See `design-invariants.md` item 1.
