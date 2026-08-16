# Design invariants

These are the design claims we keep. They were argued in 2025–2026 while CashVM was still catching up. **Layla (2026-05-15) made the script side real** (loops, functions, P2S, 128-byte commitments, 10 KB unlocking aligned with consensus). The *architecture* did not get less true.

Cited against public sources.

## Split that stays

1. **Delivery ≠ conservation ≠ state.** Stealth / ML-KEM packets hide *who*. A proof hides or binds *amounts and membership*. A CashToken continuation UTXO is the public state machine. Quantumroot protects *keys*. None of those four jobs is the others.
   - Quantumroot (public): https://blog.bitjson.com/quantumroot/ — PQ vault, not a mixer.
   - ML-KEM-768: NIST general-purpose KEM; size study arXiv 2508.01694.
2. **The pool is ZKP-agnostic.** `Verify(family, vk, statement, proof)`. Circle FRI is plugin #1. Groth16 / Goldilocks FRI / later WHIR are other plugins. See `literature/notes/zkp-agnostic-architecture.md`.
3. **Shared global anonymity set, UTXO-shaped state.** One deployment = one note/nullifier set. Shared state is the continuation UTXO + roots, not an account. Wallet-local pools are not the default. See `prior-art/shared-vs-global-state.md`.
4. **Name the proof family.** ZK is a property. Groth16, PLONK, FRI-AIR, “proof-bound spend” are different objects.
5. **Hash STARKs need no new opcode.** Pairing SNARKs and Pedersen+Bulletproofs want EC ops that are still a CHIP, not Layla. TXv5 is still a *proposal* (https://github.com/bitjson/bch-txv5), not an excuse to wait.

## Envelopes that still bind (post-Layla)

| Limit | Status after Layla | Source |
| --- | --- | --- |
| Standard tx ≤ **100,000** bytes | Still the working product envelope (0zkbrewer + ShieldKit Fv1) | `repos/BCH-FRI-STARK-Verifier` README; ShieldKit `phase-plan.md` |
| Per-input unlocking ≤ **10,000** bytes | P2S CHIP aligned standardness with this consensus cap | https://github.com/bitjson/bch-p2s ; Block blog Layla post |
| Token commitment **128** bytes | Live (was 40) | P2S / Layla |
| `OP_BEGIN` / `OP_UNTIL`, `OP_DEFINE` / `OP_INVOKE` | Live | Layla Functions + Loops CHIPs |

So: we can write looping Merkle/FRI *programs* now. We still **cannot** stuff a whole sound proof into one input. Shard the witness. Demo-size ≠ sound-size (Goldilocks sound wiring already measured **120 KB**).

## What Layla changed vs what it did not

Changed: CashScript/CashVM can express loops and functions, so much of the 2026-06 hand-CashAssembly tax is gone. 128-byte state (`PoolStateFv1`) fits a native NFT commitment.

Did not change:

- 100 KB / 10 KB envelopes
- No pairing precompile
- No live native ECADD/ECMUL (Pedersen/Bulletproofs **emulatable** in script, usually too big; CHIP 2025-05 would make them cheap)
- TXv5 not activated — no free input de-duplication
- A covenant that checks a hash is still not a STARK
- Client-side prove; relayer is not a custodian
- CashFusion / Nostr are discovery, pre-mix, or the event bus (Solana listener analogue). Not the state machine. Relays never custody.

## Public prior art to keep cross-checking

| Topic | Public URL |
| --- | --- |
| Layla / CashVM | https://bch.info/en/upgrade |
| P2S + 128 B commitment | https://github.com/bitjson/bch-p2s |
| Quantumroot | https://blog.bitjson.com/quantumroot/ https://github.com/bitjson/quantumroot |
| TXv5 (not live) | https://github.com/bitjson/bch-txv5 |
| EC opcode CHIP | https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570 |
| Groth16 on BCH | https://github.com/mr-zwets/groth16_cashscript https://www.verifier.cash/ |
| Confidential txs writeup | https://github.com/bastiancarmy/bitcoin-cash-confidential-transactions |
| Proof-bound P2S | https://github.com/bastiancarmy/bitcoin-cash-proof-bound-p2s |
| SRPA / stealth | https://bitcoincashresearch.org/t/silent-reusable-payment-addresses-srpa/1637 |
| CashTokens KB | https://github.com/toorik2/BCH_Knowledge_Base |
| Block education | https://github.com/FullStack-Agents/block-blog |
| Circle STARKs | ePrint 2024/278 |
| ethSTARK | ePrint 2021/582 |
