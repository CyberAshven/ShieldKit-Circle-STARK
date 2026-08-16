# Checkable comparison (not a cryptanalysis theorem)

Axes we can measure or cite. This is **not** a proof that Circle FRI is “more sound”
than XMR / Zcash / Aztec / Voidify / Tornado.

| Axis | This lab (any-amount) | Monero | Zcash | Aztec | Voidify | Tornado Cash |
| --- | --- | --- | --- | --- | --- | --- |
| Trusted setup | None (hash STARK / Circle FRI) | None (rings + BP) | Historic Groth16; Orchard Halo2 | Honk / Plonk-ish setup | Groth16 + ceremony | Groth16 + ceremony |
| On-chain verify | BCH 2026 VM: one packed AIR prefix + 10 depth-bound FRI kernels + bind-T + slot-0 C=QZ; digest / dummy / cross-statement fail. Full FRI fold remains in `verifyFri` (issue #2 lesson). | Consensus ring/BP | Consensus SNARK | L2 rollup circuits | Solana Groth16 verifier ELF | Ethereum Groth16 verifier |
| Any-amount | Yes (one set) | Yes | Yes | Yes | Nova-style amounts | Classic fixed tickets |
| Amount hiding | Pedersen in the note leaf; public PAA1 **zeros reserve**; pool UTXO is constant `STATE_BASE`. Public net is a separate P2PKH in/out, not the pool cell. | Yes (BP) | Yes | Yes | Yes | No (ticket size public) |
| Anon-set growth | Incremental Merkle (depth 16); mix successor updates noteRoot + nullifierRoot + reserve | Ring size (not a growing set) | Note commitment tree | Note tree | Pool tree | Pool tree per ticket |
| On-chain prover | No (off-chain prove, StarkWare split) | N/A | N/A | N/A | Off-chain | Off-chain |
| Conjectural FRI bits | 128 (`q=36`, `B=16`, grind 20, rate 2/B) | N/A | N/A | N/A | N/A | N/A |

## What we do **not** claim

- A theorem that those systems are less sound.
- Hidden individual note amounts on the UTXO (pool output is a constant `STATE_BASE`; reserve is not in the NFT). Deposit/withdraw still have a public P2PKH net.
- 128-bit collision resistance of the 4-limb algebraic mixer used inside the AIR (FRI bits are the worksheet; the note tree is still SHA-256 + Pedersen).
