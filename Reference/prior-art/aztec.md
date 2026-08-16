# Prior art: Aztec Network

Learn the **note / nullifier / client-prove** split. Do not copy their prover or their L2.

Primary:

- https://docs.aztec.network/developers/docs/foundational-topics/state_management
- https://docs.aztec.network/developers/docs/foundational-topics/pxe
- https://docs.aztec.network/developers/docs/foundational-topics/transactions
- https://aztec.network/blog/aztecs-transaction-anatomy/
- https://aztec.network/blog/the-best-of-both-worlds-how-aztec-blends-private-and-public-state
- https://github.com/AztecProtocol/aztec-nr (named in the Bastian chat)
- https://github.com/AztecProtocol/awesome-aztec

## What to steal

1. **Notes are UTXOs.** On-chain store is a *commitment* (note hash tree), not the note. Spend = prove preimage + emit a nullifier. Update = nullify old + insert new. This is already our Plane A / `PoolStateFv1` story.
2. **Nullifiers must be unlinkable** without the owner’s key. The tree proves “this nullifier is new,” not “this note was spent.”
3. **Client-side prove (PXE).** Private inputs never leave the wallet. The network sees a proof + new commitments + nullifiers. ShieldKit Fv1 already wants unilateral desktop prove. Aztec’s 2.5 s private transfer on a laptop (their Alpha V5 claim) is the UX bar, not a BCH measurement.
4. **Public vs private paths.** Aztec runs private functions locally and public functions on the sequencer. BCH has no sequencer. The analogue is: private witness stays in the wallet; public state is the CashToken continuation UTXO.
5. **Delivery of notes.** On-chain encrypted logs vs off-chain handoff vs self-notes. Maps to our Plane B (ML-KEM packets) vs out-of-band.
6. **Siloing.** They mix contract address into note hashes so two apps cannot collide. Our analogue is `pool instance ID` in the 128-byte state.
7. **Transient notes.** Created and nullified in the same tx are squashed. Useful later if we ever do change-notes; Fv1 has no transfers.

## What not to steal

- Noir / ACIR / kernel circuit / rollup-to-Ethereum. That is *their* ZKP plugin plus an L2.
- Account abstraction and Fee Juice. Different chain.
- Poseidon2 as a mandatory design-section hash. Their `#[note]` default is Poseidon2. Ours is SHA-256 unless a plugin implements something else in script.

## Standing warning (2026-08)

Aztec disclosed an Alpha **V5 proving-system vulnerability** (found 2026-07-27): a crafted proof could pass verification for a transaction the rules should reject, and historical chain data cannot tell honest accepts from forged ones.

That is the same class of failure as “FRI folded to a constant, false statement verifies.” Hygiene:

- prove a false statement from scratch
- pin vk/params
- prefer an AIR/relation that can be machine-checked (see arXiv 2606.04311 for S-two)

Aztec is a teacher for **design-section privacy**, and a cautionary tale for **ZKP-section soundness**.

How **Aztec the L2** is built (rollup, kernel, IMT, tagging): [aztec-scalability.md](aztec-scalability.md).  
How **our shielded pool** scales (races, 100 KB, one set): [shielded-pool-scalability.md](shielded-pool-scalability.md). Those are different documents.
