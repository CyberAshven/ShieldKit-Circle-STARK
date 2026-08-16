# Prior art: Tornado Cash (and why Neptune is listed next to it)

## Tornado Cash Classic

- Docs: https://docs.tornado.ws/general/how-does-it-work.html
- https://github.com/tornadocash/docs
- Bastian/ABL used this as the **anonymity-set** reference, not as something to paste onto BCH.

Mechanism (same as Voidify Classic):

```text
deposit:  commitment = H(secret, nullifier) → Merkle leaf
withdraw: π = “I know a leaf in the tree, unused nullifier, same denomination”
          public: nullifier hash, recipient, fee
```

What we keep:

- Membership + nullifier is the withdraw statement
- Anonymity set is the tree, not the mixer brand
- Fixed denomination is the conservative Fv1 profile (ShieldKit 0.1 BCH ticket)

What we reject:

- Operator / governance / tainted-set drama as part of consensus
- “Just deploy Tornado on BCH” — BCH has no pairing precompile; their Groth16 verifier is Ethereum-shaped
- Treating a mixer contract as the only privacy tool (CashFusion + stealth still matter around the pool)

Tornado’s SNARK is a ZKP plugin. The Merkle/nullifier story is design-section.

How to do this as **real UTXOs** on BCH (not an account map): [utxo-native-pool.md](utxo-native-pool.md).

## Neptune

Listed here only so the two “privacy chain” names do not get mixed:

- Tornado = application mixer on a public chain (Ethereum)
- Neptune = a whole L1 whose transactions are STARK-proven (Triton)

We are building a **BCH application** (covenant pool), so Tornado/Voidify/Aztec-notes are closer than Neptune-the-chain. Neptune/Triton stay in `stwo-sp1-triton.md`.
