# Prior art: Stwo / S-two, SP1, Triton VM

These are **prover stacks**, not pool designs. They belong in the ZKP section as comparators.

## S-two / Stwo (Starknet)

- Blog: https://www.starknet.io/blog/s-two-is-live-on-starknet-mainnet-the-fastest-prover-for-a-more-private-future/
- Code: https://github.com/starkware-libs/stwo
- AIR soundness (Lean 4): https://arxiv.org/abs/2606.04311 — Avigad, Ganor, Goldberg, Levit, Nir, Seginer, Titelman, 2026-06-03
- PDF: `Reference/literature/papers/2606-04311-stwo-air-lean.pdf`

S-two proves Cairo programs with **Circle STARK**. The paper verifies that the AIR encoding of Cairo is sound: if the AIR is satisfied, the computational claim holds. It does **not** verify Circle FRI itself.

Use:

- Circle FRI engineering (domain, folding) as prior art
- “Formally check the AIR, not just the PCS” as a future gate
- Do **not** inherit Cairo, L2 recursion, or Starknet’s hash/builtins as our pool identity

ShieldKit already says Stwo is prior art, not protocol authority.

## SP1 (Succinct)

- https://github.com/succinctlabs/sp1
- RISC-V zkVM; prove ordinary Rust. Prover powered by **Plonky3**. Audited (Veridise, Cantina, Zellic, KALOS).
Typical production path on Ethereum: prove in SP1, **wrap the STARK into Groth16/PLONK** so the L1 verifier is a pairing check. That wrap is exactly the “ugly recursive SNARK” ABL objected to — and it reintroduces a trusted setup.

On BCH, verifying SP1 *natively* means a Plonky3/FRI verifier in script (same size war as Goldilocks FRI). Verifying the wrap means Groth16 in script. Neither is Circle FRI + SHA-256.

Keep SP1 as: “how people write statements in Rust and then pick a *different* on-chain verifier.” Our statement should stay a small AIR (`PoolActionFv1`), not a general RISC-V trace.

## Triton VM (Neptune)

- https://github.com/TritonVM/triton-vm
- Spec: https://triton-vm.org/spec/
- VM + AET/AIR + recursive STARK verifier *inside the same ISA*
- Native hash is **Tip5** (STARK-friendly), not SHA-256
- Public size reports for Triton proofs are large relative to the 100 KB BCH envelope

### Why Triton is a bad fit if we stay on SHA-256

1. On-chain we want SHA-256 Merkle because CashVM already has SHA-256 and 0zkbrewer/ABL already paid that cost.
2. Triton’s FRI/Merkle layer is Tip5. A BCH Triton-verifier would reimplement Tip5 + their FRI, not reuse SHA-256.
3. Proving SHA-256 *inside* Triton (to bind to BCH state) is a large AIR — the classic “SHA-256 is hostile inside ZK” tax that Poseidon was invented to avoid.
4. Recursion is Triton’s selling point. We do not have a recursive verifier opcode, and recursion does not shrink the *first* on-chain proof unless we wrap (back to SNARKs).

So: Triton can live as an optional off-chain experiment or a future plugin. It is **not** the SHA-256 Circle-FRI backend.

## Neptune Cash

- https://neptune.cash/
- Privacy UTXO chain whose proving stack is in the Triton family

Steal: UTXO notes + STARK integrity as a *chain* design. Do not treat Neptune as a BCH covenant template. Their proof sizes are not our 100 KB envelope.
