# Ciphertext vs Circle STARK

Question: do Circle STARKs use **ciphertext**, or something closer to ciphertext than raw plaintext?

**Four different objects get called “hidden.”** The Circle STARK *protocol* is not an encryption scheme. The STARK *stack* uses arithmetization-oriented ciphers as hashes (Rescue, Poseidon). Starknet STRK20 (2026) stores official ciphertext notes and proves spends with Stwo. That is an application layer, not 2024/278.

Public sources: [ePrint 2024/278](https://eprint.iacr.org/2024/278), [2024/1037](https://eprint.iacr.org/2024/1037), [2021/582](https://eprint.iacr.org/2021/582), [2018/828](https://eprint.iacr.org/2018/828), [2019/426](https://eprint.iacr.org/2019/426), [2019/458](https://eprint.iacr.org/2019/458), [starkware-libs/starknet-privacy](https://github.com/starkware-libs/starknet-privacy), Vitalik [Exploring circle STARKs](https://vitalik.eth.limo/general/2024/07/23/circlestarks.html).

## 1. Circle STARK itself is not encryption

2024/278 is a domain / FFT / FRI construction (`x²+y²=1` over M31). No ciphertext primitive. It mentions Poseidon/Rescue only as possible future hash diffusion layers.

## 2. What STARKs do instead of encrypting the witness

Unopened FRI queries leak the witness. [2024/1037](https://eprint.iacr.org/2024/1037) wants **off-domain randomizers + a mask polynomial**, not AES. That is information-theoretic blinding of polynomial oracles.

This lab: tagged SHA-256 amount commit (PQ-family hash, not discrete-log Pedersen); OTP of published rho/owner/amount; degree-0 offset on FRI openings and packed Q; the slot lock subtracts the packed mask felt before `C=Q·Z`. Packed Newton T is still public, so the offset is recoverable. That is **weaker** than 2024/1037 HVZK. Do not write “ciphertext STARK” or “encrypted proof.”

## 3. STARK-friendly ciphers are usually hashes

Rescue (2019/426) is a cipher (plaintext + key → ciphertext). ethSTARK sets the key to zero and uses it as a sponge **hash**. Poseidon/Poseidon2 are the same pattern. We use SHA-256 on BCH 2026 VM (fits 10 KB). An AO hash is a later measurement, not a requirement for increment 4.

## 4. Applications on top of Circle STARKs may encrypt notes

STRK20 encrypts note amounts with a Poseidon PRF stream + modular add, then proves the transition with Stwo. Same split as this pool: encryption/commitment in the **design** section, Circle FRI in the **ZKP** section.

PQ angle: hash commits and SHA-256 sponges are in the hash-STARK family (no pairing, no EC DLP). ML-KEM is a Plane B delivery slot, not the covenant hook. Pedersen stays comparison-only because it is discrete-log.

## 5. Lab rule

If we want ciphertext *rather than* plaintext amounts on BCH, encode that in PAA1 / note packets. Circle FRI only binds what we publish. 2024/278 does not give encrypted proofs.
