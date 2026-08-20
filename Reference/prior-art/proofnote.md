# Proofnote / APNT — comparator, not the pool

Public sources only:

- Site: https://proofnote.cash/
- Post: https://proofnote.cash/posts/01-private-notes-without-a-global-pool/
- Repo: https://github.com/casablanca-labs/proofnote
- Tag used here: `v0.4.4`
- Why SP1 / Pedersen check: https://github.com/casablanca-labs/proofnote/blob/v0.4.4/docs/why-sp1.md
- Why not a pool: https://github.com/casablanca-labs/proofnote/blob/v0.4.4/docs/why-not-a-pool.md
- Campaign: https://fundme.cash/campaign/143

**Their product is not ours.** APNT is aggregated private note transfer on ordinary BCH UTXOs **without** a global mutable privacy pool. This lab is an **any-amount shielded pool** (one note/nullifier set, continuation UTXO). Shared concepts below are discipline, not an architecture import.

## What they actually shipped (checked, not assumed)

Campaign #143 named STARK/hash proofs and Pedersen commitments. `v0.4.4` records a different delivery:

| Named | Delivered |
| --- | --- |
| Hash STARK on-chain | SP1 guest proving the **existing SHA-256** note commitment, **wrapped Groth16** for CashVM |
| Pedersen value commitment | **Not used.** Equal-value cells + counting conservation; spent outpoint is the nullifier |

They published that mismatch instead of leaving a reader to find it. Pedersen is a requirement they checked and rejected unless measured evidence says otherwise (`why-sp1.md`, “The Pedersen question, checked rather than assumed”).

SP1 was chosen because Triton VM is Tip5-native and APNT’s commitment is domain-separated SHA-256. Substituting Tip5 for SHA-256 would have been proving a **different relation**. Quote of the rule they kept: do not claim the proof opens `noteCommitmentV0` unless the proof verifies that SHA-256 relation.

They also pin the boundary: SP1 does not make APNT “BCH-native” and does not remove random-oracle / proof-system assumptions. SP1 is “the first acceptance backend, not a permanent protocol identity.” A backend-neutral envelope (relation id, backend id, verifier method) is **design intent** in that note, not a shipped ABI in `v0.4.4`.

On-chain verifier path is a **chunked Groth16** CashVM graph (credits `groth16_cashscript`). Canonical settlement size they publish: **99,950 bytes** (inside the 100 KB standard envelope). Chipnet inclusion of that path is still **open** on the site.

## Concepts that apply here (without copying the design)

1. **Prove the relation that exists.** Our lock is SHA-256 Merkle + Circle FRI in CashVM. A Poseidon2 table entry or a Triton/Tip5 prover does not let us claim the on-chain hash changed. Same test we already use for Pedersen: increment 3 is tagged SHA-256 note-amount commit; Pedersen stays comparison-only until CHIP 2025-05 is live and measured.
2. **Backend ≠ protocol identity.** Pool `Verify(family, vk, statement, proof)`. Circle FRI is plugin #1. Groth16 / SP1 wrap is a reserved plugin, not the pool. Their sentence about SP1 matches that split; their wrap is still pairing, which is the wrong **default** verifier on BCH 2026.
3. **Check Pedersen rather than assume it.** Naming Pedersen in a roadmap is not evidence the lock uses it. We do not add a Bulletproof/Pedersen layer because a campaign or a neighbouring project named it.
4. **Claims travel with non-claims.** Their verify tooling prints `establishes` and `doesNotEstablish` together. We already refuse “demo accepted ⇒ sound” and “component script size ⇒ complete tx size.” Keep that bar.
5. **100 KB is a real envelope.** They squeezed a Groth16 settlement to 99,950 B. We keep A ≤ 100,000 B by chunking kernels (4 R-slots on A, 36 on B), not by dummy `OP_DROP` cargo.

## Concepts that do **not** apply (different design)

- **No global pool.** They argue shared mutable state contends for one UTXO; they use per-note bundles / equal-value cells. **We chose the pool:** one anonymity set, any-amount, public TVL on the continuation UTXO (`STATE_BASE` + reserve). Their cost is ad-valorem cell count; ours is a flat-ish verifier + shared roots. Neither is free — do not cite their “why not a pool” as a reason to abandon this product.
- **UTXO-as-nullifier** works for *their* public backing cells because BCH already prevents double-spend of those outpoints. A pool still needs a **private** nullifier accumulator in the NFT; spending the pool UTXO is not per-note nullification.
- **Aggregator authority split** (assemble, do not custody) is compatible with a pool relayer that only broadcasts. It is not a substitute for the covenant.
- **Groth16 wrap / pairing verifier** is their CashVM landing path. Ours is Circle FRI + SHA-256. Do not import BN254 chunking as the lab verifier.
- **Equal-value cells** are Classic/Fv1-shaped. This product is any-amount, one set. Do not silently reintroduce denomination tiers.

## Standing non-claims (theirs, left theirs)

Chipnet-only prototype, degenerate anonymity set, successive private transfer not established, live inclusion open. Do not treat their site as a land of our kernels.
