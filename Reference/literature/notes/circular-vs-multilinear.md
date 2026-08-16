# Circle STARK vs multilinear Circle STARK

Decision for this workspace, 2026-08-15.

## Short answer

**Build Circle FRI first. Do not start a "multilinear circular STARK".**

Keep the pool statement backend-neutral so a multilinear PCS can be swapped later if Circle FRI cannot fit a sound 100 KB transaction.

## What the names mean

### Circle STARK (the real object)

Haböck, Levit, Papini, ePrint **2024/278**.

Mersenne31 \(p = 2^{31}-1\) is a great machine field (31-bit limbs, cheap modular reduction) but \(p-1 = 2^{31}-2\) is **not** divisible by a large power of two. Classical FFT/FRI wants a smooth multiplicative subgroup. Circle STARKs replace that subgroup with the **circle group**

\[
x^2 + y^2 = 1 \quad \text{over } \mathbb{F}_p
\]

which *does* have a large 2-adic structure. Then one builds the circle analogues of:

- Reed–Solomon-like codes on the circle
- vanishing polynomials
- FFT
- FRI (Circle FRI)

Stwo and Plonky3's `circle` crate implement this. Vitalik's `circlestark` is the teaching implementation.

This is still a **univariate-style** STARK: a trace over a 1-dimensional FFT-friendly domain, AIR constraints, FRI low-degree test. The novelty is the domain, not a switch to multilinear polynomials.

### Multilinear STARK / multilinear PCS

The statement is a multilinear polynomial over \(\{0,1\}^n\). The IOP is usually **sumcheck** plus a multilinear polynomial commitment (Binius, WHIR, BaseFold, HyperPlonk-style).

There is no standard system called "multilinear Circle STARK". People sometimes mean one of:

1. **Sumcheck + Circle FRI as the univariate PCS** after a round of combination (possible, extra protocol layer).
2. **Confusing Circle (the group) with circular recursion** (different word).
3. **Wanting Binius/WHIR size** while keeping M31 (WHIR is a FRI-like protocol for multilinear polynomials; ShieldKit lists WHIR as a *comparator*, not an active branch).

## Why Circle FRI is the first backend

| Criterion | Circle FRI (M31) | Classical FRI (Goldilocks) | Multilinear (WHIR/Binius) |
| --- | --- | --- | --- |
| BCH limb cost | 4-byte field ops | 8-byte field ops | depends; binary towers are awkward in BigInt script |
| On-chain verifier we already understand | fold + Merkle + queries (same shape as ABL/0zkbrewer) | already measured; **sound build 120 KB** | sumcheck verifier is a different script; no BCH measurement |
| Fits ShieldKit frozen family | **yes, this is the selected family** | historical comparator | historical comparator |
| FFT on M31 | the reason Circle exists | N/A (Goldilocks has 2-adic order) | does not use that FFT |
| Pool agnosticism | one backend | one backend | one backend |

The 100 KB miss on Goldilocks is the strongest empirical reason to change **field + domain**, not to jump to a second arithmetization before Circle FRI is even implemented. ShieldKit P2 is already measuring M31 kernels. Circle/query/FRI are the next closed gates, not a WHIR rewrite.

## Why not fuse the pool to Circle STARK

BCH can host Groth16 (mr-zwets), Goldilocks FRI (0zkbrewer), Circle FRI (this lane), and later a multilinear PCS. The covenant should check:

```text
statement = (old_state, new_state, tx_context, public_ticket_rules)
proof     = bytes + openings that a chosen verifier program accepts
```

`PoolActionFv1` is already written that way. Circle FRI is the first `verifier program`. A second profile can bind a different program without changing note/nullifier/reserve semantics.

A monolithic "the pool *is* a Stwo/Cairo program" would lock the product to one prover stack. The lane README already forbids inheriting Stwo as protocol authority.

## When to reopen multilinear

Reopen only after a measured Circle-FRI 128-bit (or fallback ≥100-bit) complete transaction is on the table and fails the 100 KB envelope **and** the failure is FRI query/fold bytes, not covenant binding. Then compare:

- Circle FRI with arity-8 folds, truncated Merkle, DEEP, smaller trace
- WHIR / STIR as a drop-in proximity test
- Multilinear arithmetization of the same `PoolActionFv1` relation

Do not reopen it because the name sounds more advanced.

## Vocabulary we will use

| Say | Do not say |
| --- | --- |
| Circle FRI, Circle-domain FRI, Circle STARK | "circular STARK" in a paper citation (people will hear recursion) |
| Circle group, circle code | "circular field" |
| Multilinear IOP / WHIR / Binius | "multilinear circular STARK" |
| Backend, proof family | "the pool STARK" |
