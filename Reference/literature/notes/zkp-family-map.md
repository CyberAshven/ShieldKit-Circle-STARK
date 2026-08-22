# ZKP family map (what these names actually are)

Read this before mixing “STARK”, “WHIR”, “Spartan”, and “Circle” as if they were interchangeable products.

A proof system is a **stack**. People name one layer and mean the whole sandwich.

```text
statement language     AIR  |  R1CS  |  Plonkish  |  multilinear / sumcheck
         |                    |           |              |
arithmetization        how the computation becomes polynomials
         |
polynomial commitment  FRI | DEEP-FRI | STIR | WHIR | KZG | IPA | Binius
         |
Fiat–Shamir + ZK mask  transcript, grind, hiding
         |
on-chain verifier      what BCH script must re-run
```

Circle FRI is **one PCS + one domain**. It is not a statement language. WHIR is **another PCS**. Spartan is a **sumcheck SNARK for R1CS**. Whirlaway is **Spartan-shaped AIR + WHIR as the PCS**.

## Layers, not brands

| Layer | Job | Examples |
| --- | --- | --- |
| Statement | What you prove | “note in tree + unused nullifier + conservation” |
| Arithmetization | Encode that as algebra | **AIR** (tables + transition constraints), R1CS, Plonk gates, MLE |
| PCS / IOPP | Commit to polynomials and test degree | **FRI**, DEEP-FRI, **STIR**, **WHIR**, KZG, IPA |
| Domain trick | Make FFT/FRI work on a field | Multiplicative subgroup, **circle group** (M31) |
| Wrapper | Shrink for pairing L1s | Groth16/PLONK wrap of a STARK (SP1’s EVM path) |

“AIR FRI STARK” = AIR statement + FRI proximity test. That is the classical StarkWare / ethSTARK / 0zkbrewer shape.

“Circle STARK” = AIR (or similar) + **Circle FRI** on the circle group, usually over Mersenne31 (ePrint **2024/278**, Stwo).

“AIR WHIR” / **Whirlaway** = AIR (or SuperSpartan-for-AIR) + **WHIR** instead of FRI.

## FRI family (univariate Reed–Solomon IOPP)

| Name | Paper | What it changes |
| --- | --- | --- |
| FRI | 2018/046 | Fold a Reed–Solomon code until a constant; query Merkle paths |
| DEEP-FRI | 2019/336 | Out-of-domain samples; 0zkbrewer uses this |
| STIR | 2024/390 | Better rate per round than FRI; ABL ZIP explicitly did *not* use this |
| WHIR | 2024/1586 | STIR-style folding + BaseFold-like **sumcheck** constraint; fewer queries, faster verify; works univariate *and* multilinear |
| Circle FRI | 2024/278 | FRI on \(x^2+y^2=1\) so M31 has an FFT domain |

Local PDFs: `2018-046-fri`, `2019-336-deep-fri`, `2024-390-stir`, `2024-1586-whir`, `2024-278-circle-starks`.

WHIR is **not** a STARK by itself. It replaces FRI as the proximity test. ShieldKit already lists WHIR as a **comparator**, not the Fv1 branch. Reopen it only if a measured Circle-FRI 128-bit tx misses 100 KB **because of query/fold bytes**.

WHIR currently has **no ZK** in the base protocol (Plonky3 tracking HVZK-WHIR). Circle FRI / ethSTARK have known masking recipes (2024/1037). That matters for a privacy pool.

## Spartan and Whirlaway (multilinear / sumcheck)

| Name | Paper / repo | What it is |
| --- | --- | --- |
| Spartan | ePrint **2019/550**, CRYPTO 2020 | Transparent SNARK for **R1CS** via **sumcheck** + a multilinear PCS. Time-optimal prover. Not AIR, not FRI. Original impl uses a DL-based PCS (not PQ). |
| SPARK | inside Spartan | Compiler: any MLE PCS → sparse MLE PCS |
| SuperSpartan | later work | Spartan-style for more general / AIR-like constraints |
| Whirlaway | [github.com/TomWambsgans/Whirlaway](https://github.com/TomWambsgans/Whirlaway), LambdaClass 2025-08 | **Multilinear STARK**: SuperSpartan-for-AIR + **WHIR as PCS**. Lean-Ethereum / PQ signature research. Spec also in [whir-p3](https://github.com/tcoratger/whir-p3) |
| BaseFold | 2024 | Sumcheck + folding; WHIR borrows the constraint check |

Spartan-WHIR on EVM has been measured (PSE, 2026): WHIR verify on a 31-bit field is a *gas* story, not a BCH script story. Do not treat those gas numbers as 100 KB.

For BCH Fv1: **do not start Whirlaway**. It is the “multilinear circular” temptation with extra steps. Same rule as before: Circle FRI first; WHIR/Whirlaway if Circle FRI fails the envelope.

## Other names you will hit

| Name | One line | Our use |
| --- | --- | --- |
| Groth16 | Pairing SNARK, ~256 B, trusted setup | Voidify/Tornado; plugin only if pairings exist |
| PLONK / Honk | Universal setup or folding SNARK | Aztec-adjacent; not BCH-native default |
| Bulletproofs | Range proofs, ~700 B, no setup, EC | Needs OP_ECADD/ECMUL; not live |
| Binius | Binary-field multilinear | Comparator |
| ethSTARK | AIR + FRI cookbook | What “counts as a STARK” in the ABL/0zkbrewer line (2021/582) |
| Stwo / S-two | Circle STARK prover for Cairo | Prior art; Lean AIR paper 2606.04311 |
| SP1 | RISC-V zkVM, Plonky3, often wrap to Groth16 | Statement language, not our on-chain plugin |
| Triton | AIR VM + Tip5 recursion | Bad fit if we stay SHA-256 |

## What to implement vs what to know

| Build now | Know, do not implement |
| --- | --- |
| Circle-domain FRI + AIR of `PoolActionFv1` | Whirlaway, Spartan+WHIR |
| SHA-256 Merkle (or pinned algebraic hash later) | KZG / pairing SNARKs as identity |
| DEEP optional (0zkbrewer has it) | STIR unless Circle FRI needs rate |
| False-statement tests, 2024/1037 masking | Recursive SNARK wrap |

## Vocabulary

Say **Circle FRI** or **Circle-domain FRI** for the PCS. Say **AIR** for the statement encoding. Say **WHIR** only as a PCS swap. Say **Whirlaway** only for the Spartan+WHIR stack. Never say “WHIR STARK” when you mean Circle FRI.
