# Prior art: BCH-FRI-STARK-Verifier (0zkbrewer)

- Upstream: https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier
- Your fork: https://github.com/CyberAshven/bch-fri-stark-verifier
- Local: `repos/BCH-FRI-STARK-Verifier`
- This is **classical DEEP-ALI FRI over Goldilocks**, not Circle FRI.

## What it proves

A Poseidon2 hash chain as an AIR. Prover off-chain. Verifier is a multi-input P2SH32 transaction on unmodified BCH 2026 VM. Input 0 holds the Fiat–Shamir blob; other inputs run trace/composition openings, DEEP quotient, composition, and FRI.

Field: Goldilocks \(p = 2^{64}-2^{32}+1\), challenges in \(\mathrm{GF}(p^2)\) (`u^2-7`).

Pinned sound config (`apps/native_ct_air_config.py`):

| Param | Value | Note |
| --- | --- | --- |
| BLOWUP | 2048 | composition FRI'd directly, rate \(2/B\) not \(1/B\) |
| QUERIES | 8 | power of two for topology split |
| GRIND_BITS | 24 | ~7 s Python PoW; 40 bits was days |
| FOLD | 8 | arity-8 folds |
| TRACE_D | 20 | \(T=2^{10}\), domain \(2^{21}\) |
| SECURITY_TARGET | 100 bits | conjectural: \(q(\log_2 B - 1) + \mathrm{grind}\) |
| MERKLE_HASH_BYTES | 32 | N3 lever can cut to 26 B later |
| MASK_DEG | 64 | trace mask; FRI-fold ZK mask still OPEN |

They document the ethSTARK pitfall: if composition degree is ~2T and you FRI it directly, per-query bits are \(\log_2 B - 1\), not \(\log_2 B\).

## Measured sizes (their README)

| Build | Bytes | Notes |
| --- | --- | --- |
| Chipnet demo spend | 92,191 | 28 inputs, block 314510 |
| Same demo in harness | 92,167 | |
| Soundness-wired, same proving config | **120,537** | over the 100 KB standard limit |

The ~28 KB gap is binding, Merkle pinning, inverse hints, and cross-input authentication. Two adversarial audits found real forged accepts:

1. Hashing unlocking bytes authenticates bytes, not the redeem that runs. Bind the **locking** script.
2. Binding only terminal inputs is not enough. Bind **every** input that another input reads, anchored on the committed blob.

Demo fund/spend on chipnet:

- fund `b8952034f1123691149a2beb5320aeaf9da2a94d4f71225ff6a3dfa6db4ea341`
- spend `1f56490fb495e48a889f8327a006f9377478d9108b9bdad5c28724904c7e74b0`

## Why this is not the product backend

- Goldilocks 8-byte limbs are expensive in script compared with M31 4-byte limbs.
- Sound wiring already overshoots 100 KB on a hash-chain AIR, before a real pool statement.
- Circle FRI exists specifically so we can use Mersenne31, which has no large smooth multiplicative subgroup.

Keep this repo as:

- the best existing **on-chain FRI verifier topology** (multi-input P2SH32, FS blob, grind, DEEP)
- the checklist of **binding bugs**
- the warning that demo size ≠ sound size

## Standing review (from Bastian chat 2026-08-01)

ABL forwarded an AI review (treat as a hypothesis, then reproduce):

- FRI-to-single-constant may make the final degree check vacuous
- false-statement proof (`t[i] += 1`) may still verify
- tamper tests that only break Merkle roots do not test soundness
- grind and proof-size regressions

Any Circle FRI verifier we write must include **prove-false-statement-from-scratch** tests on day one.
