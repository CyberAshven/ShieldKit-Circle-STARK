# Paper catalog

PDFs download into `Reference/literature/papers/` (gitignored). Re-fetch with the URLs below. Hashes are filled after a successful download.

## Must-read for Circle FRI on BCH

| File | Paper | URL | Role |
| --- | --- | --- | --- |
| `2024-278-circle-starks.pdf` | Haböck, Levit, Papini — Circle STARKs | https://eprint.iacr.org/2024/278.pdf | Domain, circle FFT, Circle FRI |
| `2018-046-fri.pdf` | Ben-Sasson et al. — FRI | https://eprint.iacr.org/2018/046.pdf | Low-degree test |
| `2017-430-fast-rs-iopp.pdf` | Ben-Sasson et al. — Fast RS IOPP | https://eprint.iacr.org/2017/430.pdf | Ancestor of FRI |
| `2019-336-deep-fri.pdf` | Ben-Sasson et al. — DEEP-FRI | https://eprint.iacr.org/2019/336.pdf | Out-of-domain sampling; 0zkbrewer uses this |
| `2021-582-ethstark.pdf` | StarkWare — ethSTARK documentation | https://eprint.iacr.org/2021/582.pdf | What ABL cited as the STARK family spec; conjectural soundness |
| `2024-1037-zk-leakage-starks.pdf` | Witness masking / opened-view leakage | https://eprint.iacr.org/2024/1037.pdf | ShieldKit ZK source pin |
| `2023-323-poseidon2.pdf` | Poseidon2 | https://eprint.iacr.org/2023/323.pdf | Algebraic hash used by 0zkbrewer; M31 hashes still unselected |

## Comparators (not the active branch)

| File | Paper | URL | Role |
| --- | --- | --- | --- |
| `2024-390-stir.pdf` | STIR | https://eprint.iacr.org/2024/390.pdf | Newer proximity test; ABL explicitly did *not* use this |
| `2024-1586-whir.pdf` | WHIR | https://eprint.iacr.org/2024/1586.pdf | Multilinear-friendly FRI-like PCS |
| `2023-1784-binius.pdf` | Binius | https://eprint.iacr.org/2023/1784.pdf | Binary-field multilinear |
| `2023-1045-xhash-family.pdf` | XHash / RPO-M31 family (merged) | https://eprint.iacr.org/2023/1045.pdf | ShieldKit algebraic-hash row; **current merged PDF still a source pin** |
| `2019-550-spartan.pdf` | Setty — Spartan | https://eprint.iacr.org/2019/550.pdf | Sumcheck SNARK for R1CS; not AIR/FRI |
| (repo) | Whirlaway | https://github.com/TomWambsgans/Whirlaway | SuperSpartan-for-AIR + WHIR PCS |

## From the Bastian conversation (context, not Circle math)

| File | Paper | URL | Role in the chat |
| --- | --- | --- | --- |
| `2020-548-bastian-cited.pdf` | Yu — Blockchain Stealth Address Schemes | https://eprint.iacr.org/2020/548.pdf | Stealth / Pedersen lineage |
| `2025-1859-bastian-cited.pdf` | Dartois et al. — qt-Pegasis | https://eprint.iacr.org/2025/1859.pdf | Isogeny PQ side-quest |
| (arxiv) | Rodriguez-Alvarez et al. — ML-KEM storage | https://arxiv.org/pdf/2508.01694 | Why ML-KEM-768 |
| `blockstream-confidential-transactions.pdf` | Maxwell / Poelstra — Confidential Transactions | https://blockstream.com/bitcoin17-final41.pdf | Pedersen CT ancestor |

## Teaching / implementation (HTML or git, not necessarily PDF)

- Vitalik — Exploring circle STARKs: https://vitalik.eth.limo/general/2024/07/23/circlestarks.html
- LambdaClass intro: https://blog.lambdaclass.com/an-introduction-to-circle-starks/
- Eli Ben-Sasson: https://elibensasson.blog/why-im-excited-by-circle-stark-and-stwo/
- Stwo: https://github.com/starkware-libs/stwo
- Plonky3 circle: https://github.com/Plonky3/Plonky3/tree/main/circle
- Vitalik python: https://github.com/ethereum/research/tree/master/circlestark
- BTC script Circle Plonk: https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark

## Download status (2026-08-15)

SHA-256 list: `Reference/literature/papers/SHA256SUMS.txt`. PDFs themselves are gitignored.

Verified against ShieldKit's source pin:

- `2024-1037-zk-leakage-starks.pdf` is **457880 bytes**, sha256 `b6bd98453a64b26c7a08bf02fe9f82f3bde7dd730ecaa3fe9769b1e0f15cf270` — matches the lane pin in `source-pin-review-2026-08-08.md`.
- `2023-1045-xhash-family.pdf` is **820928 bytes**, sha256 `a6ae5fac189f8ed1da29f118ac75632a15959ae26d1075232be8e58b974ba3e5`. This is **not** the historical pre-merge artifact ShieldKit retained (728806 / `bdf95685…`). Treat it as a candidate for the missing “current merged PDF” pin; do not select the algebraic-hash row until the lane re-pins it.

Also fetched:

- `2508-01694-ml-kem-kyber.pdf` from arXiv
- `2606-04311-stwo-air-lean.pdf` — Formal verification of the S-two AIR (Lean 4)
- `Reference/literature/notes/vitalik-circle-starks.html`

S-two / Starknet:

- Blog: https://www.starknet.io/blog/s-two-is-live-on-starknet-mainnet-the-fastest-prover-for-a-more-private-future/
- arXiv: https://arxiv.org/abs/2606.04311

Re-fetch example:

```text
curl.exe -L --fail -o Reference/literature/papers/2024-278-circle-starks.pdf https://eprint.iacr.org/2024/278.pdf
```
