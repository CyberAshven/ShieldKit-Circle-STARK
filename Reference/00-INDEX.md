# Master reference index

Last updated 2026-08-16. Every entry below exists on disk or is a public URL that was actually opened.

## Artifacts in this public notebook

| Artifact | Path | Why it matters |
| --- | --- | --- |
| Public design invariants | `Reference/prior-art/design-invariants.md` | What we keep, cited to public URLs |
| Language policy | `Reference/language-policy.md` | TS / CashScript / Rust; no new JS |
| Early CashVM ZIP | `Reference/prior-art/zk-stark-cashvm-early/` | Goldilocks FRI + CashScript folds |
| verifier.cash (Groth16, not STARK) | `Reference/prior-art/verifier-cash.md` | BCH-native pairing verifier leaderboard; packaging lessons |
| Any-amount Chipnet lab | `workspaces/any-amount/` | Product profile on this branch |
| Chipnet 36-slot milestone | `workspaces/any-amount/MILESTONE.md` | Lands accumulate; current 36-fold `b1415faf…` |
| Ciphertext vs Circle STARK | `Reference/literature/notes/ciphertext-vs-circle-stark.md` | Proof ≠ ciphertext; 2024/1037 mask vs lab OTP + degree-0 offset |
| Nostr pool announce | `Reference/prior-art/nostr-pool-announce.md` | Kind 30017 discovery bus (not consensus) |

## Public remotes

| Repo | URL | Local clone / fork |
| --- | --- | --- |
| ShieldKit-Circle-STARK (upstream) | https://github.com/toorik2/ShieldKit-Circle-STARK | remote `upstream` |
| ShieldKit-Circle-STARK (fork) | https://github.com/CyberAshven/ShieldKit-Circle-STARK | remote `origin` |
| BCH-FRI-STARK-Verifier | https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier | Goldilocks FRI prior art |
| BCH_Knowledge_Base | https://github.com/toorik2/BCH_Knowledge_Base | CashScript / CashTokens |
| ShieldKit-SDK | https://github.com/toorik2/ShieldKit-SDK | Product toolkit |
| Confidential transactions writeup | https://github.com/bastiancarmy/bitcoin-cash-confidential-transactions | cited, not cloned |
| Proof-bound P2S | https://github.com/bastiancarmy/bitcoin-cash-proof-bound-p2s | cited |
| Groth16 CashScript | https://github.com/mr-zwets/groth16_cashscript | SNARK comparator |
| Bitcoin circle-stark (BTC script) | https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark | Circle Plonk in BTC script |
| Stwo | https://github.com/starkware-libs/stwo | Circle STARK prover (prior art only) |
| Plonky3 circle | https://github.com/Plonky3/Plonky3 | Circle implementation |
| Vitalik circlestark | https://github.com/ethereum/research/tree/master/circlestark | Pedagogy |
| Block blog | https://github.com/FullStack-Agents/block-blog | live: fullstack-agents.github.io/block-blog |
| PSF LLM wiki | https://github.com/FullStack-Agents/psf-llm-wiki | Cash Stack + CashScript wiki |
| Voidify Linktree (all public links) | https://linktr.ee/VoidifyCommunity | hub |
| Voidify published docs | https://voidifycto.gitbook.io/whitepaper | same as gitbook clone |
| Voidify on-chain program | https://github.com/VoidifyCommunity/voidify-smart-contract-audit | Classic + Nova Rust; cloned |
| Voidify ceremony UI | https://github.com/VoidifyCommunity/voidify-ceremony-frontend | trusted setup frontend |
| Voidify gitbook | https://github.com/VoidifyDAO/voidify-gitbook | Nova/Classic docs |
| Voidify SDK | https://github.com/VoidifyCommunity/voidify-sdk | browser prove + relayer |
| SP1 | https://github.com/succinctlabs/sp1 | RISC-V zkVM (wraps to SNARK on EVM) |
| Triton VM | https://github.com/TritonVM/triton-vm | Tip5 recursive STARK VM |
| BCH_Knowledge_Base (public) | https://github.com/toorik2/BCH_Knowledge_Base | CashScript KB |

## Core papers

See [literature/notes/paper-catalog.md](literature/notes/paper-catalog.md).

Must-read for the current lane:

1. Circle STARKs — ePrint 2024/278
2. FRI — ePrint 2018/046
3. DEEP-FRI — ePrint 2019/336
4. ethSTARK — ePrint 2021/582
5. Witness-masking / leakage — ePrint 2024/1037
6. Poseidon2 — ePrint 2023/323

Comparators, not the active branch: STIR 2024/390, WHIR 2024/1586, Binius 2023/1784.

Related public papers (not Circle-FRI math):

- 2020/548 Blockchain Stealth Address Schemes
- 2025/1859 qt-Pegasis (isogeny class-group action)
- arXiv 2508.01694 ML-KEM / Kyber size study
- arXiv 2606.04311 Formal verification of the S-two AIR (Lean 4)

## Chipnet transactions that are public evidence

| What | Txid |
| --- | --- |
| Confidential Protocol State Cell demo | `be8b9832a2a95bf9b09838cb085bc667e9eedacd2c71ae8422269816ca93737b0` |
| 0zkbrewer FRI demo fund | `b8952034f1123691149a2beb5320aeaf9da2a94d4f71225ff6a3dfa6db4ea341` |
| 0zkbrewer FRI demo spend (92,191 bytes, 28 inputs) | `1f56490fb495e48a889f8327a006f9377478d9108b9bdad5c28724904c7e74b0` |

## Notes in this tree

- [prior-art/design-invariants.md](prior-art/design-invariants.md)
- [prior-art/shieldkit-circle-stark.md](prior-art/shieldkit-circle-stark.md)
- [prior-art/bch-fri-stark-verifier.md](prior-art/bch-fri-stark-verifier.md)
- [prior-art/cashvm-early-work.md](prior-art/cashvm-early-work.md)
- [prior-art/confidential-state-cell.md](prior-art/confidential-state-cell.md)
- [prior-art/bch-knowledge-base.md](prior-art/bch-knowledge-base.md)
- [literature/notes/circular-vs-multilinear.md](literature/notes/circular-vs-multilinear.md)
- [literature/notes/zkp-agnostic-architecture.md](literature/notes/zkp-agnostic-architecture.md)
- [literature/notes/zkp-family-map.md](literature/notes/zkp-family-map.md) — FRI / WHIR / Spartan / Whirlaway / Circle
- [prior-art/bcr-privacy-threads.md](prior-art/bcr-privacy-threads.md) — BCR 1724, 1476, 1570, SRPA
- [prior-art/cardano-eutxo.md](prior-art/cardano-eutxo.md)
- [prior-art/aztec.md](prior-art/aztec.md)
- [prior-art/aztec-scalability.md](prior-art/aztec-scalability.md) — Aztec the L2 (not our pool)
- [prior-art/shielded-pool-scalability.md](prior-art/shielded-pool-scalability.md) — our mixer/pool throughput and tree growth
- [prior-art/voidify.md](prior-art/voidify.md)
- [prior-art/utxo-native-pool.md](prior-art/utxo-native-pool.md) — Tornado + Voidify + Aztec → BCH UTXO best-of
- [prior-art/shared-vs-global-state.md](prior-art/shared-vs-global-state.md) — global set vs serial UTXO vs shards
- [prior-art/stwo-sp1-triton.md](prior-art/stwo-sp1-triton.md)
- [prior-art/tornado-neptune.md](prior-art/tornado-neptune.md)
- [prior-art/block-blog.md](prior-art/block-blog.md)
- [prior-art/psf-llm-wiki.md](prior-art/psf-llm-wiki.md)
- [prior-art/cashfusion-nostr-lessons.md](prior-art/cashfusion-nostr-lessons.md)
- [prior-art/client-and-usage.md](prior-art/client-and-usage.md) — friendly CLI + 10-wallet Chipnet lab
- [prior-art/bch-literacy.md](prior-art/bch-literacy.md) — CashScript / Libauth / Cash Stack / XO / Quantumroot map
- [prior-art/xo-stack.md](prior-art/xo-stack.md) — General Protocols XO (not our engine)
- [prior-art/xo-templates.md](prior-art/xo-templates.md) — all 7 XO blogs + every template file + NIP-EE is not a template
- [prior-art/nostr-transport.md](prior-art/nostr-transport.md) — NIP-44 / 59 / 17 + Tor; event bus not a template
- [prior-art/quantumroot.md](prior-art/quantumroot.md) — PQ vault, not the mixer
- [prior-art/any-amount-profile.md](prior-art/any-amount-profile.md) — one pool, type any amount (product)
- [prior-art/cli-ux.md](prior-art/cli-ux.md) — OPTN nav + any-amount home
- [ai-prompt-master-references.md](ai-prompt-master-references.md) — master AI prompt (corrected: Pedersen emulatable, no transfer in Fv1)
