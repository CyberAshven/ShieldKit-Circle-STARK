# Master AI prompt + reference set — Circular STARK BCH shielded pool

Generated 2026-08-16. Corrected the same day: native EC opcodes are
absent, but Pedersen / Bulletproofs / pairing SNARKs can be **emulated**
in CashScript (loops + BigInt + functions). They are expensive, not
impossible. Copy the prompt block into any AI assistant, then hand it
the reference list below (or the individual files it points to) as needed.
Everything here is a public URL or a path that exists in this workspace as of
this date — nothing from `Reference/conversations/bastian/` is included,
because that folder is local-only/gitignored per [README.md](../README.md)
and [design-invariants.md](prior-art/design-invariants.md).

---

## Corrections to the first draft (Claude)

| Draft said | Actual |
| --- | --- |
| Pedersen / Bulletproofs / pairing SNARKs are **blocked** on-chain | **Emulatable** with BigInt + loops + functions. No *native* EC/pairing opcode. groth16_cashscript already verifies Groth16. Emulation is usually too large for 100 KB — that is why hash FRI is first, not why EC is forbidden. |
| Relation includes **transfer** | Product is **any-amount deposit/withdraw**. Fv1 has no transfers. Do not put transfer in the first AIR. |
| Stwo = “reference production implementation” | Prior art only. Do not copy Stwo as the protocol. |
| Link `prior-art/zkp-agnostic-architecture.md` | That file is `literature/notes/zkp-agnostic-architecture.md`. |

Jason on BCR 1476 (public): BCH can already *express* SNARK / STARK / Bulletproof verifiers in script. A dedicated `OP_CHECKZKP` is years away. Contracts first.

## The prompt

```text
You are helping design and implement a ZKP-agnostic Bitcoin Cash (BCH)
shielded pool. Circle STARKs / Circle FRI (ePrint 2024/278) are proving
plugin #1, not the whole architecture — the pool's verifier interface must
stay swappable across proof families (Groth16, classical Goldilocks FRI,
WHIR, etc. later).

Hard constraints (2026 CashVM / "Layla" upgrade):
- A complete standard BCH transaction must fit in <= 100,000 bytes.
- Per-input unlocking bytecode is capped at 10,000 bytes (consensus)
  -> a proof must be sharded across multiple inputs of one transaction.
- Soundness target: 128 bits, hard floor 100 bits.
- Hash/FRI path needs no new opcode (loops + functions are live).
- There is still no native OP_ECADD/OP_ECMUL and no pairing precompile.
  Pedersen, Bulletproofs, and pairing SNARKs are **not impossible**: they
  can be emulated in script (BigInt, loops, functions; groth16_cashscript
  already exists). Emulation is usually too fat for the 100 KB / 10 KB
  envelopes, which is why Circle FRI / hash STARKs are plugin #1. CHIP
  2025-05 would make EC cheap; do not wait on it.
- Product: **one pool, any amount** (deposit / withdraw; change note on
  partial withdraw). Joint-lane Fv1 (fixed 0.1 ticket, no transfers) is
  only the size/proof gate with toorik — do not silently widen Fv1 on
  main, and do not put "transfer" in the first relation.
- State: one global note/nullifier set per instance. Public state is a
  CashToken continuation UTXO (128-byte commitment), serial today.
- Chipnet only in experiments. First client is a desktop CLI; OPTN addon
  is a later skin. Language: TypeScript, CashScript, or Rust — no new JS.
- Stwo / Cairo / generic zkVMs are prior art, not the protocol.

Architecture layers to keep separate (do not conflate them):
1. Statement/relation (what is proven: membership + nullifier + conservation)
2. Arithmetization (AIR for the Circle-FRI plugin)
3. Polynomial commitment / IOPP (Circle FRI now; FRI/DEEP-FRI/STIR/WHIR are
   comparators, not the active branch, unless Circle FRI blows the byte
   budget)
4. Fiat-Shamir transcript + zero-knowledge masking (see ePrint 2024/1037 for
   witness-masking / opened-view leakage in STARKs)
5. On-chain verifier (the actual CashScript/CashVM opcodes re-executed by
   full nodes)

Task: [insert your specific task — e.g. "design the AIR for PoolActionFv1",
"write the CashScript FRI-fold verifier loop", "size a Chipnet deposit/withdraw tx against the 100 KB / 10 KB envelopes",
"compare Circle FRI vs. classical Goldilocks FRI for this verifier", etc.]

Ground every claim in the sources below. If a claim about proof size,
soundness, or opcode availability isn't backed by one of these sources (or
something you can point to with equal specificity), say so explicitly rather
than guessing.
```

---

## 1. Circle STARKs / Circle FRI — the core math (must-read, in order)

| # | Source | What it gives you |
| --- | --- | --- |
| 1 | Circle STARKs — Haböck, Levit, Papini. ePrint 2024/278: https://eprint.iacr.org/2024/278.pdf | The domain trick (`x²+y²=1` over Mersenne31), circle FFT, Circle FRI itself |
| 2 | Vitalik Buterin — "Exploring circle STARKs": https://vitalik.eth.limo/general/2024/07/23/circlestarks.html | Best plain-English walkthrough of why circle groups fix Mersenne31's missing 2-adicity |
| 3 | Vitalik's reference Python implementation: https://github.com/ethereum/research/tree/master/circlestark | Read the code next to the paper |
| 4 | LambdaClass — "An introduction to Circle STARKs": https://blog.lambdaclass.com/an-introduction-to-circle-starks/ | Second explainer, different angle |
| 5 | Eli Ben-Sasson — "Why I'm excited by Circle STARK and Stwo": https://elibensasson.blog/why-im-excited-by-circle-stark-and-stwo/ | Author's-eye framing of why this matters vs. classical STARKs |
| 6 | Stwo (StarkWare's Circle STARK prover, Rust): https://github.com/starkware-libs/stwo | Prior art only — do not treat as protocol authority |
| 7 | Plonky3 circle module: https://github.com/Plonky3/Plonky3/tree/main/circle | Second production implementation, different codebase style |
| 8 | Bitcoin Wildlife Sanctuary — Circle Plonk in Bitcoin Script: https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark | **Directly relevant**: someone already put a circle-domain verifier in a UTXO chain's script language (BTC, not BCH) |
| 9 | S-two / Starknet mainnet prover: https://www.starknet.io/blog/s-two-is-live-on-starknet-mainnet-the-fastest-prover-for-a-more-private-future/ | Production deployment of a Circle STARK prover at scale |
| 10 | Formal verification of the S-two AIR (Lean 4), arXiv 2606.04311: https://arxiv.org/abs/2606.04311 | If you need to argue soundness formally later |

## 2. FRI family and comparator polynomial commitment schemes

Read [Reference/literature/notes/zkp-family-map.md](literature/notes/zkp-family-map.md)
first — it untangles "STARK", "FRI", "WHIR", "Spartan", "Circle" as separate
stack layers instead of interchangeable buzzwords.

| Name | Paper | URL | Status for this project |
| --- | --- | --- | --- |
| Fast RS IOPP | Ben-Sasson et al. | https://eprint.iacr.org/2017/430.pdf | Ancestor of FRI |
| FRI | Ben-Sasson et al., ePrint 2018/046 | https://eprint.iacr.org/2018/046.pdf | Baseline low-degree test |
| DEEP-FRI | Ben-Sasson et al., ePrint 2019/336 | https://eprint.iacr.org/2019/336.pdf | Out-of-domain sampling; used by the 0zkbrewer BCH verifier |
| ethSTARK | StarkWare, ePrint 2021/582 | https://eprint.iacr.org/2021/582.pdf | The AIR+FRI "spec" this whole lineage cites |
| Witness masking / opened-view leakage | ePrint 2024/1037 | https://eprint.iacr.org/2024/1037.pdf | How you actually get zero-knowledge out of a STARK, not just soundness |
| Poseidon2 | ePrint 2023/323 | https://eprint.iacr.org/2023/323.pdf | Algebraic hash candidate (M31-friendly hash still unselected for this project) |
| STIR | ePrint 2024/390 | https://eprint.iacr.org/2024/390.pdf | Comparator — better rate/round than FRI, not the active branch |
| WHIR | ePrint 2024/1586 | https://eprint.iacr.org/2024/1586.pdf | Comparator — STIR-style folding + sumcheck; works univariate and multilinear; **no ZK in base protocol yet** |
| Binius | ePrint 2023/1784 | https://eprint.iacr.org/2023/1784.pdf | Comparator — binary-field multilinear |
| Spartan | Setty, ePrint 2019/550 | https://eprint.iacr.org/2019/550.pdf | Sumcheck SNARK for R1CS, not AIR/FRI — different arithmetization entirely |
| Whirlaway (SuperSpartan-for-AIR + WHIR) | repo | https://github.com/TomWambsgans/Whirlaway | "Multilinear circular" temptation — explicitly deferred until/unless Circle FRI fails the byte envelope |
| whir-p3 spec | repo | https://github.com/tcoratger/whir-p3 | WHIR spec paired with Plonky3 |
| XHash / RPO-M31 family | ePrint 2023/1045 | https://eprint.iacr.org/2023/1045.pdf | Algebraic-hash comparator; treat as unpinned pending re-check |

## 3. STARK provers, zkVMs, and wrap-to-SNARK paths (context, not the plugin)

| Project | URL | Note |
| --- | --- | --- |
| SP1 (RISC-V zkVM, Plonky3-based) | https://github.com/succinctlabs/sp1 | Statement language, not the on-chain verifier plugin; often wraps to Groth16 for EVM |
| Triton VM (AIR VM + Tip5 recursion) | https://github.com/TritonVM/triton-vm | Bad fit while this project stays SHA-256-first |
| Miden VM | https://github.com/0xMiden/miden-vm | Another STARK-based VM, same "know it, don't build it" bucket |
| Neptune (Triton-based L1) | https://neptune.cash/ | Full chain built on Triton VM — architecture comparator |

## 4. On-chain ZKP shielded pools / mixers — prior art for the pool design itself

| Project | URL | Why it matters here |
| --- | --- | --- |
| Tornado Cash docs | https://github.com/tornadocash/docs | Canonical note/nullifier/Merkle-tree mixer design |
| Tornado Cash docs (mirror) | https://docs.tornado.ws/general/how-does-it-work.html | Same content, alternate host |
| Tornado Cash whitepaper (v1.4) | https://tornado.cash/Tornado.cash_whitepaper_v1.4.pdf | Original design doc |
| Voidify (Nova + Classic pools) whitepaper | https://voidifycto.gitbook.io/whitepaper | Recent multi-backend shielded-pool product; direct analogue of "ZKP-agnostic pool" |
| Voidify on-chain program (Classic + Nova, Rust) | https://github.com/VoidifyCommunity/voidify-smart-contract-audit | Read the circuit/relation code directly |
| Voidify SDK (browser prove + relayer) | https://github.com/VoidifyCommunity/voidify-sdk | Client-side proving + relayer pattern |
| Voidify ceremony frontend (trusted setup UI) | https://github.com/VoidifyCommunity/voidify-ceremony-frontend | If a plugin ever needs a trusted setup (Groth16) |
| Aztec docs — state management | https://docs.aztec.network/developers/docs/foundational-topics/state_management | Private/public state split, note discovery |
| Aztec docs — PXE | https://docs.aztec.network/developers/docs/foundational-topics/pxe | Client-side proving architecture |
| Aztec docs — transactions | https://docs.aztec.network/developers/docs/foundational-topics/transactions | Tx anatomy comparator |
| Aztec — "transaction anatomy" blog | https://aztec.network/blog/aztecs-transaction-anatomy/ | Readable version of the above |
| Aztec — "private and public state" blog | https://aztec.network/blog/the-best-of-both-worlds-how-aztec-blends-private-and-public-state | Shared vs. local state design tension, same one this project has to resolve |
| Aztec — indexed Merkle tree docs | https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/indexed_merkle_tree | Nullifier-set data structure choice |
| Aztec — note discovery docs | https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery | How a wallet finds its own notes in a shared set |
| aztec-nr (Noir contracts) | https://github.com/AztecProtocol/aztec-nr | Reference note/nullifier contract code |
| awesome-aztec | https://github.com/AztecProtocol/awesome-aztec | Curated list, more reading |
| Zcash NU5 / Orchard upgrade | https://z.cash/upgrade/nu5/ | Halo2-based shielded pool, no trusted setup — closest non-BCH analogue to "Circle FRI, no trusted setup" |
| Blockstream — Confidential Transactions (Maxwell/Poelstra) | https://blockstream.com/bitcoin17-final41.pdf | Pedersen-commitment ancestor of every amount-hiding scheme here |

## 5. BCH-specific prior art, CHIPs, and protocol constraints

This is the layer that actually gates what's implementable on BCH today —
read before assuming any opcode or byte limit.

| Topic | URL | Note |
| --- | --- | --- |
| Layla / 2026 CashVM upgrade | https://bch.info/en/upgrade | Loops, functions, 128-byte commitments, 10 KB unlocking — the baseline this whole project targets |
| P2S (Pay-to-Script) CHIP, 128-byte commitment | https://github.com/bitjson/bch-p2s | Standardness alignment with the 10,000-byte per-input cap |
| bch-p2s locking bytecode length rationale | https://github.com/bitjson/bch-p2s/blob/master/rationale.md#selection-of-maximum-locking-bytecode-length | Why the limit is what it is |
| TXv5 (transaction version 5 CHIP, not yet live) | https://github.com/bitjson/bch-txv5 | Would enable input de-duplication; do not assume it is active |
| CHIP-2025-01 TXv5 discussion | https://bitcoincashresearch.org/t/chip-2025-01-txv5-transaction-version-5/1490 | BCR thread |
| CHIP-2025-05 native EC arithmetic opcodes | https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570 | Would make Pedersen/Bulletproofs **cheap**. Today: emulate in script (possible, fat) or wait for the CHIP |
| Raising the 520-byte push / 201-op limits | https://bitcoincashresearch.org/t/raising-the-520-byte-push-limit-201-operation-limit/282 | Historical limit-raising precedent |
| Confidential transactions on BCH (BCR thread) | https://bitcoincashresearch.org/t/confidential-transactions/1724 | Community design discussion |
| Shielded addresses / ZKP opcode (BCR thread) | https://bitcoincashresearch.org/t/bitcoin-cash-shielded-addresses-zkp-op-code/1476 | Earlier proposal for a native ZKP-verify opcode |
| Silent Reusable Payment Addresses (SRPA) (BCR thread) | https://bitcoincashresearch.org/t/silent-reusable-payment-addresses-srpa/1637 | Stealth-address layer — "who", not "how much"; complements but is not the pool |
| Groth16 verifier in CashScript | https://github.com/mr-zwets/groth16_cashscript | Pairings **emulated** in script — proof that "no native opcode" ≠ "cannot verify" |
| Quantumroot (PQ vault, not a mixer) | https://blog.bitjson.com/quantumroot/ and https://github.com/bitjson/quantumroot | Key-management layer, orthogonal to the pool's proof system |
| Bastian Carmy — confidential transactions writeup (public repo) | https://github.com/bastiancarmy/bitcoin-cash-confidential-transactions | Public code; the private Telegram deep-dive about it stays local per README |
| Bastian Carmy — proof-bound P2S (public repo) | https://github.com/bastiancarmy/bitcoin-cash-proof-bound-p2s | Public code, same caveat |
| 0zkbrewer — BCH-FRI-STARK-Verifier (Goldilocks DEEP-ALI FRI) | https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier | Classical (non-circle) FRI verifier already running on Chipnet — direct prior art for the verifier shape |
| toorik2 — ShieldKit-Circle-STARK (joint repo) | https://github.com/toorik2/ShieldKit-Circle-STARK | This project's own collaboration repo |
| toorik2 — ShieldKit-SDK | https://github.com/toorik2/ShieldKit-SDK | Product toolkit for spinning up a shielded pool |
| toorik2 — BCH_Knowledge_Base | https://github.com/toorik2/BCH_Knowledge_Base | CashScript / CashTokens reference |
| Four first-ever ZKP verifications on Bitcoin (Medium) | https://medium.com/@w.zhang/four-first-ever-zkp-verifications-on-bitcoin-9475df11d57e | On-chain ZK verifier precedent, BTC side |
| Block blog (BCH education, CashTokens/CashScript) | https://fullstack-agents.github.io/block-blog/#/education and https://github.com/FullStack-Agents/block-blog | General BCH dev background |
| PSF LLM wiki (CashScript/CashTokens, 125 pages) | https://github.com/FullStack-Agents/psf-llm-wiki | Deep CashScript reference, written for LLM consumption |

## 6. UTXO-model privacy design patterns (non-BCH, architecture comparators)

| Topic | URL | Why |
| --- | --- | --- |
| Cardano eUTXO — avoiding contention | https://developers.cardano.org/docs/learn/core-concepts/eutxo/#avoiding-contention | Concurrent-spend problem any shared-UTXO pool hits |
| Cardano eUTXO — multiple UTXOs design | https://developers.cardano.org/docs/learn/core-concepts/eutxo/#multiple-utxos-design | Sharding a global set across UTXOs |

## 7. On-chain evidence (Chipnet transactions, public)

| What | Txid / link |
| --- | --- |
| Confidential Protocol State Cell demo | `be8b9832a2a95bf9b09838cb085bc667e9eedacd2c71ae8422269816ca93737b0` |
| 0zkbrewer FRI demo fund | `b8952034f1123691149a2beb5320aeaf9da2a94d4f71225ff6a3dfa6db4ea341` |
| 0zkbrewer FRI demo spend (92,191 bytes, 28 inputs) | `1f56490fb495e48a889f8327a006f9377478d9108b9bdad5c28724904c7e74b0` |

## 8. General ZKP background (broader than Circle FRI — not yet in this project's pinned catalog)

These are standard, widely-cited references for "everything about ZKP" beyond
the Circle-FRI lane. They aren't in [paper-catalog.md](literature/notes/paper-catalog.md)
because they weren't the active branch, but they're worth having if you're
prompting an AI for general ZKP grounding rather than just the pool:

| Topic | URL |
| --- | --- |
| Groth16 paper | https://eprint.iacr.org/2016/260.pdf |
| PLONK paper | https://eprint.iacr.org/2019/953.pdf |
| Bulletproofs paper | https://eprint.iacr.org/2017/1066.pdf |
| Vitalik — QAPs / "why and how zk-SNARK works" series | https://vitalik.eth.limo/general/2016/12/10/qap.html |
| ZKProof community reference/standards | https://zkproof.org/ |
| Awesome zero-knowledge-proofs (curated list) | https://github.com/matter-labs/awesome-zero-knowledge-proofs |
| Zcash protocol spec | https://zips.z.cash/protocol/protocol.pdf |
| Zcash Orchard (Halo2 shielded pool, Rust) | https://github.com/zcash/orchard |
| Halo2 book | https://zcash.github.io/halo2/ |

*(Not fetched/verified in this session — spot-check before citing as fact to a third party; everything in sections 1–7 above was confirmed present in this workspace's files today.)*

## 9. This workspace's own index and notes (start here for local context)

- [Reference/00-INDEX.md](00-INDEX.md) — master index, kept current
- [Reference/literature/notes/paper-catalog.md](literature/notes/paper-catalog.md) — pinned paper set with local PDF hashes
- [Reference/literature/notes/zkp-family-map.md](literature/notes/zkp-family-map.md) — disambiguates STARK/FRI/WHIR/Spartan/Circle
- [Reference/literature/notes/zkp-agnostic-architecture.md](literature/notes/zkp-agnostic-architecture.md) — the `Verify(family, vk, statement, proof)` plugin design
- [Reference/literature/notes/circular-vs-multilinear.md](literature/notes/circular-vs-multilinear.md) — why Circle FRI first, not a multilinear Circle STARK
- [Reference/prior-art/design-invariants.md](prior-art/design-invariants.md) — the claims this project keeps, cited to public sources only
- [Reference/literature/notes/zkp-agnostic-architecture.md](literature/notes/zkp-agnostic-architecture.md) — plugin ABI
- [Reference/prior-art/shared-vs-global-state.md](prior-art/shared-vs-global-state.md) — global set vs serial UTXO vs shards
- [Reference/prior-art/xo-templates.md](prior-art/xo-templates.md) — GP XO templates (P2PKH + AnyHedge/Cauldron/wrap)
- [Reference/prior-art/bch-literacy.md](prior-art/bch-literacy.md) — Libauth vs CashScript vs XO vs Quantumroot
- [Reference/prior-art/shielded-pool-scalability.md](prior-art/shielded-pool-scalability.md) — mixer/pool throughput and tree-growth analysis
- [Reference/prior-art/utxo-native-pool.md](prior-art/utxo-native-pool.md) — Tornado + Voidify + Aztec synthesized into a BCH-UTXO-native design
- [Reference/prior-art/any-amount-profile.md](prior-art/any-amount-profile.md) — one pool, arbitrary amount, product framing
- [plans/2026-08-15-foundation-plan.md](../plans/2026-08-15-foundation-plan.md) — current working plan
- [AGENTS.md](../AGENTS.md) — agent operating rules for this repo

---

### Note on what's deliberately excluded

`Reference/conversations/bastian/` (the Telegram export, transcript, and
distilled notes with an outside collaborator) is real prior-art context but
is gitignored and marked local-only by this project's own rules — it stays
out of anything that leaves this machine, including prompts pasted into a
hosted AI. If you need that context for local reasoning, read the files
directly; don't paste them into a third-party AI chat.
