# BCH literacy map (for this workspace)

Where to read BCH facts. Not STARK math.

## Layers (do not mix the names)

| Name | Who | What it is | Use for us |
| --- | --- | --- | --- |
| **CashVM / Libauth VM** | bitjson / `@bitauth/libauth` | The script **engine**. Compile, evaluate, encode txs. Wallet **templates** (`importWalletTemplate`, `walletTemplateToCompilerBCH`). | Verifier, tx builder, Chipnet eval |
| **CashScript** | CashScript.org | High-level language → Script. Validates; does not “call”. | Covenant / verifier programs |
| **Cash Stack** | PSF / `psf-llm-wiki` | App → bch-js → API → Fulcrum → BCHN | Indexer literacy. We write **TS**, not bch-js |
| **XO Stack** | GP GitLab [`GeneralProtocols/xo`](https://gitlab.com/groups/GeneralProtocols/xo) | Libauth-schema **templates** + Engine + invitations. Published: P2PKH. `more_templates` also has AnyHedge / Cauldron / wrap / auction (+ draft oracles). | Portable action format. Not our prover. See `xo-templates.md` |
| **Chaingraph** | bitauth | GraphQL indexer | Token/UTXO reads |
| **Quantumroot** | bitjson | PQ **key vault** (Schnorr + LM-OTS). Not a mixer | Key path later. Not Plane A |

## Local clones (already here)

| Path | Open first |
| --- | --- |
| `repos/BCH_Knowledge_Base/Knowledge-Base-V2/CORE_REFERENCE.md` | CashScript types, introspection, 128 B commitments |
| `repos/BCH_Knowledge_Base/concepts/` | UTXO vs account, multi-contract |
| `repos/BCH_Knowledge_Base/best-practices/security/` | 5-point covenant |
| `repos/psf-llm-wiki/wiki/index.md` | Then `utxo`, `cashtokens-*`, `cashscript-*`, `cash-stack-layers` |
| `repos/block-blog` | Layla narrative |
| `repos/BCH-FRI-STARK-Verifier` | Libauth harness prior art |

## Rules we keep from the KB

1. Ask: **what UTXO transformation is allowed?** Not “what does the contract do.”
2. State = **mutable NFT commitment** on a continuation UTXO (128 B post-Layla).
3. Self-replicating covenant: check **all five** — locking bytecode, token category, sats, token amount, new commitment.
4. Multi-contract = **one transaction, pinned input indices**. No `delegatecall`.
5. `&&` / `\|\|` do **not** short-circuit.
6. Standard tx ≤ 100 KB. Per-input unlocking ≤ 10 KB.

## Libauth (the engine we actually compile against)

- Docs: https://libauth.org — repo: https://github.com/bitauth/libauth
- IDE / templates: https://ide.bitauth.com
- Zero-dependency TypeScript. Keys, CashAddr, CashTokens, VM eval, tx encode.
- Wallet template = JSON description of locking/unlocking; compiler emits bytecode. That is **libauth templates**, not XO templates.
- Language policy: call libauth from **strict TS**. CashScript first for covenants; hand-lower only what cashc cannot emit.

## Quantumroot (keys, not privacy)

- https://blog.bitjson.com/quantumroot/ — https://github.com/bitjson/quantumroot
- Receive address (Schnorr now) + Quantum Lock (LM-OTS / token-delegated later).
- CashToken category is the **authorization handle**, then rotates.
- OPTN notes: `D:\OPTNWallet-Desktop\docs\quantumroot-flow.md` (do not edit OPTN source).
- Does not hide amounts or membership. Do not put the mixer inside Quantumroot.

## XO Stack (app framework, not our pool)

See `xo-stack.md`. Code: GitLab `GeneralProtocols/xo` (`templates`, `engine`, …). Current published template is P2PKH on libauth wallet-template-v0. AnyHedge contracts/library are the production covenant example. Do not depend on XO Engine to prove or verify Circle FRI.

## Chipnet

`bchtest:` · Electrum `wss://chipnet.imaginary.cash:50004` · faucet tbch.googol.cash · explorer chipnet.imaginary.cash. Never mainnet in experiments.
