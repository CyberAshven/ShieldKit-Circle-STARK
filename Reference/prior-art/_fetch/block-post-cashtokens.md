---
title: "CashTokens: Bitcoin Cash's Built-in Token System"
date: "2026-07-12"
excerpt: "Most people don't know that Bitcoin Cash has a built-in token system — CashTokens. Unlike ERC-20 tokens on Ethereum (which run on a virtual machine) or SLP tokens on BCH (which run as a separate overlay), CashTokens are baked directly into the protocol. Here's why that matters."
tags: ["bitcoin-cash", "cashtokens", "blockchain", "defi"]
---

# CashTokens: Bitcoin Cash's Built-in Token System

If you've been following crypto for a while, you've probably heard of ERC-20 tokens on Ethereum, BRC-20 tokens on Bitcoin, or SLP tokens on Bitcoin Cash. But there's a newer, more elegant approach that most people haven't heard about: **CashTokens**.

Activated in the **May 2023 Bitcoin Cash upgrade**, CashTokens is a built-in token system that lives directly in the BCH protocol — not as a separate layer, not as a smart contract, but as a first-class citizen of the blockchain itself.

## What Makes CashTokens Different?

Most token systems work as **overlay protocols**. SLP tokens on Bitcoin Cash, for example, encode token data in the `OP_RETURN` field of transactions. Wallets and indexers parse this data to track token balances. It works, but it's fragile — a wallet that doesn't understand SLP could accidentally burn tokens.

CashTokens takes a different approach. Tokens are recognized at the **protocol level**. This means:

- **Counterfeit-proof by design** — The network itself validates token authenticity, not just third-party indexers
- **Non-destructive** — A wallet that doesn't understand CashTokens can't accidentally destroy them. The tokens remain safely in the UTXO
- **Opt-in** — Token-aware wallets use distinct CashAddress types, so you can't accidentally send tokens to an incompatible wallet

## Two Types of Tokens

CashTokens cleanly separates two primitives that other systems often conflate:

### Fungible Tokens
These are interchangeable units — like dollars, shares, or loyalty points. Each unit is identical to any other. They can be merged, divided, and traded freely. Use cases include:
- Stablecoins and regional currencies
- Voting shares in DAOs
- Liquidity pool tokens
- Utility tokens for dApps

### Non-Fungible Tokens (NFTs)
Each NFT is unique and cannot be divided. But in CashTokens, NFTs serve a deeper purpose than just collectibles. They act as **authenticated commitments** — messages that contracts can verify came from another contract. This enables something remarkable: **cross-contract communication** on a UTXO blockchain.

## The Killer Feature: Cross-Contract Communication

This is where CashTokens gets really interesting. Before CashTokens, Bitcoin Cash contracts could only issue commitments through private keys (signatures) or data signatures (`OP_CHECKDATASIG`). Since contracts can't hold private keys, they couldn't authenticate messages to other contracts.

CashTokens solves this. An NFT issued by a contract serves as an **impersonation-proof message** that other contracts can verify. This means:

- **Decentralized oracles** — Contracts can issue authenticated price feeds or data
- **Composable dApps** — Multiple contracts can coordinate without a central authority
- **Public interfaces** — Different developers can build compatible contracts that work together

All of this happens within Bitcoin Cash's **stateless UTXO model**, which can process over 25,000 transactions per second on modest hardware — a >1000x efficiency advantage over account-based models like Ethereum.

## What Can You Build?

The CashTokens specification includes examples of sophisticated applications:

### Decentralized Governance
Fungible tokens enable on-chain voting without locking up shares. Voters can trade their shares during the voting period, and different outcomes can have different post-vote token categories — letting the market price in the expected result in real-time.

### Multithreaded Covenants
To avoid "spend races" (where multiple users compete for the same UTXO), contracts can spawn "thread" sub-contracts. Users interact with multiple UTXOs in parallel, and results are batched back to the parent. This allows dApps to scale to millions of users without fee spikes.

### Identity Tokens
NFTs can represent identity — proving control of a persona that can be moved independently of the contracts that verify it. Users can rotate keys or upgrade to multisig without re-creating every contract they interact with.

### DeFi on Bitcoin Cash
The **Cauldron DEX** (built by Riften Labs) is already live, using CashTokens for decentralized swapping and liquidity provision. It uses a micro-pool model where anyone can create a liquidity pool for any token pair, earning 100% of the 0.3% swap fee (Cauldron takes zero platform fees).

## Ecosystem Support

CashTokens received widespread support from the Bitcoin Cash ecosystem:
- **Nodes**: BCHN, Bitcoin Verde, Bitcoin Unlimited, Flowee, Knuth, BCHD
- **Wallets**: Electron Cash, Paytaca, Cashual, Melis, and more
- **Tools**: CashScript, Libauth, Fulcrum, and the FullStack.Cash platform

## The Bottom Line

CashTokens is one of the most underrated innovations in crypto. It brings native tokenization, cross-contract communication, and scalable dApps to Bitcoin Cash — all without sacrificing the simplicity and performance that make BCH unique.

If you're building on Bitcoin Cash, CashTokens is the way to issue tokens. If you're not building on Bitcoin Cash yet, this might be the reason to start.

---

*This post was researched using the [PSF LLM Wiki](https://github.com/FullStack-Agents/psf-llm-wiki) — a knowledge base about Bitcoin Cash technology maintained by the Permissionless Software Foundation.*