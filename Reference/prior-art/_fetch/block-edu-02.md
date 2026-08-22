---
title: "How Bitcoin Cash Works"
date: "2026-08-05"
order: 2
description: "How value moves on Bitcoin Cash — the lifecycle of a transaction from your wallet to the blockchain, and how mining, blocks, and confirmations keep the ledger secure."
section: "mastering-bitcoin-cash"
source: "mastering-bitcoin-cash"
video: "https://youtu.be/YBWd602Lf58"
tags: ["Bitcoin Cash", "transactions", "blockchain", "mining", "blocks"]
---

# How Bitcoin Cash Works

Bitcoin Cash, unlike traditional banking, is based on **decentralized trust**. There is no central authority that decides who owns what. Instead, trust emerges from the interactions of many independent participants spread across the world. This lesson tracks a single payment from start to finish — from a wallet, across the peer-to-peer network, into a block, and finally into the permanent public ledger called the **blockchain**.

To follow along, we use a **blockchain explorer** — a web app that works like a search engine for Bitcoin Cash. You can search for addresses, transactions, and blocks, and see how value flows between them.

![Bitcoin Cash overview](/block-blog/images/mastering-bitcoin-cash/msbt_0201.png)

The diagram above shows the whole system at a glance: users hold wallets containing keys, transactions propagate across the network, and miners compete (through computation) to produce the **consensus blockchain** — the authoritative ledger of all transactions.

## A transaction from start to finish

Let's watch a real payment travel through the system. Alice, a new user, received some Bitcoin Cash from her friend Joe in exchange for cash. Now she's making her first retail purchase: a cup of coffee at Bob's cafe.

Bob's register accepts Bitcoin Cash. When Alice places her order, the point-of-sale system converts the price from US dollars to Bitcoin Cash at the current market rate and shows a **payment request** as a QR code:

```
Total:
    $1.50 USD
    0.00208507 BCH
```

Alice scans the QR code with her phone. Her wallet shows the payment amount, she taps **Send**, and within a few seconds — about the same time as a credit-card authorization — Bob's register shows the transaction as received. In the sections below we unpack exactly what happened under the hood.

## What is a transaction?

In simple terms, a **transaction** tells the network that the owner of some Bitcoin Cash has authorized the transfer of part (or all) of it to another owner. The new owner can then spend it by creating another transaction, and so on, forming a **chain of ownership**.

A transaction looks like a line in a double-entry bookkeeping ledger:

- **Inputs** are debits — where the value is coming from.
- **Outputs** are credits — where the value is going.

![Transaction as double-entry bookkeeping](/block-blog/images/mastering-bitcoin-cash/transaction-as-double-entry-bookkepping.png)

The inputs and outputs don't have to add up to the same amount. Outputs add up to *slightly less* than inputs, and the difference is the **transaction fee** — a small payment collected by the miner who includes the transaction in a block.

Each input must carry proof of ownership: a **digital signature** from the owner, which anyone can independently verify. "Spending" in Bitcoin Cash simply means signing a transaction that transfers value from a previous transaction to a new owner.

### UTXOs: the building blocks of value

There are no "account balances" in Bitcoin Cash. Instead, value lives in discrete chunks called **unspent transaction outputs**, or **UTXOs** (pronounced "utx-ohs"). Your balance is simply the sum of all the UTXOs that your keys can unlock.

When you spend, a UTXO must be consumed **in its entirety**. If it's worth more than you're paying, the wallet sends the leftover back to you as **change** — as a new output in the same transaction. This is why a simple payment usually has one input and two outputs: one to the recipient, one back to yourself.

![The most common transaction: one input, two outputs](/block-blog/images/mastering-bitcoin-cash/msbt_0205.png)

There are a few other common transaction shapes:

- **Aggregating** — several inputs combined into a single output, like exchanging a pile of coins for one larger note. Wallets use this to clean up many small change outputs.
- **Distributing** — one input split among several recipients, useful for payroll or revenue splits.

![Transaction aggregating funds](/block-blog/images/mastering-bitcoin-cash/msbt_0206.png)

![Transaction distributing funds](/block-blog/images/mastering-bitcoin-cash/msbt_0207.png)

Because each output of one transaction can become the input of the next, value chains together from owner to owner. The diagram below shows how Joe's payment to Alice becomes the input Alice uses to pay Bob, and so on.

![A chain of transactions](/block-blog/images/mastering-bitcoin-cash/chain-of-transactions.png)

## Building a transaction

Alice's wallet does all the heavy lifting of constructing a transaction. She only specifies a destination and an amount; the wallet selects the inputs, creates the outputs, and handles the change.

A key detail: **a wallet can construct and sign a transaction even while completely offline.** Like writing a check at home and mailing it later, the transaction only needs to be sent to the network when it's time to execute.

To find inputs, the wallet looks up the UTXOs it controls. Full-index clients keep a copy of every unspent output on the whole blockchain; lightweight clients track only the user's own outputs, or query the network for this information via a public API. Once the wallet finds an input worth enough, it splits it into the payment plus change, adds a small fee, and signs it.

![The chain of value from Joe to Alice to Bob and beyond](/block-blog/images/mastering-bitcoin-cash/msbt_0210.png)

## Broadcasting to the network

Once signed, the transaction is sent to the peer-to-peer network. Because a transaction contains everything needed to process it, it doesn't matter *how* or *where* it's transmitted — wired, Wi-Fi, or mobile.

Each node that receives a valid transaction it hasn't seen before immediately forwards it to its peers. This "flooding" approach spreads the transaction across the network within seconds. When it reaches Bob's wallet, the wallet recognizes it as an incoming payment (it contains outputs Bob's keys can unlock), verifies it is well-formed and uses previously unspent inputs, and Bob can safely accept it.

> **A common misconception:** transactions don't have to wait for "confirmation" to be useful. Confirmations do make a payment irreversible, but for small-value purchases like a cup of coffee, a merchant can safely accept a **zero-confirmation** transaction with no more risk than a credit-card payment taken without a signature.

Before a transaction is confirmed, it sits in a temporary pool called the **mempool** on each node, waiting for a miner to include it in a block.

## Mining and blocks

A transaction only becomes part of the permanent ledger when a miner includes it in a **block** through a process called **mining**. Mining serves two purposes:

- It **creates new Bitcoin Cash** — each block mints a fixed, diminishing block reward.
- It **builds trust** — a transaction is only "official" once enough computational work has secured the block containing it.

Mining is often described like a giant, competitive sudoku that resets every time someone finds a solution. Solving it requires enormous computation, but verifying a solution is easy. The "puzzle" is based on a cryptographic hash: miners repeatedly hash the block header, tweaking a number called the **nonce**, until the resulting hash falls below a target value — a **proof-of-work**. The first miner to find a valid solution publishes the block and claims the reward.

Today mining is done with specialized hardware called **ASICs**. Most miners join **mining pools**, which combine the hashing power of many participants and share the rewards proportionally — like a lottery pool.

### Blocks are built for miners

When a miner assembles a block, it includes a special first transaction called the **coinbase transaction**. Unlike a normal transaction, the coinbase has no inputs; it creates new value from two sources:

1. The **block reward** — new Bitcoin Cash created by the protocol.
2. The **transaction fees** of the transactions in the block.

The block reward doesn't stay constant. It **halves every 210,000 blocks** (roughly every four years). It began at **50 BCH** per block and, as of the 2024 halving, stands at **3.125 BCH** per block. The total supply is capped at **21 million BCH**, which the issuance schedule projects to reach around the year 2140.

Miners prioritize the highest-fee transactions first, which is why a reasonable fee helps your payment get picked up quickly. Bitcoin Cash blocks can hold far more transactions than the original Bitcoin design — up to **32 MB** — which keeps fees tiny and the network usable even during busy periods.

## Confirmations and trust

When Alice's transaction is included in a block and that block is published, the transaction receives its **first confirmation**. Each new block mined on top of it adds another confirmation.

![The block containing the transaction, with more blocks piled on top](/block-blog/images/mastering-bitcoin-cash/msbt_0201.png)

Each block links to the one before it, forming an unbroken chain back to the **genesis block** (block #0). To reverse a transaction, an attacker would have to redo all the proof-of-work for the block containing it *and* every block on top — an exponentially more expensive task as blocks pile up. By convention, a transaction with **six or more confirmations** is considered irrevocable.

## Spending the received funds

Now that Alice's payment is embedded in the blockchain, Bob can spend it just like she did. He creates his own transaction referencing the UTXO as an input, assigning it to a new owner — say, a contractor or supplier. Most businesses aggregate the day's many small payments into one larger output, concentrating revenue into a single "checking" address.

Every new transaction extends the chain, and each gets added to the global ledger for all to see and verify. Anyone can independently audit the history of any address using a **blockchain explorer** — a level of transparency and accountability that no traditional financial system offers.

## Wrap up

A Bitcoin Cash payment is a chain of verifiable, cryptographic events:

1. **Construct** — your wallet picks inputs (UTXOs), creates outputs plus change, and signs with your private key.
2. **Broadcast** — the signed transaction floods across the peer-to-peer network.
3. **Confirm** — a miner bundles it into a block secured by proof-of-work; each new block strengthens the trust in it.
4. **Spend** — the recipient uses that output as the input to their own future transaction, continuing the chain.

There is no bank, no clearinghouse, and no trusted middleman. Trust comes from the mathematics of the blockchain. Now that you understand how the machinery works, you're ready for the practical side: making your first payment.

Ready for the next lesson? Head back to [BCH Education](#/education) to continue.
