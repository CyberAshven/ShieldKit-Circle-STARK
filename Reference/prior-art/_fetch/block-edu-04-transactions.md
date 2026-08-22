---
title: "Transactions"
date: "2026-08-06"
order: 4
description: "How value moves on the Bitcoin Cash network — the anatomy of a transaction, UTXOs, inputs and outputs, fees, and the scripts that unlock your money."
section: "mastering-bitcoin-cash"
source: "mastering-bitcoin-cash"
video: "https://youtu.be/vUJV5C0rukk"
tags: ["Bitcoin Cash", "transactions", "UTXO", "scripts", "fees"]
---

# Transactions

Transactions are the heart of the Bitcoin Cash system. Everything else — the network, the miners, the blockchain — exists to make sure transactions can be created, broadcast, validated, and recorded in the global ledger. A **transaction** is simply a data structure that encodes the transfer of value between participants. Each one is a permanent public entry in Bitcoin Cash's blockchain.

In this lesson we'll look at what a transaction contains, how it moves from your wallet to the ledger, and the clever scripts that make sure only you can spend your money.

## The transaction lifecycle

Every transaction follows the same path through the network:

1. **Creation (origination)** — You (or your wallet) build the transaction, choosing which of your funds to spend and where they should go.
2. **Signing** — The transaction is signed with one or more digital signatures, proving you own the funds being spent.
3. **Broadcasting** — The signed transaction is sent to the Bitcoin Cash network, where nodes validate and relay it to one another.
4. **Mining** — A mining node includes the transaction in a new block.
5. **Confirmation** — Once in a block (and secured by the blocks that follow), the transaction becomes a permanent part of the ledger.

Because transactions are **signed and contain no secret information**, they can be broadcast over almost any transport — WiFi, Bluetooth, NFC, a text message, even a forum post. There's no need for an encrypted channel or a trusted third party. The transaction simply has to reach *any* node, which will validate it and pass it along to its peers in an expanding ripple until it spreads across the whole network.

> **There are no accounts in Bitcoin Cash.** Your "balance" is a derived idea — your wallet scans the blockchain and adds up all the unspent outputs that belong to you.

## How value is recorded: UTXOs

To understand transactions you first need to understand Bitcoin Cash's accounting model, which is built on **unspent transaction outputs**, or **UTXOs**.

A UTXO is an indivisible chunk of Bitcoin Cash locked to a specific owner and recorded on the blockchain. When someone sends you money, that amount is recorded as a new UTXO in your name. Whenever you spend, your wallet *consumes* one or more of your UTXOs in full and creates new UTXOs for the recipients.

Think of UTXOs like physical coins and banknotes. You can't pay a $1.50 bill by cutting a $5 note in half — you hand over a whole note and get change back. The same applies on Bitcoin Cash:

- If you have a **20 BCH** UTXO and want to pay **1 BCH**, you must spend the whole 20 BCH output.
- Your transaction produces two outputs: **1 BCH** to the recipient, and **19 BCH** in *change* back to your own wallet.

As a result, almost every Bitcoin Cash transaction generates change. All of this selection and change-making is done automatically by your wallet — it's invisible unless you're building raw transactions yourself.

The units are **satoshis**: just as a dollar divides into 100 cents, one Bitcoin Cash divides into 100,000,000 satoshis (10⁸). A UTXO can hold any amount measured in satoshis, but once created it's indivisible — it can only be consumed whole.

## Transaction structure

A transaction is a compact bundle of data with a few key fields:

| Field | Purpose |
| :---- | :------ |
| **Version** | Which rules this transaction follows |
| **Inputs** | The UTXOs being spent (the source of funds) |
| **Outputs** | The new UTXOs being created (the destination) |
| **Locktime** | The earliest time the transaction becomes valid |

### Inputs and outputs

- **Inputs** are pointers to specific UTXOs you want to spend, along with an *unlocking script* (usually containing your signature) that proves you own them.
- **Outputs** are the new chunks of value you create, each with an amount in satoshis and a *locking script* that sets the conditions for spending them.

Value flows in a chain: a transaction *consumes* UTXOs as inputs and *creates* UTXOs as outputs, passing ownership from one person to the next.

The one exception is the **coinbase transaction** — the first transaction in every block. It's created by the winning miner with no inputs at all, minting brand-new Bitcoin Cash as a block reward. This is how new BCH enters circulation, per the protocol's predetermined issuance schedule.

### Locktime

The **locktime** field defines the earliest time a transaction is valid. Most transactions set it to zero, meaning "valid immediately." If it's set:

- **Below 500 million**, it's interpreted as a **block height** — the transaction isn't valid until that block is mined.
- **At or above 500 million**, it's interpreted as a **Unix timestamp** — the transaction isn't valid until that time.

This lets you create a *postdated* transaction, much like postdating a paper check. (Time-based locktime is actually measured against the network's *median-time-past* — the median timestamp of the preceding 11 blocks — so it lags the current wall-clock time slightly.)

## Transaction fees

Transaction fees are what compensate miners for securing the network and including your transaction in a block. They also discourage spam by imposing a small cost on every transaction.

Here's the key concept: **there is no "fee" field in a transaction.** A fee is implied — it's the difference between the total value of the inputs and the total value of the outputs:

```
Fees = Sum(Inputs) – Sum(Outputs)
```

Fees are based on the **size of the transaction in bytes**, not its value in BCH. Miners prioritize transactions that pay higher fees, so a transaction with a decent fee is likely to be mined in the next block.

> ⚠️ **Warning:** If you build a transaction manually and forget to add a change output, the "leftover" value becomes the fee — and the miner who mines your transaction collects it! Always account for all your inputs, either by paying them out or returning the excess as change to yourself.

Let's use a concrete example. Alice pays Bob's Cafe **0.00208507 BCH** for coffee and wants a fee of **1 satoshi per byte**. Her wallet selects a **0.00277257 BCH** UTXO. To make the transaction balance, it:

1. **Consumes** the 0.00277257 BCH UTXO as an input.
2. **Creates output 1:** 0.00208507 BCH to Bob's Cafe.
3. **Creates output 2:** 0.00068507 BCH in change back to Alice.
4. Leaves 0.00000243 BCH unallocated — the implicit fee for the miner.

## Transaction scripts

Every output is "locked" with a small program called a **locking script** that sets the conditions for spending it. To spend that output, a transaction input must provide an **unlocking script** that satisfies those conditions.

Bitcoin Cash uses a programming language called **Script** — a simple, stack-based language. It's deliberately limited: no loops, no complex flow control. That's a feature, not a bug. Because every full node validates every transaction, keeping the language simple prevents malicious "logic bombs" or infinite loops from being embedded in a transaction to attack the network.

![Combining the unlocking and locking scripts to evaluate a transaction](/block-blog/images/mastering-bitcoin-cash/msbt_0501.png)

When a transaction is validated, the node executes the unlocking script and the locking script together, using a data structure called a **stack**. Data is *pushed* onto the top of the stack, and operators *pop* values off it and push results back. If the final result is TRUE, the transaction is valid.

![Bitcoin Cash's script validation doing simple math](/block-blog/images/mastering-bitcoin-cash/msbt_0502.png)

For example, the script `2 3 OP_ADD 5 OP_EQUAL` pushes `2` and `3`, adds them with `OP_ADD` (leaving `5`), then checks with `OP_EQUAL` whether that equals the `5` already on the stack. The result is TRUE, so the output is spendable. This is a valid (if unusual!) locking script.

In the most common case, the locking script locks funds to a **Bitcoin Cash address** (which is a hash of a public key). To spend it, you provide an unlocking script containing your signature and public key, and the script verifies they match.

## Standard transaction types

The Bitcoin Cash network recognizes a handful of standard transaction types:

| Type | How it works | Typical use |
| :--- | :--- | :--- |
| **P2PKH** | Locks to a public key *hash* (an address) | Standard payments to an address |
| **P2PK** | Locks to the public key directly | Older; mostly seen in coinbase transactions |
| **Multi-signature** | Requires M-of-N signatures | Shared wallets, escrow |
| **OP_RETURN** | Stores data on-chain | Non-payment data, timestamps |
| **P2SH** | Locks to a script *hash* | Complex spending conditions |

### Pay-to-Public-Key-Hash (P2PKH)

**P2PKH** is by far the most common transaction type. It locks an output to a public key hash — in other words, to a Bitcoin Cash address. When you send someone BCH, you create a P2PKH output locked to their address.

To spend it, the recipient provides their public key and a valid signature from the matching private key. The script checks that the public key hashes to the locked address *and* that the signature is valid.

### OP_RETURN (data output)

The blockchain can carry more than just payments. **OP_RETURN** lets you attach a small amount of arbitrary data to a transaction — up to **220 bytes** (raised from 80 bytes in the May 2018 network upgrade). Applications often use it to record a hash as proof-of-existence of a file, or to add identifying prefixes for token protocols and metadata.

Crucially, an OP_RETURN output is **provably unspendable**. It's marked as data, not as value, so it's never added to the UTXO set and never bloats the set of spendable outputs. It's usually given a zero BCH amount, because any BCH assigned to it would be lost forever.

### Multi-signature (multisig)

A **multi-signature** script requires a certain number of signatures to release the funds. In an **M-of-N** scheme, N public keys are recorded and at least M of them must sign. For example, a **2-of-3** arrangement might have a buyer, seller, and arbitrator — any two can unlock an escrow. Standard multisig scripts support up to **15** public keys.

Multisig is powerful, but a raw multisig script is long and cumbersome to send around. In practice it's almost always wrapped in a P2SH address (see below) so the payer only deals with a short address.

### Pay-to-Script-Hash (P2SH)

**P2SH** ("pay to script hash") solves a real usability problem. Consider a business that requires a **2-of-5 multisig** for all incoming payments. That's a long, complex script. Without P2SH, every customer would need special software to construct it — a terrible experience.

P2SH fixes this by replacing the complex script with a **20-byte cryptographic hash** of that script:

- The **locking script** only contains `OP_HASH160 <hash> OP_EQUAL` — a short, simple "pay to this hash."
- The complex script (called the **redeem script**) isn't revealed until the output is actually *spent*, when the spender presents it alongside their signatures.

The network first verifies the hash of the redeem script matches, then executes the redeem script itself to validate the spend. This shifts the complexity and the fee burden of the long script from the *sender* (at payment time) to the *recipient* (at spending time).

P2SH addresses start with **`p`** in modern CashAddr format (or `3` in the older Base58Check format). To a payer, sending to a P2SH address looks exactly like a normal payment — the complexity is hidden.

> ⚠️ **Warning:** A P2SH locking script contains only a *hash* of the redeem script, which gives no clue about the script's contents. If the redeem script turns out to be invalid, you can permanently lock BCH in a way that can never be spent. The network can't catch this until the spend is attempted.

## Transactions today: signatures and tokens

Three more things are worth knowing about modern Bitcoin Cash transactions:

- **Schnorr signatures.** Bitcoin Cash originally used the older **ECDSA** signature algorithm. Since the **May 2019** network upgrade it also accepts **Schnorr** signatures, which are more efficient, allow multiple keys to be *aggregated* into a single signature, and are used for n-of-n multisig without a dedicated multisig script. Wallets increasingly use Schnorr because it makes transactions smaller and cheaper.

- **CashTokens.** Since the **May 2023** upgrade, Bitcoin Cash transactions can also carry **tokens** — both fungible tokens (like a currency or reward point) and non-fungible tokens (NFTs). Token data is encoded in a special token prefix on the output, alongside the BCH amount and locking script. This means the same transaction machinery that moves BCH can also move native digital assets.

- **SLP tokens.** The **Simple Ledger Protocol (SLP)** is an older, separate token system that predates CashTokens. Instead of being built into the node, SLP tokens are carried in the `OP_RETURN` data field of an ordinary BCH transaction and validated by a separate indexer rather than the full node. This **loose coupling** means SLP can be adapted to other UTXO blockchains (like eCash) and is less exposed to changes in the base protocol. SLP uses its own address prefix — `simpleledger:` — to keep token-bearing outputs from being accidentally spent in a non-token-aware wallet.

  SLP supports both fungible tokens (Type 1) and NFTs (via the **NFT1** spec, which groups child NFTs under a parent Group ID). A common rule of thumb in the ecosystem: **SLP is often preferred for NFTs**, because each NFT is a distinct, individually-identifiable UTXO that's easy to track and trade, while **CashTokens are often preferred for fungible tokens**, because they're validated directly by miners and can't be accidentally burned. Both systems let the same BCH transaction machinery move digital assets — they just take different approaches to how tokens are defined and secured.

## Chains and orphans

Transactions build on each other. A **child** transaction spends the outputs created by its **parent**, forming a chain. When a chain is broadcast, the pieces don't always arrive in order — sometimes the child arrives before its parent.

Instead of rejecting it, a node places the parentless child in a temporary **orphan pool**. When the parent finally arrives, the orphan is released, revalidated, and promoted into the main **mempool** (the pool of valid, unconfirmed transactions waiting to be mined). This ensures valid transactions aren't rejected just because of network propagation delays.

## Wrap up

Let's summarize what makes a Bitcoin Cash transaction work:

1. **UTXOs** — indivisible chunks of BCH locked to owners. You spend them whole and get change back.
2. **Inputs & outputs** — a transaction consumes UTXOs (inputs) and creates new ones (outputs), passing value down a chain.
3. **Fees** — the implicit difference between inputs and outputs, paid to miners, based on transaction size.
4. **Scripts** — locking scripts set the conditions to spend; unlocking scripts (with your signature) satisfy them. Script is a simple, safe stack language.
5. **Standard types** — P2PKH (addresses), multisig, OP_RETURN (data), and P2SH (complex scripts as short hashes).
6. **Modern additions** — Schnorr signatures, CashTokens, and SLP tokens.

Transactions are what turn Bitcoin Cash into *programmable money* — a global, open ledger where value can move from anyone to anyone, secured by cryptography rather than trust.

Ready for the next lesson? Head back to [BCH Education](#/education) to continue.
