# XO templates (the thing we mean)

Repo: [gitlab.com/GeneralProtocols/xo/templates](https://gitlab.com/GeneralProtocols/xo/templates)  
npm: `@xo-cash/templates`  
Type: `XOTemplate` in [xo/types `source/template.ts`](https://gitlab.com/GeneralProtocols/xo/types/-/blob/development/source/template.ts)  
Invitations: [xo/types `source/invitation.ts`](https://gitlab.com/GeneralProtocols/xo/types/-/blob/development/source/invitation.ts)

A template is **not** CashScript and **not** the XO Engine. It is a **libauth wallet-template-v0 JSON** plus GP fields: roles, start actions, invitations, composable txs, CashASM in `$(…)`, scenarios.

Schema: `https://libauth.org/schemas/wallet-template-v0.schema.json`

**Searched 2026-08-16.** Public blog index, every GitLab branch of `xo/templates`, every `source/*.ts` on those branches, `xo/types` template + invitation types, the whole NIP index, and NIP-EE itself. There is no eighth XO blog and no seventh template file.

There is **no `warp.ts`**. The early extra template is **`wrap.ts`** (wrapped.cash, BCH ↔ wBCH). It is not on `development`. It landed once, on `more_templates`, in the same 2026-05-23 commit as oracles (`143ffbc3` “Add oracles and wrap contracts”). Before that commit the branch only had p2pkh + anyhedge + cauldron + auction.

## What is shipped vs what exists

| Branch | Head | Templates | Status |
| --- | --- | --- | --- |
| **`development` (default, published)** | `aeea85b4` 2026-07-30 | `p2pkh.ts` only (`index.ts` re-exports it) | What `npm i @xo-cash/templates` gives you. Slightly newer than the copy on `more_templates` (59,912 vs 59,710 bytes). |
| **`more_templates`** | `143ffbc3` 2026-05-23 “Add oracles and wrap contracts” | `p2pkh` + `anyhedge` + `cauldron` + `wrap` + `auction` exported; **`oracles.ts` present but not exported** | WIP. This is the useful set. |
| **`anyhedge`** | `9b1e2ca2` 2026-05-15 | `p2pkh` + `anyhedge` | Earlier snapshot |
| **`mr-8`** / **`fix/audit`** | — | not a template set | MR / audit leftovers |

Do not wait for `more_templates` to merge before writing our covenant. Copy the **shape**.

Other branches of this repo do not add more usecases. The rest of the [XO GitLab group](https://gitlab.com/groups/GeneralProtocols/xo) is engine / state / crypto / primitives / types / utils / transports / coordinator-server / invitations / eslint / pipelines — **no extra templates**.

## Shape (every template)

```text
roles → start[] → actions → transactions → inputs/outputs
      → lockingScripts (p2s | p2pkh | p2sh)
      → scripts (CashAssembly)
      → variables / constants / scenarios
```

From `xo/types` `XOTemplate` (development):

- **roles** last for one action (owner, short/long, trader, …).
- **start** = intents that mint an instance (`action` + `role` + optional `generate` / `variables` / `secrets`).
- **actions** name what the wallet shows (fund, mature, deposit, withdraw). Optional `conditions` = CashASM that hides an action until true.
- **transactions** have `inputs` / `outputs` with optional indices. `composable: true` = invitation can add funding inputs. `false` = exact shape.
- **state** on a locking script = which variables/secrets the wallet must remember for that UTXO.
- **privacy** / **selectable** / **balance** = coin-selection and “is this my balance?”
- **defaults.change** = how the engine builds change.
- **scenarios** = happy-path fixtures the engine can fail *before* funds move.
- VM list today includes through `BCH_2026_05`. Locking types: `p2s` / `p2pkh` / `p2sh`.

That is the portable UI: OPTN / CLI / XO wallet all read the same actions.

### Invitation (not a template)

`XOInvitation` is a signed commit chain: `invitationIdentifier` + `templateIdentifier` + `actionIdentifier` + `commits[]` (each commit has `previousCommitIdentifier`, entity, expiry, optional `actionReference`, variables/inputs/outputs, signature) + optional `result` (tx hash / data). Later commits can `mergesWith` an earlier item (e.g. add `unlockingBytecode` without replacing the commit).

This is how two wallets finish one action. Transport is unspecified (file, QR, or the **Nostr event bus** — same job as a Solana program listener; already proven on OPTN P2P CashFusion). Local Chipnet rehearsal can stay in-process. Cross-machine gather uses Nostr, not a new custom socket.

## Public XO blog (complete)

Index: [stack.xo.cash/blog](https://stack.xo.cash/blog/). **Exactly seven posts.** VitePress; bodies live in `/assets/chunks/<slug>.….js`. No sitemap. No eighth article as of 2026-08-16.

| Date | Title | Author | What it actually says |
| --- | --- | --- | --- |
| 2025-10-15 | [Intro to XO: The Why and the What](https://stack.xo.cash/blog/2025-10-15-Intro-to-XO-The-Why-and-the-What.html) | John Moriarty | Wallet-Connect-style “sign this blob” is unsafe: the wallet cannot verify the dapp. Losing **state** (oracle, leverage, payouts) can lose funds. **Templates** describe participants, actions, state, and human text. Trust moves from *every frontend* to *the template once*. Engine interprets templates so apps do not reimplement wallets. |
| 2025-10-16 | [Vision to Reality: P2PKH Fungible Token Request](https://stack.xo.cash/blog/2025-10-16-Vision-to-Reality-P2PKH-Fungible-Token-Request.html) | Jonathan Silverblood | Worked example: request 100.00 MUSD. Engine + template + invitation. CashASM: `$(…)` evaluates, `<x>` pushes. Identity is derived from root entropy. Mindmap used in every later V2R post: invitations connect, templates describe, engine generates/manages. |
| 2025-10-30 | [Vision to Reality 2: Managing State and Ownership](https://stack.xo.cash/blog/2025-10-30-Vision-to-Reality-2-Managing-State-and-Ownership.html) | Jonathan Silverblood | After broadcast, engine binds the UTXO to template + action + variables. `ownerKey` must be stored as a **secret** on the locking script. Unknown activity (airdrop, dust) uses the lockscript’s own name/description. `balance` / `selectable` / `privacy`. Sign/verify messages on P2PKH. |
| 2025-12-15 | [Vision to Reality 3: Template Updates](https://stack.xo.cash/blog/2025-12-15-Vision-to-Reality-3-Template-Updates.html) | Jonathan Silverblood | `omitChangeAmounts` for burns. **Intents** on start + follow-up actions. Role-specific names/descriptions. Slot min/max (fundraisers). Explicit `generate: ['ownerKey']`. Explicit tx input/output order (composition still unfinished). **Scenarios** as pre-fund tests. |
| 2025-12-20 | [What Makes the XO Wallet Different](https://stack.xo.cash/blog/2025-12-20-What-Makes-the-XO-Wallet-Different.html) | Saqib Noor | Product: wallet understands **intent**, not just bytes. “Trust the template once, not every website.” Not a template file. |
| 2026-08-05 | [Vision to Reality 4: Revving the Engine](https://stack.xo.cash/blog/2026-08-05-Vision-to-Reality-4-Revving-The-Engine.html) | Jonathan Silverblood | Blaze hackathon **Nov 2026**. Planned: concepts / best-practices / tools articles; **alpha CLI or TUI wallet**; alpha graphical debug tool. Token support still limited (balance estimates defined, unused). Rename lockingScript vs lockingBytecode; add `unlockingScripts`. Explicit **default outputs**. Events instead of poll. Docs. New primitives: Satoshis, Transaction Hash, **extended public keys** (no key reuse on invitation steps), Timestamps. Per-seed isolated DB. Invitation import/export. Template validation. Application + engine state. Keep polishing P2PKH. |
| 2026-08-12 | [Vision to Reality 5: Conceptualizing the Future](https://stack.xo.cash/blog/2026-08-12-Vision-to-Reality-5-Conceptualizing-The-Future.html) | Jonathan Silverblood | Concept glossary (table below). **Composition is not implemented**; default will be off. |

V2R4 promised more articles (high-level concepts, template best practices, tools/limits). Those are **not published yet**. V2R5 is the concepts article.

### V2R5 words

| Word | Meaning |
| --- | --- |
| **Origins** | New data only via template instructions: `generate`, provided `variables`/`secrets`, or user-filled requirements |
| **Intent** | Request to produce a tx / output / lock. `generate` / `variables` / `secrets` say where data comes from |
| **Action** | Something a user can do; usually one broadcast tx |
| **State** | Lives on the **output**, not a global wallet dump. After spend it is archived. Templated / engine / app state |
| **Invitation** | Incomplete action; parties commit until it can execute. Commits expire |
| **Reservation** | Local lock on a UTXO so this engine does not double-commit. **Not** a chain guarantee |
| **Eventual consistency** | Pending by default; same seed on two engines will catch up |
| **Discovery** | Watch lockscripts; unknown activity gets tagged later |
| **Sync / backup** | BIP-39 recovers the account; encrypted state replicates. **Private keys are not synced** — only derivation info. Engine refuses to run without enough replica storage |
| **Account** | One root entropy (not “wallet”) |
| **Composition** | Many actions in one tx. **Not implemented.** Default will be off |

BCH’s job is UTXOs + locking scripts. Templates describe that. Engine generates keys/invites/txs and stores secrets. Invitations connect apps, wallets, users.

## Templates on `more_templates`

### P2PKH (`p2pkh.ts`) — published (`development`)

Export: `p2pkhTemplate`. Name: “Wallet (P2PKH)”. Version `1`. Lock: `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`. Dust 546.

Roles: owner / receiver / sender (one action only).

Start: receive; request sats / FT / NFT (receiver generates `ownerKey`).

Actions:

| Action | Transaction / data | Composable |
| --- | --- | --- |
| `receive` | unspecified cash/tokens | yes |
| `requestSatoshis` | exact sats | yes |
| `requestFungibleTokens` | category + amount | yes |
| `requestNonfungibleTokens` | category + capability + commitment | yes |
| `sendSatoshis` | condition: UTXO value > dust | yes |
| `sendFungibleTokens` | condition: token amount > 0 | yes |
| `sendNonfungibleTokens` | condition: token category size > 32 | yes |
| `burnFungibleTokens` / `burnNonfungibleTokens` | `omitChangeAmounts`; no required outputs | yes |
| `sign` / `verify` | **data**, not a tx (`OP_CHECKDATASIG` + Bitcoin message prefix) | — |

`receivingLockingScript` is selectable + counts in balance; `sendingLockingscript` is not (external recipient). One scenario: request 2000 sats.

`development` is the copy to cite. `more_templates` is the same template a few weeks older.

### AnyHedge v0.12 (`anyhedge.ts`)

Roles: **short** / **long**. Start: `fund` as short (generates `contractIdentifier`).

Actions: **fund**, **mature**, **liquidate**, **redeem** (mutual, both sign).

Composable: funding **true**; mature/liquidate **false** (exact two payouts); mutual redeem **true**.

Lock: **P2SH**. Bytecode from AnyHedge `contracts/v0.12`. Unlock path 0 = mutual, 1 = oracle settlement (`OP_CHECKDATASIG`).

State on the funded UTXO: oracle key, nominal units, liquidation prices, maturity, payout scripts, mutual-redeem keys.

Closest pattern to a **two-party** contract with coop exit. We do **not** need their oracle.

### Cauldron (`cauldron.ts`)

Roles: LP / trader. Start: `createPool` as LP (generates `ownerKey`).

Actions: **createPool**, **tradeBchForTokens** (“Buy Tokens”), **tradeTokensForBch** (“Sell Tokens”), **withdraw**.

Composable: create + both trades **true**; withdraw **false**.

Lock: **P2S** pool. Empty unlock = trade (`OP_DEPTH = 0`); sig+pk = withdraw. Payouts can be P2PKH.

On-chain: same-index output keeps bytecode + category; `K = bch * tokens` with ~0.3% fee.

Steal: path select by stack depth; **same-index self-replicate** (`OUTPUTBYTECODE == UTXOBYTECODE`). That is how a serial pool state UTXO should look.

### Wrap BCH (`wrap.ts`) — early extra template (not `warp.ts`)

This is the early GP experiment besides P2PKH / AnyHedge / Cauldron. It encodes [wrapped.cash](https://wrapped.cash/) as an XO template. **Never merged to `development`.** Two drafts exist:

**1. GitLab `more_templates/source/wrap.ts`** (6,057 bytes, export `wrapBCHTemplate`)

- One **user** role. Start: `wrap` / `unwrap`. Both txs composable. Lock **P2SH**.
- Three CashASM checks: persist bytecode, persist category, conserve `value + tokenAmount`.
- Pinned category: `ff4d6e4b90aa8158d39c5dc874fd9411af1ac3b5ed6f354755e8362a0d02c6b3`. Token dust 1000.

**2. Local `Reference/wrap.ts`** (later unpublished draft, not on GitLab)

- Roles **wrapper** / **unwrapper** / **service**. `start: []` — comment says the engine cannot see covenant UTXOs so it cannot initiate wrap/unwrap.
- Same three conservation scripts. Unlock is `<wrapBCHLockingBytecode>` (P2SH redeem). Bootstrap ceremony is *not* in the template; only the final category is.
- Notes: “this covenant only ensure the security of its own funds, leaving user protection to be done in user space.” `relevant: false` for wrapper/unwrapper on the covenant lock so users do not index the pool UTXO as theirs.

Steal: tiny conservation covenant. We would pin **our** category, not theirs. The later draft is closer to a serial pool (service holds the UTXO; user is a guest action).

### Auction (`auction.ts`) — exported, still `version: '0'`

`TemplateNFTAuction`. Roles: seller / bidder / buyer / winner. Start: `create` as seller.

Actions: **create**, **placeBid**, **buyItNow**, **claimAfterEnd**, **sweepExcessToSeller**. All five txs marked composable.

Three input paths: bid / final / recovery. Seller locks an **immutable NFT** + initial bid. Min/max bid increment % and outbid bonus % are constants. After end, anyone can claim: winner gets NFT, seller gets BCH. `sweepExcessToSeller` is the malformed-UTXO recovery path.

Lock: **P2SH**. Learning example, not an audit artifact.

### Oracles (`oracles.ts`) — **not exported**, draft

`TemplateSimplifiedOracle`. `version: '0'`. **`BCH_2026_05` only**. Role: operator.

Actions: **initializeOracle** (mint state NFT + attestation NFT), **attest**.

Lock: **P2S**. State token = mutable NFT commitment: prefix(1) + HASH160 root(20) + seq(4) + ts(4) + latest leaf data. Attestation token authorizes the operator. Merkle continuation uses **`OP_BEGIN` / `OP_UNTIL`**, HASH160 leaves, direction bits.

This file does **not** typecheck as written:

- `type: integer` is unquoted (invalid TS) on `leafHashSize` / `minimumStateSize`
- lockscript field is `lockingScript` not `lockingBytecode`
- `importDefaultValue` / `templates:` import hash are not the current `XOTemplate` shape
- TODOs on genesis category / passing `oracleCategory`

Do not copy it onto Chipnet. Useful only as a sketch of **mutable NFT state + merkle history**.

## NIP-EE is not an XO template

[nips.nostr.com/EE](https://nips.nostr.com/EE) is **MLS E2EE** group/DMs on Nostr (kinds 443 KeyPackage, 444 Welcome, 445 Group). Marked **unrecommended**; superseded by [Marmot](https://github.com/marmot-protocol/marmot). The NIP index now lists those kinds under Marmot.

Related NIPs (encryption lineage, not templates): NIP-04 (deprecated DMs), NIP-17 (gift-wrapped DMs), NIP-44 (payloads), NIP-59 (gift wrap), NIP-70 (protected events).

Searched the **full NIP list** (01–F4). Nothing there is an XO / libauth wallet template. Nearby-looking items that are still not XO:

- NIP-47 Nostr Wallet Connect, NIP-60 Cashu wallet — other wallet protocols
- kind `2022` Coinjoin Pool ([joinstr](https://gitlab.com/1440000bytes/joinstr)) — not GP, not our pool

NIP-EE is only a possible **ciphertext** for invitations (and is already superseded). Do not treat it as `p2pkh.ts`.

The useful Nostr layer is **not** NIP-EE. It is the NIP-01 listener + gift-wrap mailbox that replaced a fusion server. See `cashfusion-nostr-lessons.md`.

## What we would write

A **Shielded pool** `XOTemplate` (later, Chipnet):

| Action | Like |
| --- | --- |
| `deposit` | Cauldron `createPool` / wrap — one user, any amount, composable fee input |
| `withdraw` | wrap `unwrap` — prove + payout; leftover change note |
| `rehearse` | not on-chain; CLI only |

Locking script = our CashScript/P2S verifier, not P2PKH. Template only **names** the actions and tx shape. Proof stays a plugin.

Steal from this search:

- P2PKH action list + conditions + scenarios as the portable CLI/OPTN surface
- Cauldron same-index self-replicate
- Wrap three-point conservation (we already require the KB five-point check)
- AnyHedge versioned artifact + mutual/coop exit *shape*
- Invitation commit chain **later**, if two wallets must finish one withdraw
- V2R3 `omitChangeAmounts` if burn/partial-withdraw change is messy

## Do not

- Depend on XO Engine to run the template
- Treat `more_templates` as audited (auction v0, oracles does not compile)
- Put AnyHedge oracle settlement into the mixer
- Confuse Cauldron (AMM micro-pool) with our **shielded** pool
- Treat NIP-EE / Marmot / NIP-47 / Cashu as XO templates
- Sync private keys the XO way *from this chat* — seeds stay in the local CLI
- Wait for V2R4’s unpublished “best practices” / Blaze CLI before writing CashScript
