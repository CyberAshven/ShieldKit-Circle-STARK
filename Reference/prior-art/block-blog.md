# Prior art: Block blog (FullStack-Agents)

Live:

- Education: https://fullstack-agents.github.io/block-blog/#/education
- Ask: https://fullstack-agents.github.io/block-blog/#/ask
- Source: https://github.com/FullStack-Agents/block-blog
- Local clone: `repos/block-blog`

This is Block’s BCH education site (Vite + React, markdown in-repo). It is **not** a STARK paper. Use it as a CashScript / UTXO / CashTokens primer next to toorik’s `BCH_Knowledge_Base`.

## Education track (`education/`)

| File | Topic |
| --- | --- |
| `01-what-is-bitcoin-cash.md` | BCH intro |
| `02-how-bitcoin-cash-works.md` | UTXO mental model |
| `03-keys-addresses-wallets.md` | keys |
| `04-transactions.md` | tx anatomy |
| `05-the-bitcoin-cash-network.md` | p2p / nodes |
| `06-the-blockchain.md` | chain |
| `07-javascript-introduction.md` | JS for wallets |
| `08-keys-addresses-receiving-bch.md` | receive |
| `09-send-bch.md` | send |

## Posts that matter to this repo

- `2026-07-31-smart-contracts-bitcoin-cash.md` — **Layla (2026-05-15)**: `OP_BEGIN`/`OP_UNTIL`, `OP_DEFINE`/`OP_INVOKE`, P2S standard, **128-byte** token commitments, 10 KB unlocking. This is why FRI loops and `PoolStateFv1` are even possible.
- `2026-07-12-cashtokens-intro.md` / `2026-08-04-cashtokens-points-tickets-you-own.md` — native tokens / commitments
- `2026-08-02-nostr-social-media-you-own.md` — Nostr as a user-owned bus (discovery, not custody)
- `2026-08-09-cauldron-defi-bitcoin-cash.md` — live CashScript DeFi

`#/ask` is the site’s Q&A surface over the same corpus. Prefer the markdown source in the clone over scraping the hash-router.

## How it sits next to toorik’s knowledge base

| | Block blog | `BCH_Knowledge_Base` |
| --- | --- | --- |
| Audience | builders + users, narrative | agent/dev reference |
| CashScript depth | survey | language + FAQ + security |
| Use when | explaining UTXO/Layla to ourselves | writing actual redeem scripts |

Both are design-section literacy. Neither selects a proof family.

Same org also maintains [psf-llm-wiki](psf-llm-wiki.md) — denser interlinked CashScript/CashTokens pages. Use the wiki for specs; use this blog for Layla narrative (newer than the wiki’s 2026-05-25 index).
