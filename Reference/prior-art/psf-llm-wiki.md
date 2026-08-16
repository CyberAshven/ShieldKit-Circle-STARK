# Prior art: PSF LLM Wiki

Yes — keep it as a **BCH / Cash Stack / CashScript** reference. It is not a STARK or pool-protocol source.

- https://github.com/FullStack-Agents/psf-llm-wiki
- Local: `repos/psf-llm-wiki` (125 wiki pages, index last updated 2026-05-25)
- Same org as Block blog (`FullStack-Agents`)

Karpathy-style LLM wiki for Bitcoin Cash, the Permissionless Software Foundation, and the [Cash Stack](https://cashstack.info). Start at `wiki/index.md`. Agent rules: `AGENTS.md`.

## Use it for

| Pages | Why we care |
| --- | --- |
| `utxo.md`, `transaction-anatomy.md`, `locking-script.md`, `p2sh.md` | UTXO-native pool mental model |
| `cashtokens.md`, `cashtokens-spec.md`, `cashtokens-intro.md` | NFT commitment / category = our state cell |
| `token-examples.md` | covenant tracking, depository child covenants, multithreaded covenants |
| `cashscript-language.md`, `cashscript-sdk.md`, `cashscript-faq.md` | writing verifier/covenant code |
| `cashscript-multi-contract.md` | Main+sidecar, input-position pinning — same shape as a multi-input FRI verifier |
| `cashscript-security.md` | 5-point covenant checks, output limiting |
| `network-level-validation-rules.md`, `standard-transaction-types.md` | 100 KB / standardness vs consensus |
| `sha-256.md`, `hash.md`, `merkle-tree.md` | chain-native hash we want in Circle FRI |
| `bcmr-spec.md` | token metadata, not pool state |

## Do not use it for

- Circle FRI, Stwo, Groth16, Voidify, Aztec notes
- Proof sizes or soundness
- Treating `bch-js` / PSF JS stack as our language policy (we write **TypeScript**, CashScript, or Rust)

It sits next to `BCH_Knowledge_Base` (toorik, more CashScript-faq-from-Telegram) and `block-blog` (narrative Layla posts). The wiki is denser and interlinked; the blog is newer on Layla (July 2026 posts). If they disagree, prefer current CHIPs / libauth / toorik KB for contract facts, and this wiki for Cash Stack + CashTokens spec literacy.

## How to query

1. Read `repos/psf-llm-wiki/wiki/index.md`
2. Open the matching pages
3. File durable pool/FRI facts in *our* `Reference/prior-art/`, not back into their wiki
