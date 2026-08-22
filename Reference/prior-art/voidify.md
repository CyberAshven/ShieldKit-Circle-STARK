# Prior art: Voidify (Nova + Classic Groth16 on Solana)

Official hub (2026-08-16): **https://linktr.ee/VoidifyCommunity**

That Linktree is the complete public index. Docs live at **https://voidifycto.gitbook.io/whitepaper** (same 13 chapters as `VoidifyDAO/voidify-gitbook`, with `llms.txt`). Markdown: append `.md` to a chapter URL.

| Linktree label | URL | Use for us |
| --- | --- | --- |
| Documentation | https://voidifycto.gitbook.io/whitepaper | Product + mechanism + ceremony |
| Docs index (agents) | https://voidifycto.gitbook.io/whitepaper/llms.txt | Chapter list |
| Launch App | https://voidifycto.eth.limo/ | ENS/IPFS frontend (not protocol) |
| Deposit & Withdrawal data | https://dune.com/voidify/voidify-privacy | Live set size / volume — study, not copy |
| Medium | https://medium.com/@voidify | Announcements |
| GitHub org | https://github.com/VoidifyCommunity | Code |
| Token / chart / CG | Jupiter / Dexscreener / CoinGecko | Token, ignore for BCH design |

GitHub (already cloned or fetched):

- https://github.com/VoidifyCommunity/voidify-smart-contract-audit
- https://github.com/VoidifyCommunity/voidify-sdk
- https://github.com/VoidifyCommunity/voidify-relayer
- https://github.com/VoidifyCommunity/voidify-ceremony-frontend
- https://github.com/VoidifyCommunity/voidify-ceremony-verifier-frontend
- https://github.com/VoidifyCommunity/voidify-ceremony-record
- https://github.com/VoidifyDAO/voidify-gitbook
- Local: `repos/voidify-gitbook`, `repos/voidify-ceremony-frontend`, `repos/voidify-smart-contract-audit`
- Dumps: `Reference/prior-art/_fetch/voidify-*.md`

GitBook chapters (I–XIII): Premise, Mechanism, Nova, Fees, Deposit/Withdraw, Relayers, Substream, Compliance tool, Stake, Governance, Trust setup, Stay Shadowed, Conclusion. **Steal I–III, V–VI, XI.** Leave IV/VII–X/XII as Solana-token product.

## Two products, two circuits, one brand

| | Classic | Nova |
| --- | --- | --- |
| Amounts | Fixed denomination pools | Flexible amounts, partial withdraw |
| Private state | One note per deposit (secret + nullifier) | Rolling encrypted balance / replacement output |
| Access | Saved note | Wallet signature ± passphrase |
| Circuit | `withdraw` | `transaction2` |
| Groth16 public inputs | 8 | 5 |
| Ceremony | separate Phase 2 | separate Phase 2 |

Both: browser proves, Solana program verifies, nullifier stops double-spend, relayer is optional broadcast. Trusted setups are **not interchangeable**. wasm / zkey / on-chain vk must be the same build.

That is the plugin lesson: same design family (privacy pool), two ZKP artifacts.

## On-chain program (studied 2026-08-16)

Clone: `repos/voidify-smart-contract-audit`  
Program: `4WJnXP7mFxFY45SYvfyGDwEBdcwafVqdgbYYSHpoded4`  
Audit: HashCloak, source pin `2d0f9b9e22a3741f100afa1414f1c084066addf3`

Verified in Rust, not just docs:

- Classic pool: fixed `denomination` + Poseidon Merkle **depth 20** (`state/classic/pool.rs`)
- Nova pool: Poseidon Merkle **depth 26**, **100** recent roots (`state/nova/pool.rs`)
- Nova public inputs (`utils/nova/proof.rs`): `root`, `public_amount`, `ext_data_hash`, `input_nullifier`, `output_commitment` — **5** inputs
- Proof bytes: **256** (`G1 64 || G2 128 || G1 64`), `Groth16Verifier` from `groth16_solana`, vk `nr_pubinputs: 5`
- Nullifiers are **Solana PDAs**, not a Merkle root (account-model)
- Relayer is a signer; cannot change `ext_data` without breaking the proof
- Same program also has DAO, treasury, oracle, stake, substream — Fv1 should not copy that surface

Org: https://github.com/VoidifyCommunity (relayer, sdk, ceremony, ceremony-record, ceremony-verifier, smart-contract-audit)

## How they embed the verifier (user-reported sizes; now matches source)

Voidify’s Groth16 verifier is **statically linked into the core Solana program**, not a separate verifier program.

User-reported measurements (not re-weighed in this workspace):

- Core ELF ≈ **1.17 MiB** — protocol logic + verifier, not verifier alone
- Embedded raw VK: **832 B** Nova (5 public inputs) + **1024 B** Classic (8 public inputs) = **1856 B**
- Each Groth16 proof: **256 B** (BN254 compressed triple)

On Solana that is rational: pairings exist, proofs are tiny, program size is cheap relative to compute. On BCH the same *architecture* (covenant contains `Verify`) is right; the same *family* (Groth16/BN254) is wrong until pairings are cheap. 256 B proofs are why people pick SNARKs. Our 100 KB budget is for a hash STARK that does not need a ceremony.

Ceremony property they document correctly: Phase 2 is safe if **one** contributor was honest and erased entropy. Beacon = future BTC block. VK change = on-chain redeploy, no silent off-chain switch.

## Classic mechanism (Tornado-shaped)

From gitbook II:

- Note = (secret, nullifier)
- Commitment = Poseidon(secret, nullifier)
- Commitment inserted in on-chain Merkle tree
- Withdraw proves membership + unused nullifier, same denomination

Anonymity set is **per denomination**. Timing still leaks.

## Nova mechanism (not Tornado)

- First deposit creates a private output
- Later deposit spends it and writes old+new amount
- Withdraw spends it, pays public destination minus fees, writes remainder
- Proof: input exists, belongs to user, unspent, conservation — without revealing *which* commitment

UX win: no wait for a matching denomination. Privacy loss: unusual amounts and timing still correlate. Fv1 staying fixed-ticket is the conservative ShieldKit choice; Nova is a **later design-section profile**, not a reason to abandon Circle FRI.

## Relayer / SDK

- Client-side prove in the browser (IndexedDB, wasm+zkey hosted by the app)
- Relayer submits withdrawals; cannot spend without the user key
- Do not log `result.note`
- Unlock message “Voidify Nova account sign in” is off-chain; phishing that message is a theft path

## What we take / leave

Take: two circuits as two plugins; vk pinned on chain; client prove; relayer non-custodial; Classic vs flexible-amount as *profiles*; ceremony hygiene if we ever ship Groth16.

Leave: Poseidon-in-the-design-section as mandatory; trusted setup as default; Solana ELF size as a BCH budget; static-link meaning “only Groth16 forever.”
