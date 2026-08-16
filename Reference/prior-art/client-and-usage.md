# Client and how to use the pool

Short answer: **no GUI**. The first client is a **local desktop CLI**. **One pool, any amount** (see `any-amount-profile.md`). You type how much to deposit or withdraw.

The joint ShieldKit lane freeze (Fv1 = 0.1 ticket) is a size/proof gate with toorik, not the product we are building the CLI around.

- Lane README: `repos/ShieldKit-Circle-STARK/research-lanes/bch-shielded-pool-design/README.md`
- Client envelope: `analysis/design-options.md` item 3
- Product-shaped CLI (different backend): `repos/ShieldKit-SDK`

## What the user actually runs

The pool is not a website and not a hosted mixer. It is:

1. one immutable covenant template (the instance),
2. one serial continuation UTXO that holds `PoolStateFv1` (roots + ticket reserve),
3. a local program that keeps **notes** (the secrets) and builds a standard BCH transaction.

Fv1 commands, conceptually:

| Step | What the CLI does | What the chain sees |
| --- | --- | --- |
| `pool create` (once) | Deploy genesis + empty state cell | New instance, empty note/nullifier roots, reserve 0 |
| `action deposit` | Fund **any** amount, insert one note, save the note locally | reserve += amount, new note root, successor state |
| wait | Nothing. Anonymity is everyone in this one set | Other people's deposits (any size) |
| `action withdraw --to <fresh address>` | Prove membership + unused nullifier; pay **the amount you typed**; change stays as a new note; fee from a separate transparent input | reserve −=, new nullifier (+ change leaf) |

No batching. Private send-to-another-person is the same family but not required to type an amount.

If two withdraw/deposit txs race the same state outpoint, ordinary UTXO rules pick a winner. The loser re-reads the new public roots, rebuilds the proof if needed, and retries. That is why the wallet must reconstruct state from chain, not from a server.

## GUI, mobile, browser

Out of scope for this phase:

- GUI / Tauri / Capacitor
- mobile prover
- browser wasm prove
- required remote proving

Unilateral withdrawal proof target: **&lt; 60 s** on the pinned ordinary desktop.

A later wallet (OPTN, Paytaca, or anything else) can wrap the same CLI or TypeScript SDK. That wrapper is not the pool. Do not start it until Chipnet deposit → withdraw works from the command line.

Voidify's browser + relayer path is prior art for *optional broadcast*, not the Fv1 client.

## Relayer

Optional and non-custodial. It may broadcast **already constructed** transaction bytes. It must not be needed for:

- proving,
- note recovery,
- withdrawal.

Fee privacy and hidden fee sponsorship are also out of scope. The fee input is transparent on purpose.

## ShieldKit-SDK vs this lane

`repos/ShieldKit-SDK` is the toolkit shape we want later (`design list`, `--home`, `action deposit` / `action withdraw`). Today its only money-moving backend is **PF10** on Chipnet, and PF10 still has **transfer**. Fv1 Circle FRI is a different frozen profile: deposit and withdraw only.

Do not treat `npm run shieldkit` PF10 as the Circle-FRI pool. Do not copy PF10 transfer into Fv1.

ShieldKit is a toolkit, not a hosted pool, relay, wallet service, or custodian. Each instance has its own genesis and anonymity set.

## Network

Chipnet only until both sides agree otherwise. Never mainnet in experiments.

## Friendly CLI (yes) vs GUI (still no)

The first client should be **easy to drive**, not a desktop app. Navigation follows OPTN. Home is **one pool**; you type any amount. Full screen map: `cli-ux.md`.

The "button" is a CLI command, for example:

```text
lab demo --wallets 10
```

That is the start switch. Fv1 state is **serial**, so that command is a loop (deposit 1, then 2, … then shuffled withdraws). It is not 10 parallel clicks.

## Nobody else is in the pool — Chipnet lab roster

An instance with one depositor has no anonymity set. You already have Chipnet-faucet-funded seeds. **Import those into the local pool CLI.** That is the intended lab roster.

Default path (your wallets):

1. `wallet import --label w1` … `w10` — you type each Chipnet phrase **in the running CLI** (hidden prompt, not echoed).
2. CLI checks Chipnet only (`bchtest:`). Refuse `bitcoincash:`.
3. `wallet list` shows labels + addresses + balances, never words.
4. `lab demo --wallets w1..w10` deposits from each, then withdraws in shuffled order to **fresh** `bchtest:` addresses.

Generate is only a fallback if you do not already have funded Chipnet identities.

This is a **lab rehearsal**, not real-world anonymity. Local import of Chipnet faucet seeds is fine. Hardcoding those words into source, `.env` in the repo, chat, or `--mnemonic` argv is not.

## How you type a seed (never in this chat)

Same rule as ShieldKit-SDK: **never pass a seed or key on the command line**. Never paste a phrase into the Grok/agent conversation. The agent must not see it.

Allowed:

| How | Use |
| --- | --- |
| Hidden interactive prompt in **your** terminal (`wallet import`) | You type 12/24 words; they are not echoed; they never appear in argv or chat |
| Generate | CLI prints the Chipnet receive address; mnemonic is shown once on the TTY or stored encrypted — agent logs must show addresses only |
| Encrypted file under a home **outside the repo** (`0600`) | Later unlock with a passphrase prompt |

Forbidden:

- `import --mnemonic "word word …"`
- pasting a seed in chat so the agent can "enter it for you"
- committing wallet files
- mainnet

If the agent needs you to import, it starts the local prompt and stops. You type in the terminal. The agent continues from the **address list**, not from the words.

## Command sketch (not implemented yet)

Product / everyday:

```text
pool create
wallet list
action deposit --wallet alice --amount 0.37
action withdraw --wallet alice --amount 0.12 --to <fresh-bchtest>
```

Lab ("the button"):

```text
wallet import --label w1       # hidden prompt; Chipnet phrase you already funded
wallet import --label w2
# …
lab demo --wallets w1..w10     # sequential deposit-all, then shuffled withdraw
lab status                     # who deposited, reserve, last state outpoint
```

`lab wallets generate` remains available if you need extra empty Chipnet identities.

Confirmations stay in the CLI: show full destination address, **the amount you typed**, fee input, then `type yes`. No GUI modal.

Wallet files and the home stay **outside** `D:\Circular-STARKs` (same as ShieldKit: secrets not in the repo). Chipnet only.

## What we will not build now

- A website that is "the pool"
- A GUI as a prerequisite for proving the lane
- A required coordinator or remote prover
- Wallet UI, mobile, or browser wasm
- A mixer CLI that takes seeds as arguments or in chat
