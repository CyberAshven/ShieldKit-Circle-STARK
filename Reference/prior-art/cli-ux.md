# Pool CLI UX (OPTN-shaped, still a terminal)

The client is a **navigable local program**, not a flag dump and not a GUI. Steal OPTN's *information architecture and trust rules*. Do not copy OPTN branding, screens, or source.

Sources used:

- `D:\OPTNWallet-Desktop\.claude\skills\ui-ux-product\SKILL.md`
- `D:\OPTNWallet-Desktop\docs\UX_IMPROVEMENT_PLAN.md`
- `C:\Users\asus\.agents\skills\wallet-ui-ux-product\SKILL.md`
- `C:\Users\asus\.agents\skills\wallet-ux-patterns\SKILL.md`

## Understanding

A pool CLI that only exposes `action deposit --wallet …` is unusable for a 10-wallet Chipnet rehearsal. OPTN already solved the wallet mental model: **home answers "what do I have and what next?"**, send/receive are guided, state is never hidden.

Map that onto a terminal. One running process, numbered menus, arrow keys + Enter, `b` back, `q` quit. Flags exist later for scripts. Humans live in the menu.

## Proposed experience

Every screen has **one purpose** and **one primary action**. Advanced stuff is one level down.

### Status strip (every screen)

Always show, never make the user infer:

```text
Chipnet · Ready
```

States, same as OPTN: Connecting · Syncing · Ready · Offline · Stale · Retrying · Failed · Waiting for confirmation.

A `0.00 BCH` line must say **Synced** or **Not synced yet**. Never a bare zero.

Network is Chipnet and visible. No mainnet switch in Fv1.

### Home = one pool, type any amount

Product decision: **any amount, one set** (Voidify Nova / Zcash / Aztec). Not Classic tiers. See `any-amount-profile.md`.

```text
╔════════════════════════════════════════════════════╗
║  Chipnet · Ready                                   ║
║                                                    ║
║  Shielded pool                                     ║
║    notes in the set     1,402                      ║
║    reserve              184.22000000 BCH           ║
║                                                    ║
║  Your notes             0.84700000 BCH  (4)        ║
║  Spendable (wallets)    2.40000000 BCH             ║
║                                                    ║
║    1)  Deposit          ← type any amount          ║
║    2)  Withdraw         ← type any amount          ║
║    3)  Run rehearsal                               ║
║                                                    ║
║    4)  Wallets     5)  Activity     6)  Settings   ║
║    q)  Quit                                        ║
╚════════════════════════════════════════════════════╝
```

No denomination list. Set size is everyone in **this** instance. Dummy numbers above are examples, not caps.

Primary = Deposit / Withdraw / Rehearsal. Do not put FRI, AIR, outpoints, or Electrum on Home.

### Wallets (OPTN wallet list, terminal)

```text
Wallets
  #   Label   Chipnet address                         Spendable     Notes
  1   w1      bchtest:qp3wjpa3tjlj54rxgh9jl5u6epkq…   0.25000000    1
  2   w2      bchtest:qrf8ka9l…                       0.10000000    0
  …

  1-9  open wallet
  i    import wallet
  n    new Chipnet wallet
  b    back
```

Open-wallet screen: full address, spendable, notes you can withdraw, then Deposit / Withdraw / Back. Copy address is a first-class action.

Import is a **wallet-owned prompt** inside this program (numbered words, live 12/24 count, checksum as you go). Not a shell argument.

### Deposit (OPTN send, guided)

Recipient is the pool. **You type the amount.**

1. Pick **from** wallet (show spendable).
2. Amount (any, ≥ dust, ≤ spendable − fee).
3. Review (mandatory):
   - From: full `bchtest:` address
   - Into the pool: **the amount you typed** (full precision)
   - Network fee: N sats (separate transparent coin)
   - After: wallet spendable and your notes total
4. Buttons: `Back` · `Deposit now`
4. Progress: Building → Proving (timer) → Broadcasting → In mempool. Never a silent spinner.
5. Success: txid + explorer link. Failure: plain sentence + `Retry` + `Back`. Funds not sent if broadcast failed.

### Withdraw (same send skeleton)

1. Pick which notes / wallet (show each note’s amount).
2. Amount (any, up to those notes; leftover becomes a change note).
3. Fresh destination: paste or generate. Full address on review, never truncated.
4. Exit speed (two buttons, default is fast):
   - **Withdraw now** — prove and broadcast as soon as the review is confirmed.
   - **Batch exit** — opt-in. Joins a **shared round**. The first waiter samples a CSPRNG-uniform wait in `[--batch-min, --batch-max]` (default **30..180 s**). `--batch-window N` pins a fixed length. Anyone else who opts in before close waits the **remaining** time on that same clock (not their own roll). Countdown shows time left in this round. At close, one successor pays each waiter to that waiter's P2PKH (each lock+value HASH256-bound). Arrive after close → next round (new sample). Not CashFusion: no `OP_RETURN FUSE`, no Pedersen/blind Schnorr. Fee change is dust to a fresh address.
5. Review: amount out, full `to`, fee, change left shielded, and (if batch) remaining countdown.
6. `Back` · `Withdraw now` · `Batch exit`
6. Same progress / success / fail states. Batch path never silently skips the countdown.

Private send-to-another-person is the same family but not on Home yet. Do not show Transfer until that action exists.

### Run rehearsal

One screen, one action:

```text
Rehearsal · one pool, varied amounts
  Each of 10 wallets deposits an amount you set (or a default spread),
  then withdraws (full or partial) in shuffled order to fresh addresses.

  Already in the set:  1,402 notes
  Wallets ready:       10 / 10

  [Back]    [Start rehearsal]
```

Disable Start until every selected wallet can pay its chosen amount + fee. Then a live list:

```text
  3/20  Deposit w3   proving…  12s
```

Each step has Retry. A race on the state coin says **Someone else moved first — retrying** and continues. Cancel is always available; it stops *before the next* action, it does not unwind finished ones.

### Activity (OPTN history)

Status first, then amount, then wallet label. Detail: full txid, confirmations, explorer. Pending vs confirmed vs failed. Compact, not a hash dump.

### Settings (grouped, like OPTN plan)

- Network — Chipnet (read-only in Fv1), Refresh connection
- Wallets — import, remove from this PC
- Advanced — home path, explorer URL
- Batch exit — one **window** in seconds (default 180). How long a round stays open after the first waiter. It does not turn batch-exit on. Withdraw still offers it per action.
- Developer — hidden until toggled; FRI knobs live here only

Destructive items in their own block with explicit labels (`Remove w3 from this PC`), never `OK`.

## Copy

Plain language on primary screens:

| Internal | User sees |
| --- | --- |
| continuation UTXO | pool state |
| nullifier | spent note |
| Electrum | connection |
| Sync | Refresh |
| mempool admission | In the mempool |

Keep full precision on BCH amounts. No fiat required on Chipnet.

## Navigation rules (from the OPTN skill)

- One primary action per screen
- `b` / Esc always goes back; Cancel always visible on money screens
- Keyboard first (numbers, arrows, Enter)
- Color is extra: Ready green, caution yellow, failed red, plus a word
- Empty, loading, offline, stale, error, success are all explicit
- Do not add a navigation level that only has one item

## Implementation (when we build it)

- TypeScript, strict. Interactive app + later flag grammar.
- Wallet home **outside** this git repo.
- Reuse ShieldKit-SDK command names under the hood (`pool create`, `action deposit`) so a script can skip the menu.
- Do not start this until Chipnet deposit → withdraw can actually move coins, except a dry-run menu shell if we want to feel the nav.

## Dapp / later GUI (batch-exit)

Steal the CLI knobs; do not invent a second window.

| Surface | Behavior |
| --- | --- |
| Withdraw screen | Default **Withdraw now**. Second button **Batch exit** (opt-in, not on Home as the only action). |
| Countdown | Full-screen remaining `Xm Ys` plus a word (`Waiting to join the batch`). Cancel returns to review; it does not spend. |
| Settings | One integer: `batch-window` seconds (default 180). Floor 1, ceiling 86400. Same name as CLI `--batch-window`. Not a per-user min/max. |
| Clock | First Batch-exit click opens the round. Later clicks join and wait **remaining** time. After close, a new click opens the next round. |
| Chain picture | CashFusion-*shaped*: one tx, many shuffled P2PKH outputs. Do **not** emit `OP_RETURN FUSE` or CashFusion session hashes. Amounts stay any-amount (not equalized). |
| Coordinator | Optional. Relays/Nostr (kind 12230-style gather) may list waiters; they must not hold keys or be required to withdraw. Today the lab is local CLI + a fusion sketch. |
| Later lock | Sum of payout outputs = abs-net, instead of output 1 HASH256 taking the whole net. Until that lands, the GUI must not claim N users already share one successor. |
| Hash | Settings → Advanced may show internal-hash id (`sha256` default, `blake2s`, `poseidon2-m31`). Poseidon2 is prover-side; the redeem stays `OP_SHA256`. |

Code already exports `BATCH_EXIT_WINDOW_SECONDS_DEFAULT`, `joinRound`, `runBatchExitCountdown`, `shapeFusionOutputs` from `workspaces/any-amount/src/pool/batch-exit.ts`.

## Risks

- A 10-wallet rehearsal looks like a real mixer. Label it **Chipnet rehearsal**.
- Unusual public amounts still correlate. Do not pretend any-amount is invisible amounts.
- Joint-lane Fv1 is still a 0.1 ticket. Do not silently retitle that repo’s freeze. Our CLI/product is the `any-amount` profile.
- Serial pool: the rehearsal is a queue. Show step n/m so it does not feel stuck.
- Importing many wallets: list + labels, not ten equal primary buttons.

## Verification

Interactive OPTN-shaped menu is still planning. CLI flags for opt-in batch-exit exist in `workspaces/any-amount` (`--batch-exit`, `--batch-window`, shared-round countdown). No OPTN source was changed.

## Remaining

Wire the menu after the pool can deposit and withdraw once. Then dogfood the rehearsal on Chipnet with the funded roster.
