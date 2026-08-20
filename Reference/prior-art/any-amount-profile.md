# Product: one pool, any amount

Decided 2026-08-16. We are **not** shipping Tornado/Voidify Classic tiers.

The product is **one Chipnet pool, any amount, one anonymity set** — Voidify Nova / Zcash / Aztec *amounts*, not 0.01 / 0.1 / 1 / 10 buckets.

## What “any” means

- Deposit whatever BCH you type (above dust + fee).
- Withdraw whatever you type, up to your notes. Partial withdraw leaves a **change note**.
- Every note sits in the **same** set. A 0.013 deposit and a 2.5 deposit share anonymity.
- Home has **one** pool, not a denomination board.

Public deposit/withdraw amounts are still visible (Nova says this too). Weird amounts can still correlate. The protocol does not split the set to hide that.

## What it is not (yet)

- Private transfer to someone else’s note — same family as Nova/Zcash, not required to type an amount. Add as a later action on this profile if we want it.
- One-successor N-payout is shipped (sum of shuffled P2PKH = abs-net; every lock+value HASH256-bound). Opt-in **batch-exit** samples a shared CSPRNG-uniform wait in [30, 180]s (knobs `--batch-min`/`--batch-max`; `--batch-window` pins). Later opt-ins wait the remaining time on that clock. Each waiter is paid to that waiter's P2PKH.
- Fv1’s frozen 0.1 ticket — that stays the **joint ShieldKit size gate** with toorik. Do not rename or widen `PoolActionFv1` on `main`. Our product statement is a **new profile** (`any-amount`, Nova-shaped) that still calls `Verify`.

## Statement (plugin, not a new STARK brand)

```text
public:  old_state, new_state, public_amount, ext_data (recipient / fee)
private: note(s), amount(s), nullifier, change note if partial

deposit:  public_amount > 0, reserve += public_amount, insert note
withdraw: public_amount < 0, reserve += public_amount,
          spend note, insert change if leftover
```

`public_amount` is the visible delta, same as Voidify Nova. Circle FRI is still the first backend.

## Is Fv1 better?

**On two axes, yes. As the product, no.**

| Axis | Fv1 (0.1 ticket) | any-amount (ours) |
| --- | --- | --- |
| Amount privacy | **Better.** Every deposit/withdraw is 0.1. Nothing to correlate. | Worse. The public delta is the amount you typed. Weird numbers link. |
| Statement / 100 KB | **Better.** No change note, no `public_amount` algebra. This is why the joint lane froze it. | Heavier. Partial withdraw = spend + change + conservation. |
| Set size | Only other 0.1 deposits. Empty if nobody uses that ticket. | **Better.** Everyone in one set. |
| UX / reputable wallet | Classic mixer. Feels like Tornado 2019. | **Better.** Nova / Zcash / Aztec. Type the number. |
| First Chipnet STARK | **Better kill-gate.** Prove Circle FRI fits. | Wrong first AIR if the tx blows the 100 KB cap. |

Use Fv1 to **measure the proof**. Ship **any-amount** as the pool people type into. Same `Verify` plugin. Do not pretend Fv1 is the nicer product, and do not pretend any-amount hides amounts.

## CLI

Type the amount. Do not ask the user to pick a tier. Rehearsal uses varied amounts across the 10 Chipnet wallets so the set is not one fake ticket size.

See `cli-ux.md`.
