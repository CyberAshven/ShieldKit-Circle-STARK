# Lessons: P2P Nostr CashFusion

Fusion is **not** a ZKP plugin. It is a design-section pre-step: break the transparent UTXO graph *before* (or after) a shielded action.

Primary source: **OPTN desktop** P2P CashFusion (server fusion → Nostr bus → P2P gather). CashFusion is a wallet feature, not a consensus pool.

## What actually worked / was decided

- CashFusion math is Pedersen commitments + blind Schnorr, CoinJoin with `OP_RETURN FUSE` + session hash. Homomorphic amounts, not a STARK.
- Server fusion is easier and **sees the player graph**. That is why P2P is the end state.
- Nostr is the **event bus**. On Solana, clients subscribe to program logs / account changes through one RPC (`onLogs`, `onProgramAccountChange`). BCH has no equivalent listener in the node. Nostr `REQ` filters are that listener: announce a kind, peers subscribe, late joiners still see **replaceable** events. Relays must not be able to spend, reconstruct notes, or be required for withdrawal.
- **P2P CashFusion already proved this.** OPTN desktop: replaceable kind **12230** rolling pool announce (stored + replayed via `since`, so a Tor peer who connects late still sees who is waiting — ephemeral 2xxxx kinds do not). Private round traffic is NIP-59 gift-wrap kind **1059** / NIP-44, same outer kind as ordinary DMs. Fresh secp256k1 **round key**, never the wallet or chat identity. Lowest-pubkey coordinator; silent coordinator is dropped and election repeats. OPTN uses 12230 because late Tor subscribers otherwise miss ephemeral gather events.
- **Tor provides unlinkability**, not an onion mix-net. Fail **closed** if Tor is down.
- Outputs: HD by default, optional RPA/stealth. Do not invent new stealth crypto inside fusion.
- Fusion outputs are ordinary BCH UTXOs. They compose with SRPA and with a later shielded deposit.

## Pool discovery (Nostr)

A peer can announce a mix gather via Nostr; wallets pick a denomination and broadcast that they are looking for peers. That is **discovery of a CashFusion-style or friend-mixer set**, not the ShieldKit continuation UTXO.

Keep a clean split:

| Bus | May do | Must not do |
| --- | --- | --- |
| Nostr | find peers, hand encrypted notes, announce a fusion round | hold keys, be the state machine, be required to withdraw |
| CashFusion | unlink transparent coins | replace membership/nullifier proofs |
| Shielded pool | consensus-enforce notes/reserve | depend on a named relay |

Tor + stealth + fusion + hidden amounts is the *stack*. Each layer is optional and replaceable. The ZKP plugin only sits on the pool layer.

## Mapping onto Fv1

- User may fuse, then deposit the fused coin into the 0.1 BCH ticket pool.
- Relayer on the pool tx is the same *role* as a fusion coordinator: optional broadcaster.
- Do not put Nostr event ids into `PoolStateFv1`.
- If we ever ship a “friend mixer” one-shot covenant, it is another **design profile** that still calls `Verify`.

## Three different Nostr things (do not flatten)

| Thing | Job | Not |
| --- | --- | --- |
| **Nostr bus** (NIP-01 subscribe) | Replace a Solana-style event listener: discover peers, announce a round, hand encrypted blobs | The pool state machine |
| **P2P CashFusion over that bus** | Unlink transparent coins without a fusion server (OPTN already ships this) | A STARK / membership proof |
| **NIP-EE / Marmot** | MLS E2EE groups. Unrecommended; Marmot superseded it | An XO template (`p2pkh.ts`) |

NIP-EE can still be a later **invitation ciphertext** format. The bus we actually reuse is the CashFusion one: kinds + gift-wrap + throwaway keys.

Chipnet 10-wallet rehearsal on one machine can stay local. The moment we need **cross-machine / P2P** discovery or a fusion pre-step, Nostr is the proven listener — not an optional curiosity.

## Opt-in batch exit (any-amount lab)

CashFusion remains **not** a ZKP plugin. Batch-exit is an opt-in *timing + output-shape* path for people who are not in a hurry:

- CLI: `pool withdraw --sats N --batch-exit [--batch-min 30] [--batch-max 180]`
- CSPRNG wait in the knob window, live countdown
- Ready waiters sketch one shuffled multi-P2PKH list (`cashfusion-like-multi-p2pkh`)
- We do **not** speak CashFusion: no `OP_RETURN FUSE`, no Pedersen, no blind Schnorr
- The shipped pool redeem still HASH256-binds **one** payout at output 1. Grouping N exits into that one successor is a later lock (`sum(payouts) = abs-net`)
- Dapp notes: `cli-ux.md` (Withdraw + Settings knobs + countdown)

Fast single withdraw stays the default. Fv1 still has no user batching.
