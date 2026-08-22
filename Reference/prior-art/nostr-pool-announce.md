# Nostr pool announce (listener, not consensus)

BCH nodes have no Solana-style `onLogs` / program-account subscription.
This lab uses Nostr `REQ` filters as that bus. Relays do **not** custody,
do **not** sit in pool state, and are **not** required to withdraw.

Already shipped pattern: OPTN P2P CashFusion (replaceable kind **12230** +
NIP-59 gift-wrap **1059**). Transport notes: [`nostr-transport.md`](nostr-transport.md),
[`cashfusion-nostr-lessons.md`](cashfusion-nostr-lessons.md).

Public NIPs: [44](https://nips.nostr.com/44), [59](https://nips.nostr.com/59),
[17](https://nips.nostr.com/17), [01](https://nips.nostr.com/01) (kind 30000–39999
parameterized replaceable).

## Candidate advertise (kind 30017)

Parameterized replaceable event for **discovery** of a Chipnet pool root.
This is not a consensus write. Lab examples stay on **chipnet**.

```json
{
  "kind": 30017,
  "content": "",
  "tags": [
    ["d", "chipnet-any-amount"],
    ["bchct", "rpv1"],
    ["network", "chipnet"],
    ["topic", "shielded-pool"],
    ["type", "circle-fri-lab"],
    ["scheme", "sha256-merkle"],
    ["transport", "nip17"],
    ["encryption", "nip44"],
    ["wrap", "nip59"],
    ["asset", "bch"],
    ["privacy", "note-commitments"],
    ["note-root", "<NOTE_MERKLE_ROOT>"],
    ["nullifier-root", "<NULLIFIER_ROOT>"]
  ]
}
```

Kind **12230** remains the fusion gather announce. Kind **30017** is a
longer-lived pool-root advertise. Do not put event ids into the NFT cell.

## On-chain membership is still a SHA-256 walk

The covenant walks 33-byte `(bit || sibling)` steps (`src/chain/note-merkle.ts`).
Nostr only tells peers *which* roots to look at. A dummy / missing walk still
fails the lock.

## Privacy stack (layers, not one product)

| Layer | Job |
| --- | --- |
| Nostr + Tor | Discover peers / hand encrypted notes |
| CashFusion (optional) | Unlink transparent coins first |
| Pool covenant | Enforce noteRoot / nullifierRoot / sequence |
| Pedersen in the note | Hide **note** amounts; pool UTXO sats stay `STATE_BASE` |
