# Nostr transport (NIP-44 / 59 / 17) + Tor

Read 2026-08-16 from [nips.nostr.com/44](https://nips.nostr.com/44), [/59](https://nips.nostr.com/59), [/17](https://nips.nostr.com/17). Public notes only.

This is the **event bus**, not an XO template and not the pool relation. OPTN P2P CashFusion already proved the listener pattern (kind 12230 + gift-wrap 1059).

## Stack

| Layer | Job | Leak if used alone |
| --- | --- | --- |
| **NIP-44 v2** | Payload encrypt: secp256k1 ECDH → HKDF (`nip44-v2`) → ChaCha20 + HMAC-SHA256, padded, base64. Conversation key is static (`conv(a,B)==conv(b,A)`). | No forward secrecy. No PQ. `created_at` still public on the outer event. IP to the relay. |
| **NIP-59** | Gift wrap. **Rumor** (unsigned) → **seal** kind 13 (author, empty tags) → **wrap** kind 1059 (random one-time key + `p` recipient). Kind **21059** is ephemeral (not stored). | Seal shows *who signed* if it leaks. Wrap hides author. Relays should AUTH and only serve 1059 to the `p` tag. |
| **NIP-17** | DM protocol on top: rumor kind 14 (or 15 files), seal, wrap to each receiver **and** the sender. Inbox relays in kind **10050**. Randomize timestamps up to 2 days past. | One wrap per recipient — bad for large groups. Spam: random wrap keys defeat pubkey reputation (NIP-42 AUTH). |
| **Tor** | Unlinkability of the **socket** (Electrum + relay). Fail **closed** if privacy mode requires SOCKS and it is missing. | Not a mix-net. Timing across relays still correlates. |

NIP-44 is **not** a NIP-04 drop-in. Validate the outer NIP-01 signature **before** decrypt. `#` prefix = future version, not invalid base64.

NIP-EE / Marmot is MLS (forward secrecy). Different layer. We reuse 44/59/17 like OPTN fusion, not EE.

## How we use it

- Replaceable announce (kind **12240** here, 12230 in OPTN fusion) = Solana `onLogs`.
- Private handoff = 1059 gift-wrap of a pool invitation / round message.
- Fresh **round key**, never the BCH wallet key or chat nsec.
- Relays never custody, never sit in `PoolState`.
- Chipnet lab may run clearnet. Anything called private must set `TOR_SOCKS` and fail closed.

Code: `repos/ShieldKit-Circle-STARK/workspaces/any-amount/src/nostr/`.
