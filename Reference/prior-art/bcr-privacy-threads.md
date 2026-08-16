# Bitcoin Cash Research — privacy / ZKP / EC threads

Public forum only. No private chat. Start here when someone says “we already discussed this on BCR.”

| Thread | URL | Why it matters |
| --- | --- | --- |
| Confidential Transactions | https://bitcoincashresearch.org/t/confidential-transactions/1724 | Bastian’s public foundation: RPA front end, sharded state-cell pool, `proofBlob32` ABI, Phase 3 ZK+nullifiers, Plane A/B Chipnet |
| SRPA | https://bitcoincashresearch.org/t/silent-reusable-payment-addresses-srpa/1637 | ABLA origin; Bastian: “ZEC global pool, local to the wallet” |
| Shielded addresses & ZKP opcode | https://bitcoincashresearch.org/t/bitcoin-cash-shielded-addresses-zkp-op-code/1476 | ABLA 2025-01; Jason: no `OP_CHECKZKP` for years; **contracts first**; 2026 loops/functions/P2S |
| Native EC arithmetic CHIP | https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570 | `OP_ECADD` / `OP_ECMUL`; ABLA Jun 2026: Bulletproofs now, STARK later; Pedersen hiding vs binding |
| TXv5 | https://bitcoincashresearch.org/t/chip-2025-01-txv5-transaction-version-5/1490 | Not live; size/factoring help for ZKP covenants |
| Raising 520 B push / 201 ops (historical) | https://bitcoincashresearch.org/t/raising-the-520-byte-push-limit-201-operation-limit/282 | Why old script could not do FRI |

CHIP drafts: https://github.com/lightswarm124/bch-ec-arithmetic · https://github.com/bitjson/bch-txv5 · https://github.com/bitjson/bch-p2s

## What 1724 actually proposes (public, Bastian)

Not a consensus shielded pool. A **local-first** policy-UTXO pool:

- RPA/SRPA = receive UX (still EC today; PQ swap later)
- Sharded CashToken state cells = wallet-managed covenant UTXOs (parallelism, restore)
- ABI reserves `proofBlob32` so Phase 3 can drop in a proof **without changing tx shapes**
- Phase 2 = identity stealth + import; Phase 3 = amounts + nullifiers + real proofs
- Fusion of *funding* coins is complementary; paycode does not erase fusion ancestry (his reply to CashDragon)
- April 2026: answers bitjson’s public “actually ZK, PQ direction, &lt;100 KB” challenge
- Chipnet Plane A + 12× ML-KEM-768 Plane B (txid in thread)

That is **compatible** with our Fv1 global-set design if the *same covenant template* and *same pool instance ID* are what wallets talk to. His “local-first” is how he started; the ABI slot is why a later global instance does not need a new opcode.

Do **not** copy: a 32-byte blob as the whole proof (that is a pointer/placeholder, not Circle FRI). Do not treat wallet-owned shards as the anonymity set.

## What 1476 + Jason settled

- BCH can already express SNARK/STARK/Bulletproof verifiers in script (since 2023 split-across-inputs; 2025 bigint; 2026 loops/functions).
- A dedicated ZKP opcode is **years** away; constructions churn (Zcash Orchard).
- Permissionless contract experiments beat ossifying `OP_CHECKZKP`.
- OP_DEFINE/INVOKE (not OP_EVAL) shipped; TXv5 still proposed.
- ABLA asked whether hidden addresses + visible amounts are enough — Jason’s path is *covenant ZKP*, not a new address format opcode.

Our lane follows Jason: **Circle FRI in a covenant**, not a consensus ZKP opcode.

## What 1570 + ABLA (Jun 2026) settled

- ECADD/ECMUL make **Pedersen + Bulletproofs** practical (balance = point add; range = MSM).
- ECMUL cheaper than CHECKSIG (already does a mul inside).
- Pairing opcode: CHIP author said **not** for now (too heavy).
- ABLA: Pedersen *hiding* is information-theoretic; QC breaks *binding* going forward. On a **transparent-backed** BCH pool, a binding break is theft **inside the pool**, not 21M inflation (unlike Monero).
- No compact PQ drop-in for Pedersen+BP; hash STARKs do the same statements, tens of KB, **no new opcode**, waiting on size/op-cost (TXv5 comfort).
- EC ops unlock *now*; STARK is the later/PQ path for the **same layer**. They are not mutually exclusive.

Fv1 does **not** wait on this CHIP. Amounts in Fv1 are public tickets; hiding amounts is a later profile (EC path or STARK path).

## ABLA on 1724 (Feb 2026)

Public praise for the expansion from SRPA to a ZKP privacy system; pointed at Triton as a then-candidate. **We later rejected Triton as the SHA-256 on-chain plugin.** That post is history, not a stack choice.

## How this maps onto our repo

| BCR idea | Our object |
| --- | --- |
| `proofBlob32` reserved lane | ZKP plugin ABI (`Verify`) — but the blob must become a real sharded proof, not 32 B |
| Sharded state cells | Optional later; Fv1 = one serial continuation UTXO |
| Local-first pool | Extra instance; default product = global set per deployment |
| Plane A / Plane B | State UTXO + ML-KEM packets |
| EC CHIP | Amount-hiding profile, not Fv1 |
| No ZKP opcode | Circle FRI in script |
| bitjson &lt;100 KB challenge | Our envelope |
