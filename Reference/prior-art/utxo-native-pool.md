# UTXO-native pool: best of Tornado, Voidify, Aztec, BCH

Study date 2026-08-16. Sources are public repos and docs. Private chat is not quoted here.

BCH already *is* UTXO. The win is not “add notes.” The win is: **money, public state, and private notes are all UTXOs** (real or virtual), while the ZKP stays a plugin.

## What each system actually is

| | Tornado Classic | Voidify Classic | Voidify Nova | Aztec | BCH target |
| --- | --- | --- | --- | --- | --- |
| Chain model | Account + ERC20/ETH | Solana accounts | Solana accounts | L2 notes + public tree | **Native UTXO + CashToken** |
| Private object | One note / deposit | One note / deposit | Rolling encrypted balance | Notes (UTXOs) | Notes (virtual UTXOs) |
| Amounts | Fixed denom | Fixed denom | Flexible + partial | Arbitrary | Fv1 fixed ticket; later profile can be Nova |
| On-chain money | Contract balance | Pool treasury account | Pool treasury account | L2 public/private | **State UTXO sats = reserve** |
| On-chain tree | Full Merkle in storage | Poseidon tree in account | Poseidon tree depth **26**, 100-root history | Note-hash + nullifier trees | **Roots only** in 128-byte NFT (`PoolStateFv1`) |
| Nullifiers | `mapping(bytes32=>bool)` | PDA account per nullifier | PDA per `input_nullifier` | Nullifier tree | **Nullifier Merkle root** in state |
| Proof | Groth16, 6 public inputs | Groth16, 256 B | Groth16, **5** public inputs, **256 B** | Client kernel (their plugin) | Circle FRI first |
| Verifier | Separate `Verifier.sol` | **Statically linked** in one program | Same program | Protocol circuits | Covenant *is* `Verify` |
| Relayer | Optional, bound in circuit | Required path for privacy; cannot reroute | Same | Sequencer / PXE | Optional broadcaster; bind payout in proof |
| Delivery | User saves note | User saves note / wallet+passphrase | Encrypted output on chain | Encrypted logs / PXE | Plane B ML-KEM packets |

## Tornado (code: `tornadocash/tornado-core`)

`circuits/withdraw.circom` + `contracts/Tornado.sol`:

```text
commitment = Pedersen(nullifier || secret)
deposit:  insert commitment into Merkle tree (depth 20)
withdraw public: root, nullifierHash, recipient, relayer, fee, refund
withdraw private: nullifier, secret, path
constraint: nullifierHash = Pedersen(nullifier)
            commitment in tree at root
            recipient/relayer/fee/refund are bound (squared so they cannot be swapped)
then: nullifierHashes[h] = true; pay denomination - fee
```

Steal:

- Membership + unused nullifier **is** the withdraw statement
- Bind recipient, relayer, and fee *inside* the proof
- Fixed denomination = uniform public amounts (Fv1 0.1 BCH)

Do not steal:

- Account `mapping` for nullifiers (BCH has no map)
- Separate pairing verifier contract
- Pedersen-in-circuit as the only hash (on BCH, SHA-256 is native)

## Voidify (code: `VoidifyCommunity/voidify-smart-contract-audit`)

Program id `4WJnXP7mFxFY45SYvfyGDwEBdcwafVqdgbYYSHpoded4`. HashCloak audit in-repo. One Anchor program, two plugins.

**Classic** (`state/classic/pool.rs`): denomination + Poseidon Merkle, depth 20. Withdraw takes `[u8; 256]` proof. Tornado on Solana.

**Nova** (`utils/nova/proof.rs`, verified in source):

```text
public_inputs[5] = root, public_amount, ext_data_hash, input_nullifier, output_commitment
proof = 256 bytes = G1(64) || G2(128) || G1(64)
vk.nr_pubinputs = 5
tree levels = 26, root history = 100
```

That matches the 832 B / 1024 B / 256 B sizes. Groth16 is `groth16_solana::Groth16Verifier` **inside** the same program as pools, relayers, DAO, treasury, oracles.

Nova statement is Aztec-shaped: spend one commitment, emit one replacement, public amount is the visible delta (deposit + / withdraw −), `ext_data_hash` binds recipient/mint/relayer/encrypted output.

Steal:

- Two statements (fixed note vs rolling note) as **two profiles**, one product
- `ext_data_hash` binding (better than Tornado’s dummy squares)
- Relayer cannot change recipient; program checks proof then pays
- Client-side prove; wasm/zkey are artifacts, not consensus
- Root history (recent roots remain valid) so wallets are not raced on every leaf

Do not steal:

- Groth16 as identity
- Poseidon as the design-section hash
- DAO / slash / oracle / treasury as Fv1
- Nullifier as a **new account** (Solana PDA). That is account-model. On BCH the nullifier set is a **root in the state UTXO**.

Local clone: `repos/voidify-smart-contract-audit`.

## Aztec (docs, not their prover)

Notes *are* UTXOs. On-chain: note-hash tree + nullifier tree. Spend = prove preimage + emit unlinkable nullifier + maybe create new notes. Client PXE proves. Delivery = encrypted logs or out of band. Silo by contract address.

Steal:

- Virtual UTXO mental model (already BCH-native)
- Unlinkable nullifiers
- Client prove
- Encrypted delivery → Plane B
- Siloing → `pool instance ID` in `PoolStateFv1`

Do not steal: sequencer, Noir, Fee Juice, their proving stack (V5 had a soundness incident).

## What “UTXO-native” means on BCH (this is the best-of)

Tornado and Voidify simulate a UTXO note set **inside an account**. Aztec is UTXO notes on an L2. We can do the real thing:

```text
one continuation UTXO  (or N shards that share the same covenant)
    satoshis = base + outstandingTickets * ticket
    CashToken commitment 128 B =
        PAF1 | seq | deposits | withdraws | poolId | noteRoot | nullRoot

deposit transaction
    consume current state UTXO + ticket-value funding
    create successor state UTXO   (noteRoot' only)
    optional Plane B packets
    proof plugin: “insert one well-formed note, conservation holds”

withdraw transaction
    consume current state UTXO
    create successor state UTXO   (nullRoot' only)
    payout output + optional relayer fee + fee funding input
    proof plugin: membership + unused nullifier + insert + bind payout/fee
```

Why this is strictly more native than Tornado/Voidify:

1. **Reserve is the UTXO value.** No ERC20 `balanceOf(pool)`. Consensus already conserves sats if the covenant checks `newValue == oldValue - ticket` (withdraw) or `+ ticket` (deposit).
2. **State is an outpoint.** Two valid txs race; one wins. That *is* Aztec’s “one state transition” without a sequencer.
3. **Nullifiers are a set root**, not a hashmap and not a PDA. Membership/non-membership is in the proof, as BCH script cannot store a million flags.
4. **Notes never become on-chain objects.** Only their commitments’ *root* does. Same as Aztec/Tornado, but the carrier is a CashToken NFT, not contract storage.
5. **Proof family is not the UTXO.** Swap Circle FRI / later Groth16 / later Nova-statement without changing the state codec.

Shard variant (early BCH pool sketches, also compatible): several covenant UTXOs, each with a slice of the tree or a copy of the roots, so spends stay uniform. Fv1 froze **one** continuation UTXO first. Shards are a later topology if the 10 KB input cap forces it — that is verifier partitioning, not user batching.

## Bindings we must copy (or we are worse than Tornado)

| Binding | Tornado | Voidify Nova | BCH must |
| --- | --- | --- | --- |
| Recipient | public input | inside `ext_data_hash` | proof + covenant check the payout locking bytecode |
| Relayer fee | public input | ext_data | optional output; proof binds amount |
| Root freshness | `isKnownRoot` history | 100-root ring | pin current state outpoint; old proofs die when the UTXO is spent |
| Double spend | mapping | PDA create | nullifier root unique-insert in the proof |
| Amount | contract `denomination` | `public_amount` + pool min/max | ticket constant in `PoolConfigFv1` + UTXO value check |

On BCH, **root freshness is free** if the proof is bound to the *current* state UTXO. You cannot replay a withdraw against a successor. That is better than Tornado’s root-history window.

## Fv1 vs later Nova-shaped profile

Keep Fv1 = Tornado/Classic: one ticket, one note, one nullifier. Uniform public amounts.

A later profile can be Voidify Nova / Aztec change-notes: spend note, emit remainder note, `public_amount` is the visible withdraw. Same state codec, different `PoolAction` statement, different plugin. Do not widen Fv1 now.

## Complementary layers (not the pool)

- CashFusion: unlink the *funding* UTXO before deposit
- Stealth / SRPA / ML-KEM Plane B: unlink delivery
- Quantumroot: PQ keys, not mixing
- Relayer: broadcast only

Stacking those around a UTXO covenant is the “best of the best.” Copying Solana’s account program or Ethereum’s mixer contract is not.

## Local study set

| Path | What |
| --- | --- |
| `repos/voidify-smart-contract-audit` | On-chain Classic + Nova |
| `repos/voidify-gitbook` | Product docs |
| `repos/voidify-ceremony-frontend` | Trusted setup UI |
| Tornado | https://github.com/tornadocash/tornado-core |
| Aztec notes | `Reference/prior-art/aztec.md` |
| Fv1 codec | `repos/ShieldKit-Circle-STARK/.../spec/pool-state-fv1.md` |
| Plugin ABI | `Reference/literature/notes/zkp-agnostic-architecture.md` |
