# What the shielded pool actually is

Jason / BCR 1476: **covenant first**, no `OP_CHECKZKP`.
BCR 1724: state cell + `proofBlob` slot.
BCR 1570: Pedersen/Bulletproofs when EC ops exist; hash STARKs do the same job without a CHIP.

The pool is **not a P2PKH address**. It is a self-replicating **covenant UTXO**. P2PKH is only how users fund, take payouts, and pay fees.

## Locks

| Coin | Lock | Why |
| --- | --- | --- |
| **Pool state UTXO** | **P2S** on 2026 Chipnet (program *is* the lock). ShieldKit P1 measured **P2SH32** shells — same covenant, hashed redeem. | Self-replicating. Validates. Does not “call.” |
| **User funding / payout / fee** | **P2PKH** today | Addresses later: Quantumroot (LM-OTS + lock NFT). Not the mixer. |

Cauldron is P2S. Wrap is P2SH. We are the Cauldron *shape* (same-index successor) with a **shielded** statement, not an AMM.

Chipnet lab default for the first broadcast is **P2SH32** (P1-measured shell). P2S compiles and measures in the same tree; swap the lock kind when we want the raw program as the lock.

CashTokens genesis is only legal from a parent **vout = 0**. A change output cannot mint a new category (`bad-txns-token-invalid-category`). The CLI self-sends a single-output prep tx when the lab UTXO is not vout 0.

`OP_SIZE` leaves the commitment on the stack. The redeem must `OP_DROP` it or a successor fails with “Extra items left on stack” (first Chipnet cell `0adce2ca…`).

## Five-point successor (every pool spend)

Output 0 must keep:

1. locking bytecode (P2S / P2SH32 redeem)
2. token category
3. satoshis = `STATE_BASE + reserve`
4. fungible token amount `0`
5. new 128-byte commitment (`PAA1` any-amount, or `PAF1` Fv1 ticket)

Layla (2026-05-15) made NFT commitments **128 bytes**. That is why `PAA1` is 128 bytes, not a 40-byte hash of the state.

The on-chain proof slot is `OP_RETURN PAA1PROF || SHA-256(proof)`. The full Circle FRI blob stays off-chain until a sharded on-chain verifier fits the 10 KB unlocking / 100 KB tx envelopes.

## Plugins (do not flatten)

| Plugin | Job | Not |
| --- | --- | --- |
| **Circle FRI (SHA-256)** | Membership, nullifier, transition. Hash STARK. PQ family. | Addresses |
| **Pedersen / Bulletproofs** | Confidential *amounts* (BCR 1570). Needs EC CHIP on-chain or lives inside the STARK. | Delivery |
| **ML-KEM-768** | Plane B *who* / note packets (BCR 1724). | The covenant |
| **Quantumroot** | PQ *keys* after ECDSA dies. | The pool set |
| **Nostr 44/59/17** | Event bus (CashFusion-style listener). | State |

`Verify(family, vk, statement, proof)` stays the only covenant hook.

## Profiles

- **Fv1** (joint, sealed): 0.1 ticket, public amount, PAF1. Size gate with toorik. Do not widen it on `main`.
- **any-amount** (this workspace): type the number, `public_amount` visible until the Pedersen profile hides it.
- **hidden-amount**: same covenant + Pedersen (or STARK-encoded amounts). Later.

P2PKH is **not** the shielded pool. The pool is the **covenant UTXO**.

## Circle FRI parameters (shipped)

| Item | Value |
| --- | --- |
| Family | `circle-fri-m31` |
| Field | M31 (`2^31-1`) |
| Domain | circle group `x²+y²=1`, generator `(2, 1268011823)`, subgroup `g = [2^26]G`, `n=32` |
| Queries | 8 |
| Fold | Circle FRI fold (2024/278) with `x=0` fallback to `y` |
| Binding | `SHA-256(encodeStatement \|\| i)` → 16 coeffs; membership, nullifier, reserve, Pedersen bytes all sit in the statement |
| `sound` | **`false`** |

An honest deposit or withdraw verifies. A false reserve, false note commitment, or false nullifier is rejected because the statement polynomial moves, not only because a bit in the proof flipped.

## Confidential amounts

`amountCommitIn` / `amountCommitOut` are 32-byte Pedersen-style scalars (`C = v·G + r·H` over the secp256k1 scalar field, hash-to-scalar generators). They are first-class statement fields. Public deltas stay visible. Real on-chain EC points wait on CHIP 2025-05 or move inside the AIR.

Partial withdraw mints a **new change note**: leftover amount, same `ownerSecret`, **fresh `rho`**, new Merkle index. Reusing `rho` would make `nullifierOf(change) == nullifierOf(spent)` and the next spend dies (`nullifier already used`).

## Chipnet path

1. Lab wallet is P2PKH (`bchtest:q…`).
2. `lab demo --wallets 100` rehearses deposit+withdraw prove/verify locally.
3. `pool measure-tx` compiles P2S genesis, P2SH32 genesis, and a P2SH32 successor; prints byte counts.
4. `pool chipnet-covenant` signs a P2SH32 five-point genesis with a 128-byte `PAA1` NFT and the proof-slot OP_RETURN, then broadcasts when the lab UTXO is funded.

## 100-wallet scale

The CLI walks K wallets through deposit, **partial withdraw** (fresh change `rho` + new index), then spend-change, each with Circle FRI prove+verify. One hundred **funded** on-chain wallets is not required while the faucet is captcha-gated.

## What is closed

- Sound 128-bit on-chain Circle FRI shards (Goldilocks sound wiring already measured ~120 KB).
- Hidden amounts as EC points on-chain.
- Steal-resistant covenant that accepts only `Verify` (current five-point script does not check a proof; Chipnet genesis is a small lab cell).
- OPTN addon wired into OPTN upstream.
- ML-KEM Plane B and Quantumroot addresses.

## FAQ

### Is this sounder than Aztec / Zcash / Monero?

No published theorem says that, and a demo accept does not prove it. What we can say honestly:

- Circle FRI is a **hash STARK**: no trusted setup, no pairing curve, PQ *family* (SHA-256 + M31). Aztec (Honk/Plonk-ish) and Zcash (Halo2 / Groth16 history) sit on pairing or discrete-log assumptions. Monero is ring signatures + Bulletproofs, not a membership STARK.
- The **shipped** parameters are `n=32`, 8 queries, `sound: false`. That is weaker than any production shielded system.
- Superiority, if it ever exists, will be a parameter + audit claim after a 128-bit on-chain verifier fits. Not today.

### Why Rust?

Toorik’s ShieldKit-SDK `designs/fri` splits **Rust `fri-prover` / `fri-worker`** (heavy prove) from TS CLI/chain. This workspace does the same: TypeScript is the shipped plugin; `crates/circle-fri-worker` is an optional prove worker that emits the same proof bytes so TS `verifyFri` can consume them. n=32 is fast in TS; Rust is there for later larger domains and for a cross-check, not because TS is blocked.

### Why not Fv1 0.1?

Fv1 is the joint **size gate** with toorik (fixed ticket, smaller AIR). It is a better first *measurement*, not the product. The product is one set, any amount (Nova / Zcash / Aztec amounts). `public_amount` stays visible until the Pedersen/hidden profile. Do not widen sealed `PoolActionFv1` on `main`.

### Why a fresh rho on change?

`nullifier = SHA-256(poolInstance || ownerSecret || rho)`. Reusing `rho` on the leftover note makes the change spend the same nullifier as the note you just burned. The machine then throws `nullifier already used` (or `note not in tree` if you also keep the old index). Change keeps the owner, mints a new `rho`, and returns the new Merkle index.

### What is still closed?

On-chain FRI shards, hidden-amount EC, steal-resistant `Verify` in the covenant, OPTN upstream wiring, Quantumroot addresses, ML-KEM delivery. See `STATUS.md`.

### P2S or P2SH?

Both. Same five-point program. **P2S**: the program *is* the lock (2026). **P2SH32**: `OP_HASH256 <redeem> OP_EQUAL` (ShieldKit P1 shells). P2PKH never holds the pool set.

### Are ML-KEM and Quantumroot the mixer?

No. ML-KEM is Plane B note delivery. Quantumroot is a PQ key vault. Neither is on the covenant `Verify` hook.
