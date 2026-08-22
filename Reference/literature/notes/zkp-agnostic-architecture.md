# ZKP-agnostic pool: design section vs ZKP section

The pool is **not** “a Circle STARK.” It is a BCH covenant + note/nullifier/reserve machine. A proof family is a **plugin**. Circle FRI is plugin #1 because it matches SHA-256 + BigInt + loops on CashVM. Groth16, Goldilocks FRI, a future WHIR backend, or even a pairing CHIP later must be attachable without rewriting notes.

Name the layers correctly: AIR is the statement encoding; FRI/STIR/WHIR are proximity tests; Spartan is sumcheck+R1CS; Whirlaway is AIR+WHIR. See `zkp-family-map.md`.

Local vs global pool is a product choice; STARK vs SNARK is a verifier choice. Do not fuse them.

Voidify is the existence proof of the *wrong* fusion done on purpose: Groth16 is **statically linked** into their Solana core program. That is fine on Solana (pairings exist, 256-byte proofs). Copying that fusion onto BCH would lock us to one family that BCH cannot verify cheaply today. Copy the **split**, not the linker.

```text
┌─────────────────────────────────────────────────────────┐
│ DESIGN SECTION  (stable)                                │
│  notes, nullifiers, reserve, Plane A/B, discovery,      │
│  relayer policy, CashFusion pre-mix, recovery           │
│  statement = (old_state, new_state, tx_context, rules)  │
└───────────────────────────┬─────────────────────────────┘
                            │  Verify(family, vk, x, π)
┌───────────────────────────▼─────────────────────────────┐
│ ZKP SECTION  (swappable plugins)                        │
│  circle-fri-m31  │  goldilocks-deep-ali  │  groth16-bn254 │
│  (active)        │  (prior art)          │  (size dream;  │
│                  │                       │   needs pairings│
│                  │                       │   or wrap)      │
└─────────────────────────────────────────────────────────┘
```

## Design section (do not put field/FRI constants here)

Owns:

- Ticket / amount policy (Fv1 = fixed 0.1 BCH; a later profile can be Nova-style flexible)
- `PoolStateFv1` 128-byte commitment
- Note commitment + nullifier uniqueness
- Conservation of reserve sats
- Tx binding (non-circular context)
- Delivery (ML-KEM packets / Plane B)
- Discovery / event bus: **Nostr** (Solana `onLogs` analogue). Proven on OPTN P2P CashFusion. Never a custodian.
- Relayer: broadcast only
- Complementary CashFusion: break transparent input linkage *before* deposit

Does **not** own: blowup, queries, grind, M31 vs Goldilocks, Poseidon vs SHA-256 inside the PCS, trusted setup.

## ZKP section (plugin ABI)

Every backend implements the same check:

```text
Verify(vk, public_inputs, proof) -> accept | reject
public_inputs  = canonical encoding of the design-section statement
vk             = verifying key or FRI parameter pin (hash-committed)
proof          = family-specific bytes, sharded across BCH inputs if needed
```

Required plugin metadata:

| Field | Why |
| --- | --- |
| `family` | `circle-fri` / `goldilocks-fri` / `groth16-bn254` / … |
| `vk_id` | hash of the exact vk/params; covenant pins this |
| `public_input_layout` | how statement fields become field elements / bytes |
| `proof_max_bytes` | must fit remaining 100 KB after design-section overhead |
| `verifier_program` | P2SH32/P2S redeem(s) that implement `Verify` |
| `assumptions` | transparent / trusted-setup / pairing / hash conjecture |
| `pq_notes` | Groth16 is not PQ; hash FRI can be |

A deployment may ship **one** plugin (Fv1 = Circle FRI) or several covenants that share the same state codec and differ only in the verifier redeem. Do not put a runtime “selector admin key” in Fv1. A new family is a new reviewed profile, not a silent upgrade.

## What Voidify’s static link actually means for us

They measured (user-supplied; not re-weighed here):

- Core Solana ELF ~1.17 MiB = **protocol + verifier**, not verifier alone
- VK material: 832 B Nova (5 public inputs) + 1024 B Classic (8 public inputs) = 1856 B
- Each Groth16 proof: **256 B**

Lesson:

1. Proof size and program size are different budgets. BCH’s hard budget is the **transaction** (100 KB) and **per-input** (10 KB), not an ELF.
2. Embedding the verifier in the core program is the Solana analogue of “the covenant *is* the verifier.” That is correct. Making that verifier *only Groth16* is their product choice, not a law.
3. Two circuits (Classic vs Nova) = two plugins, two ceremonies, two VKs, **same product**. We should be able to do the same: fixed-ticket Circle FRI now, flexible-amount backend later, without renaming the pool.

On BCH, Groth16 stays a comparator (`mr-zwets/groth16_cashscript`) until pairings exist or someone wraps a STARK into Groth16 off-chain *and* we accept a trusted setup. Do not make that the identity of the pool.

## SHA-256 vs Triton / SP1 / Stwo

We are targeting **SHA-256** as the chain-visible hash (BCH native, ABL ZIP, 0zkbrewer Merkle). That choice fights several zkVMs:

| System | Native hash | Can it be *the* BCH verifier? |
| --- | --- | --- |
| Circle FRI with SHA-256 Merkle | SHA-256 | **Yes — this is the lane** |
| 0zkbrewer DEEP-ALI | SHA-256 Merkle + Poseidon2 in AIR | Prior art, Goldilocks, over 100 KB when sound |
| Triton VM | Tip5 / STARK-friendly, recursive by design | Not a SHA-256 verifier. Proving SHA-256 *inside* Triton is a huge AIR. Verifying Triton on BCH means implementing *their* FRI+hash, not SHA-256 |
| SP1 | Plonky3 / Poseidon-family; often **wrapped to Groth16** for EVM | Same wrap problem; Groth16 on BCH is pairing-heavy |
| Stwo / S-two | Circle STARK + Poseidon/Blake for Cairo | Prior art for Circle FRI engineering. Do not inherit Cairo or Starknet recursion |

So: **Triton is probably the wrong on-chain plugin if we stay on SHA-256.** It can still be an *off-chain* research prover if someone later writes a Triton-verifier plugin. That is exactly why the ZKP section is a plugin.

Algebraic hashes (Poseidon2, RPO-M31, Tip5) stay allowed *inside* a plugin that also implements them in script. They are not allowed to leak into the design-section state codec unless every plugin agrees.

## Aztec / Tornado / Neptune — steal the design, not the prover

- **Tornado Classic:** commitment = hash(secret, nullifier), Merkle membership, nullifier uniqueness, fixed denomination. Maps to ShieldKit Fv1 + Voidify Classic.
- **Aztec:** notes + nullifiers + client-side prove (PXE) + optional public path. Maps to Plane A state + wallet-local prove. Their prover (Noir / Honk / etc.) is *their* plugin. July 2026 Alpha V5 had a proving-system bug that accepted illegal transitions — same hygiene we already want (false-statement tests, AIR soundness).
- **Neptune:** UTXO privacy chain with Triton-style STARKs. Product is a chain, not a BCH covenant. Hash/recursion lessons only.

## CashFusion / Nostr — not a proof family

Fusion breaks **transparent** input linkage. It does not replace membership proofs.

Nostr is useful **because** BCH has no Solana-style program event listener. A relay subscription *is* that listener. OPTN P2P CashFusion already uses it in production-shaped code: replaceable kind 12230 announce, NIP-59/44 private round traffic, throwaway round keys.

Lessons (OPTN P2P CashFusion):

- Server fusion sees the graph; P2P over Nostr is the listener + mailbox, not custody
- Relayer/coordinator must not be required for withdrawal
- Tor for unlinkability; fail closed if the privacy transport is down
- Pool announce is a discovery event, not `PoolStateFv1`
- Fusion outputs are ordinary UTXOs and can *fund* a shielded deposit

Keep fusion in the design section as an optional pre-step. Keep the Nostr bus available for any later P2P gather (fusion, friend-mixer, invitation handoff).

## Fv1 vs later profiles

| Profile | Design | First plugin |
| --- | --- | --- |
| ShieldKit Fv1 (joint freeze) | fixed 0.1 BCH ticket, size/proof gate | Circle-domain FRI |
| Voidify Classic analogue | fixed denominations, one note each | not our product |
| **any-amount (ours)** | one set, type any amount, change notes | Circle FRI first; Nova-shaped statement |

Product is any-amount. Fv1 stays a named gate. Any-amount still plugs into `Verify`.
