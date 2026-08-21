# FRI_VERSION 10 — on-chain batch-exit note walks

**Status: specified, not implemented.** Written up so it can be executed cold.

## The gap

Envelope B and C's pay hop walk **one** spent note plus **one** change note on
chain, in the note-auth kernel. A batch-exit round with N waiters walks the first
note and leaves the other N−1 in `verifyFri`. `vm-verifier.ts:566` says it plainly:

> B adds a note-auth kernel; batch-exit extra notes still stay in `verifyFri`.

So batch-exit is the one item on the note/nullifier/amount-auth list that is not
on-chain. Everything else in that list was closed on `FRI_VERSION` 9.

## Why it is a version bump, not a kernel change

The kernel side is easy — N note-auth kernels instead of 1, the same pattern the
36 fold kernels already use. The blocker is upstream: **the encoded proof carries
exactly one auth.**

`fri.ts:89` — `auth: FriAuth`, singular. `decodeAuth` (`fri.ts:548`) returns one
`{leaf, index, path, root, nullifier, rho, owner, amountSats, publicDeltaSats,
amountCommit, createdLeaf, createdIndex, createdPath}`. And
`noteAuthUnlockingFromProof` (`note-auth-kernel.ts:243`) builds its walk from it:

```ts
const auth = decodeFriProof(args.proof).auth;
spentIndex: deposit ? auth.createdIndex : auth.index,
spentPath:  deposit ? auth.createdPath  : auth.path,
```

A kernel can only walk a note whose index and path are **in the proof**. Carrying
N of them changes what a proof *is*, which by the project's own rule ("that's a new
FRI_VERSION, not a silent edit of 8") makes this **FRI_VERSION 10**. `VK_ID`
(`params.ts:26`) embeds the version, and `fri.ts:435` rejects a mismatched
`proof.version`, so every FRI 9 artifact stops verifying — including the A and B
lands of 2026-08-21. That is the intended, honest consequence of a wire change.

## Work items

| # | Where | What |
| --- | --- | --- |
| 1 | `fri.ts` | `FriProof.auth: FriAuth` → `auths: FriAuth[]`. Update `encodeFriProof` / `decodeAuth` / `decodeFriProof` for a length-prefixed list. |
| 2 | `fri.ts` | OTP masking is per-auth today (`maskAuth` / `unmaskAuth`, ~`:596`, `:705`). Mask each auth; keep the viewing key out of the encoding. |
| 3 | `fri.ts` | `authPreimageOpen` (`:395`) and `verifyFri` loop over all auths instead of the single one. |
| 4 | `covenant-spend.ts` | `prefixExtraKernelCount` counts N note-auth kernels, not 0-or-1; the successor adds N inputs with per-note unlockings; `compileFundVerifierKernels` mints N note-auth kernel UTXOs. |
| 5 | `params.ts` | `FRI_VERSION` 9 → 10. |

Items 4 is mechanical. Items 1–3 are the soundness-critical ones — they touch the
proof format and the one-time-pad masking.

## Size budget (measured, not estimated)

A note-auth input is **1725 B** (1684 unlocking + ~41 overhead); the lock is 35 B.

| envelope | headroom | extra notes that fit |
| --- | --- | --- |
| **B** (498398 B of 1 MB) | 501602 B | **290** |
| **C pay hop** (89338 B of 100000) | 10662 B | **6** |

So B is effectively unbounded for realistic batch sizes. **C is not** — a batch
larger than ~6 waiters does not fit the pay hop, and note-auth kernels cannot move
to a tape hop because they read `<0> OP_UTXOTOKENCOMMITMENT` and only the pay hop
spends the pool NFT. Either document a max batch size for C, or accept that large
batches are a B-only feature.

## Test gaps to close at the same time

- No test walks more than one note. Add a batch-exit case with N ≥ 2 that fails if
  any waiter's note is not checked on chain.
- Add a VM case asserting a **fake** extra note is rejected — the one-note version
  of this exists; the N-note version does not.

## Do not change

- The note-auth kernel's checks themselves. `amountCommit = SHA256(tag ‖ amount8 ‖
  rho)`, `leaf = SHA256(amountCommit ‖ rho ‖ owner)`, `nf = SHA256(instance ‖ owner
  ‖ rho)` all stay. This is a count change, not a scheme change.
- The claim discipline. Until items 1–5 are done and tested, batch-exit extra notes
  remain off-chain and `MILESTONE.md` should keep saying so.
