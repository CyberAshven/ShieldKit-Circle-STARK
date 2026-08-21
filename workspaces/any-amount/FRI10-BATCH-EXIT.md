# Batch-exit note walks — build FRI10 **beside** FRI9, do not bump

> **If you are an AI or a new contributor picking this up: read this section first.**
>
> - **Do not change `FRI_VERSION`.** It is 9. Leave it at 9.
> - **Do not edit `src/backends/circle/fri.ts` in place.** FRI9 is landed, sound,
>   and has on-chain artifacts depending on it.
> - Add a **new zkp plugin family** alongside `circle-fri-m31`. That is the
>   supported extension point, stated in `src/plugins/registry.ts`: *"A later
>   plugin is one registry row + prove/verify; notes/nullifiers stay."*
> - Related: [`C-BINDING.md`](C-BINDING.md) (what the tape does and does not bind),
>   [`MILESTONE.md`](MILESTONE.md), [`STATUS.md`](STATUS.md).

**Status: specified, not implemented.** Written to be executed cold.

## Documentation convention

The same copy-don't-mutate rule applies to **documents**, not just code. When the
batch work needs to change something a FRI9 doc asserts, **do not edit the FRI9
doc** — copy it to a new file with `-FRI10` appended and change the copy:

| FRI9 (leave as-is) | FRI10 (create when needed) |
| --- | --- |
| `MILESTONE.md` | `MILESTONE-FRI10.md` |
| `STATUS.md` | `STATUS-FRI10.md` |
| `C-BINDING.md` | `C-BINDING-FRI10.md` |
| `COMPARISON.md` | `COMPARISON-FRI10.md` |

The FRI9 documents describe a configuration with on-chain artifacts behind it.
They stay true no matter what happens to the batch work. If FRI10 is abandoned,
delete the `-FRI10` files and nothing else moves.

## The gap

Envelope B and C's pay hop walk **one** spent note plus **one** change note on
chain, in the note-auth kernel. A batch-exit round with N waiters walks the first
and leaves the other N−1 in `verifyFri`. `vm-verifier.ts:566`:

> B adds a note-auth kernel; batch-exit extra notes still stay in `verifyFri`.

This is the last item on the note/nullifier/amount-auth list that is not on-chain.
Everything else was closed on FRI9.

## Why it looks like a version bump, and why it must not be one

The kernel side is easy — N note-auth kernels instead of 1, the same pattern the
36 fold kernels already use. The blocker is upstream: **the encoded proof carries
exactly one auth.** `fri.ts:89` is `auth: FriAuth`, singular, and
`noteAuthUnlockingFromProof` (`note-auth-kernel.ts:243`) builds its walk from it:

```ts
const auth = decodeFriProof(args.proof).auth;
spentIndex: deposit ? auth.createdIndex : auth.index,
```

A kernel can only walk a note whose index and path are in the proof, so carrying N
changes what a proof *is*.

The tempting move is `FRI_VERSION` 9 → 10. **Don't.** `VK_ID` (`params.ts:26`)
embeds the version and `fri.ts:435` rejects a mismatched `proof.version`, so a bump
invalidates every FRI9 artifact — including the Chipnet lands of 2026-08-21
(A `614b7077…`, B `81bb2cef…`, and C's 18 tape hops). If the new work has a bug you
have lost the known-good configuration at the same moment.

## The safe shape: a second family

`zkpPlugins` is a list (`registry.ts:50`), each entry carries its own `family` and
`vkId`, and `zkpPluginByFamily()` dispatches. `hash-lab-v0` already demonstrates a
second family coexisting. So:

| | |
| --- | --- |
| **Leave alone** | `FRI_VERSION = 9`, `VK_ID`, `fri.ts`, `circleFriPlugin`, the note-auth kernel's checks, every existing lock |
| **Add** | `src/backends/circle-batch/` (or similar) with its own `fri.ts` supporting `auths[]`, its own `VK_ID`, its own plugin object |
| **Register** | one row in `zkpPlugins`, e.g. `family: "circle-fri-m31-batch"` |
| **Select** | `--plugin circle-fri-m31-batch`; default stays `DEFAULT_ZKP_FAMILY` = FRI9 |

Cross-family verify already rejects, so a batch proof cannot be mistaken for a FRI9
proof or vice versa. FRI9 keeps working the entire time, and the fallback is
"don't pass `--plugin`".

Duplication is the price and it is the right price. Share by extracting helpers
only where it cannot change FRI9 behaviour; when in doubt, copy.

## Work items

| # | Where | What |
| --- | --- | --- |
| 1 | new backend | `FriProof.auths: FriAuth[]` (length-prefixed) in the copied encode/decode. |
| 2 | new backend | Per-auth OTP masking — `maskAuth` / `unmaskAuth` are per-auth today (~`fri.ts:596`, `:705`). |
| 3 | new backend | `authPreimageOpen` (`:395`) and `verifyFri` loop over all auths. |
| 4 | `covenant-spend.ts` | N note-auth kernels: `prefixExtraKernelCount` counts N, the successor adds N inputs, `compileFundVerifierKernels` mints N. Must stay behind a flag so the FRI9 path is byte-identical. |
| 5 | `registry.ts` | One row. No `FRI_VERSION` change anywhere. |

Item 4 is the only one touching shared code — gate it so FRI9 output does not
change by a single byte, and check that by re-running `pool measure-tx` and
comparing against A 87611 / B 498398 / C pay 89338.

## Size budget (measured)

A note-auth input is **1725 B** (1684 unlocking + ~41 overhead); the lock is 35 B.

| envelope | headroom in one tx | extra notes in one tx |
| --- | --- | --- |
| **B** (498398 B of 1 MB) | 501602 B | **290** |
| **C pay hop** (89338 B of 100000) | 10662 B | **6** |

**Those are per-transaction figures, and only B is bounded by them.** An earlier
draft claimed note-auth "cannot move to a tape hop because it reads
`<0> OP_UTXOTOKENCOMMITMENT` and only the pay hop spends the pool NFT". That is
**no longer true**: tape hops now carry a sibling NFT of the pool category at input
0, so `OP_UTXOTOKENCOMMITMENT`, `OP_OUTPUTTOKENCOMMITMENT` and `OP_INPUTBYTECODE`
are all available there. Nothing in the kernel needs the pool specifically.

So batch-exit on C scales by **hop count**: 320 hops against 32 MB
(`CHAINED_HOPS_MAX`, `CHAINED_TX_BYTES`). B is capped at ~290 by its envelope; C is
not capped by size. **For large batches C is the more scalable envelope.**

Two real constraints, neither about size:

1. **The batch must be known at genesis.** Note-auth asserts one insertion per
   kernel (`SHA256(oldNfRoot ‖ nf) == newNfRoot`), so N waiters need N distinct
   transitions and the siblings must be minted as a chain of intermediate nfRoots.
   Genesis mints them, so the round is fixed there. cqz is unaffected — it compares
   the noteRoot slice (64..96), and a withdraw with no change note leaves noteRoot
   equal (`note-auth-kernel.ts:47`).
2. **It changes the binding claim.** `C-BINDING.md` argues the siblings pin every
   hop to one statement; a chained-nfRoot design has hops attesting a *sequence*.
   That may be equally sound. It is not verified. Do not assert it.

## Test gaps to close at the same time

- No test walks more than one note. Add a batch case with N ≥ 2 that fails if any
  waiter's note is unchecked on chain.
- Add a VM case rejecting a **fake** extra note (the one-note version exists).
- Add a regression asserting the FRI9 family's compile sizes are unchanged.

## Do not change

- The note-auth kernel's checks. `amountCommit = SHA256(tag ‖ amount8 ‖ rho)`,
  `leaf = SHA256(amountCommit ‖ rho ‖ owner)`, `nf = SHA256(instance ‖ owner ‖ rho)`
  all stay. This is a count change, not a scheme change.
- The claim discipline. Until this ships and is tested, batch-exit extra notes are
  off-chain and `MILESTONE.md` keeps saying so.
