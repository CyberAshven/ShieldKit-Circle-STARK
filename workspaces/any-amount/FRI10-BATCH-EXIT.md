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

**Status: off-chain half BUILT and passing (commit `7289d13`); on-chain half open.**
`circle-fri-m31-batch` is registered beside `circle-fri-m31` and runs today via
`--plugin circle-fri-m31-batch`. `FRI_VERSION` is still 9 and was never bumped.
Six soundness invariants pass (`test/fri10-invariants.test.ts`), full suite 183/0,
and FRI9's compile sizes are byte-identical (A 87611, B 498398).

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

**Items 1, 2, 3 and 5 are DONE** (commit `7289d13`). Item 4 is the only one left,
and it is not what this document originally said it was — see below.

| # | Where | What | Status |
| --- | --- | --- | --- |
| 1 | new backend | `FriProof.auths: FriAuth[]`, length-prefixed in the encoding | **done** |
| 2 | new backend | per-auth OTP pads (`auth-pad.ts`) | **done** |
| 3 | new backend | verify checks every auth, count pinned to `withdrawalCount` | **done** |
| 4 | `covenant-spend.ts` | N note-auth kernels **on chain** | **open — redesign needed** |
| 5 | `registry.ts` | `circle-fri-m31-batch` beside `circle-fri-m31` | **done** |

What 1-3 turned out to mean, which was less than expected: FRI9 **already**
validates N notes correctly (`checkBatchSpends` — no duplicate index, positive
amounts, membership, non-zero nullifier, `sum == public net`), but only when the
**witness** carries them (`air.ts:141`). Without a witness it falls through to the
single-note check and rejects an honest batch with `"withdraw exceeds note"`
(`air.ts:144`), because `auths[0]` covers only its own amount. So FRI10 publishes
the auths and feeds them to FRI9's own audited path. `buildTrace`, the AIR and the
FRI layers are untouched and shared.

## Item 4: one nullifier insertion per transaction

The note-auth kernel asserts

```
SHA256(oldNfRoot || nf) == newNfRoot
```

reading `<0> OP_UTXOTOKENCOMMITMENT` for the old root and
`<0> OP_OUTPUTTOKENCOMMITMENT` for the new one (`note-auth-kernel.ts:106-122`).
Both come from **one** transaction, so a transaction has exactly one
`(oldNfRoot, newNfRoot)` pair.

N independent note-auth kernels in that transaction would each require
`SHA256(oldNfRoot || nf_i) == newNfRoot`. Distinct notes give distinct `nf`, so
that is **N distinct required values for a single output commitment —
unsatisfiable for N > 1.** Adding kernels to one transaction cannot work no matter
how many bytes are free.

### Verified five independent ways (2026-08-22)

This was double-checked before acting on it, because the whole item hinges on it
and an earlier claim in this work ("FRI10's exposure is closed") turned out to be
false when tested. Each check below is independent of the others.

1. **The assembly itself.** The withdraw branch after `OP_ELSE`
   (`note-auth-kernel.ts:126-175`) is literally
   `<0> OP_UTXOTOKENCOMMITMENT / EXTRACT_NF_ROOT / OP_SWAP / OP_CAT / OP_SHA256 /
   <0> OP_OUTPUTTOKENCOMMITMENT / EXTRACT_NF_ROOT / OP_EQUALVERIFY`. The indices are
   absolute `0`, so every kernel in a transaction reads the **same** input 0 and the
   **same** output 0 regardless of which input slot it occupies.
2. **There is only one kernel variant.** `compileNoteAuthLockP2sh32()` takes **no
   parameter**, unlike `compileSlotsLockP2sh32(slot = 0)` (`air-cqz.ts:1325`) and
   `compileFoldLockP2sh32(nFold = 1, queryIndex = 0)` (`fold-kernel.ts:162`). Kernel
   *i* cannot be made to differ from kernel *j*.
3. **Arithmetic.** For two real notes, the required new roots are distinct
   (`af276d46…` vs `d60501d3…`). One 128-byte commitment holds one value.
4. **No multi-note support exists anywhere.** Every call site of
   `compileNoteAuthLockP2sh32` / `noteAuthKernelUnlocking` emits at most one per
   transaction, and no covenant path counts note-auth inputs above one.
5. **Empirically, in the real BCH 2026 VM.** Building the transactions and running
   `vm.verify`:

   | scenario | result |
   | --- | --- |
   | state advanced by 1 note, kernel for that note | **accepted** |
   | same state, kernel for a *different* note | rejected, `OP_VERIFY` at its input |
   | both kernels in one transaction | rejected at the second kernel's input |
   | genuine 2-note batch exit, either kernel alone | **rejected** |
   | genuine 2-note batch exit, both kernels | **rejected** |

   The last two rows are the important ones. A real batch moves the root by two
   steps, `SHA256(SHA256(old ‖ nf₀) ‖ nf₁)`, which equals neither single-step value,
   so on a genuine batch **neither** kernel is satisfiable — not just "not both".

**Provenance.** The kernel came from commit `5f47e04` *"On-chain note Merkle,
nullifier, and amount/auth on B"*, written before this line of work. There is no
batch or N-note intent anywhere in the file. The one-note shape is original design,
not something a later change broke.

The claim stands: **N distinct required values for a single output commitment,
unsatisfiable for N > 1.**

Two ways out, both design decisions rather than mechanical work:

**A. One kernel per transaction, N transactions.** Envelope C only. Each tape hop
carries one note-auth kernel and advances the nfRoot by one step, with the genesis
siblings minted as a **chain of intermediate nfRoots** rather than all holding OLD.
Needs the batch known at genesis. No kernel change.

**B. Fold a list inside one kernel.** Change the note-auth kernel to walk N
nullifiers and assert the folded root in a single transaction. Works on B as well
as C, but it is a kernel change, and the kernels are the part the project has been
most careful about.

Whichever is chosen, gate it so the FRI9 path stays byte-identical and check that
with `pool measure-tx` against A 87611 / B 498398 / C pay 89354.

## Size budget (measured)

A note-auth input is **1725 B** (1684 unlocking + ~41 overhead); the lock is 35 B.

| envelope | headroom in one tx | extra notes in one tx |
| --- | --- | --- |
| **B** (498398 B of 1 MB) | 501602 B | **290** |
| **C pay hop** (89338 B of 100000) | 10662 B | **6** |

**Those byte figures are not the real constraint.** Item 4 above shows a
transaction can only make **one** nullifier insertion, so B — one transaction — can
walk **one** note on chain regardless of its 501602 free bytes. The 290 figure is
what the bytes would allow, not what the nfRoot chaining allows. An earlier
draft claimed note-auth "cannot move to a tape hop because it reads
`<0> OP_UTXOTOKENCOMMITMENT` and only the pay hop spends the pool NFT". That is
**no longer true**: tape hops now carry a sibling NFT of the pool category at input
0, so `OP_UTXOTOKENCOMMITMENT`, `OP_OUTPUTTOKENCOMMITMENT` and `OP_INPUTBYTECODE`
are all available there. Nothing in the kernel needs the pool specifically.

So batch-exit on C scales by **hop count**: 320 hops against 32 MB
(`CHAINED_HOPS_MAX`, `CHAINED_TX_BYTES`), one nullifier insertion per hop. Under
option A, **C is not merely the more scalable envelope for on-chain batch-exit — it
is the only one that works at all**, because B has a single transaction and
therefore a single nfRoot step.

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
