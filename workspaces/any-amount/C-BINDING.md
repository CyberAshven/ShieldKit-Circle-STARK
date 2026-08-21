# Envelope C: what the tape chain does and does not bind

**Question.** B checks 36 unique-orbit queries in one transaction. C checks the same
36 across 19 transactions. Is C's chain equivalent, or is B strictly stronger?

**Answer.** B is stronger, and the gap is not nominal. C's per-hop verification is
real and enforced; what is *not* enforced is that the hops attest the **same
statement**. This is a script-level fact, not a conjecture.

## What C does enforce

Each tape hop is an ordinary transaction that must be valid to be mined. Its inputs
include the fold and R-slot kernel P2SH32 locks, and those locks run the real checks:
`foldPair` on the remaining FRI layers, and `(qTable − R)·Z == C(z)` at a
Fiat–Shamir index the lock **recomputes itself** (`fsIndexSlotAsm`, seeded from the
packed AIR) rather than accepting from the prover. A hop whose 2 queries do not
verify cannot be mined.

The pay hop spends the tape tip, so the 18 hops must exist on chain before the pay
transaction is valid. Skipping a hop leaves the tip unspent and the pay hop
references a missing input.

So: **18 hops of genuine verification work happened, and the pay hop cannot land
without them.**

## What C does not enforce

Nothing ties hop *i*'s statement to the pay hop's statement. Three reasons, each
checkable in the source:

| | |
| --- | --- |
| `chained.ts` `tapeCommit()` | `TAPE1 ‖ digest ‖ index ‖ hopCount ‖ chunkHash` is written into an `OP_RETURN` and **never read by any script**. Grep it: it appears where it is built and nowhere else. It is an annotation for observers. |
| `chained.ts` `compileTapeHop()` | Hop *i+1* spends hop *i*'s output 0, which is `p2pkhLockingOf(wallet)` — a plain P2PKH. The chain is held together by a **signature**, not a covenant. Any holder of the key can build any tape. |
| `covenant-spend.ts` tape carrier | On a tape hop, input 0 is the AIR carrier, whose lock is `OP_DROP OP_1`. The packed AIR is **dropped, not checked**. Each hop supplies its own. |

And BCH script cannot inspect an ancestor transaction's outputs, so the pay hop has
no way to read what the tape hops committed to.

The consequence: a prover holding the wallet key could compile each hop against a
*different* packed AIR — 18 statements, 2 satisfied queries each — and every hop
would be individually valid, the tip would exist, and the pay hop would land. The
chain proves "eighteen valid hops occurred", not "eighteen hops attested one
statement".

In B, all 36 slot kernels read one packed AIR inside one script evaluation. One
statement, 36 checks, atomically. That is the difference, and it is real.

## What this does not affect

**Completeness is unaffected.** Note Merkle, nullifier, and amount/auth run in the
note-auth kernel on C's pay hop exactly as on B — one transaction, one statement,
nothing deferred to `verifyFri`. The gap here is about the *tape*, not the note.

## What would close it

The pay hop can introspect **its own** inputs even though it cannot read ancestors.
So bind the tape tip's *locking bytecode* to the digest:

1. Lock each tape hop's output 0 to a P2SH32 script parameterised by `digest`
   instead of a bare P2PKH, so the tip's locking bytecode is a function of the
   statement.
2. In the pay hop's covenant, assert `OP_UTXOBYTECODE` of the tape input equals the
   lock derived from the statement the pay hop is verifying.
3. Have each tape hop's lock require the next hop to carry the same `digest`, so the
   parameter propagates instead of being re-chosen per hop.

That makes "the tip I am spending descends from hops committed to *my* statement" a
consensus fact rather than a convention. It is a covenant change to the tape, not a
proof-format change, and does not touch `FRI_VERSION`.

Until then the honest claim is the one already in `MILESTONE.md`: C matches B on the
completeness kernels, and C's 36 orbits are **not** same-tx binds.
