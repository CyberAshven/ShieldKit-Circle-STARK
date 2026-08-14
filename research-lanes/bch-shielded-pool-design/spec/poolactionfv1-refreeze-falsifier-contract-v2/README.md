# PoolActionFv1 refreeze falsifier contract v2

Status: `BLOCKED_VERSION_PIVOT_NO_REFREEZE`  
Authority: none

This code-free package records the additive minimum falsifier-family contract
for a possible future PoolActionFv1 refreeze review. It contains 57 family
obligations and zero executable variants or expectation rows. Every family is
`PLANNED_NO_CREDIT`. The final variant count is intentionally `null` because
selected proof-session and deployment artifacts do not yet exist.

The family roster was transcribed from the root-supervisory matrix review. That
review was delivered in agent conversation and has no stable raw file pin.
Consequently, the roster requires a later outside-package review anchor and
this package is not a complete contract closure.

## Contents

- `matrix-roster.v2.json` records exactly 57 stable `RF-*` obligations in the
  required 12/4/9/7/18/4/3 group split.
- `variant-expansion.v2.json` records known finite axes and unresolved selected
  artifact axes. It is not a variant roster and contains zero executable rows.
- `stage-vocabulary.v2.json` fixes the semantic vocabulary permitted in a
  future immutable expectation ledger.
- `expectation-ledger-boundary.v2.json` fixes the zero-row boundary and
  separation/integrity rules for a future ledger.
- `expectation-ledger.v2.schema.json` is the exact schema for that future,
  nonempty immutable ledger. No ledger instance exists here.
- `independence-interface.v2.json` specifies producer, SUT, oracle, and
  comparator-only referee isolation.
- `source-pins.v2.json` pins the frozen inputs and closure packages. Its missing
  matrix-review raw pin is explicit.
- The remaining `*.schema.json` files validate the corresponding contract
  objects. `MANIFEST.json` and `SHA256SUMS` seal the package without
  self-reference.

## Frozen identity boundary

This package preserves the exact 589-byte PAST layout, `PAST` magic, relation
version 1, the historical `PCTX` TxContextFv1 preimage/domain/codec/inclusion
boundary, and the universal token-record grammar for kinds 0 through 4. These
are immutable preconditions, not newly established closures.

No selected digest, security profile, proof grammar, checkpoint, wrapper,
deployment manifest, concrete carrier lock, or runtime is supplied. The
future tool and evidence paths named in `independence-interface.v2.json` are
architecture references only and are not created by this package.

## Kill gates

Any of the following requires a separate Fv2 successor and forbids an Fv1
refreeze:

1. Changing PAST bytes, field order, relation version, or adding a
   proof-session root to PAST.
2. Changing the TxContextFv1 preimage, digest domain, codec version, or
   inclusion boundary.
3. Narrowing or expanding the universal token language instead of selecting an
   already-permitted concrete deployment.
4. Changing state, action, conservation, transaction shape, carrier lifecycle,
   or requiring another transaction or coordinator.
5. Hashing full proof bytes self-referentially.
6. Using the funding signature to bind sibling unlocking bytecodes.
7. Introducing a template, manifest, or concrete-lock digest cycle.
8. Leaving any required single-invariant falsifier accepting.

## Nonclaims

This package does not implement or execute a candidate, tuple, proof, script,
transaction, oracle, VM, node, or runtime. It grants no execution, blocker
closure, family closure, relation refreeze, measurement admission,
qualification, ranking, selection, promotion, or release authority. It does
not amend or supersede historical P0/P1 artifacts, the contradiction capsule,
the blocked disposition, or the v1 synthetic falsifier evidence.

