# PoolActionFv2 authenticated-view introspection HOLD

Status: `HOLD_PENDING_ARCHITECTURE_REVIEW`

This note records a read-only architecture contradiction found before any
PoolActionFv2 refreeze, proof-suite selection, BCH execution, or measurement.
It grants no Hard Gate 1 or Hard Gate 5 credit.

## Scope and provenance

- ShieldKit-LABS: `c92e1f81176f6d196410e70564c50c2bdbd02cb9`
- BCHN: `864c53ee34924cca6c6b6d96607ff2cedcdccf02`
- CashScript/cashc vendor: `4b26f340243ca8c2be700940d72a2d5331dfa064`
- installed Libauth: `3.1.0-next.8`
- BCHN source SHA-256:
  - `src/script/script.h`: `fdd6f1326c72032b4eeb5cf6605b1153d47798e84f8a39a69a66d83a64fc52ed`
  - `src/script/interpreter.cpp`: `4fd02e84439fcc2bf6e2e3093d6a660e3ec3860aa8e14c00d259d438e27da5b4`
  - `src/primitives/token.h`: `5e77bc41c24e4995a1c9299512c1131a3dd9a1c8dcda1be7bab60c7cb367ad70`

The audit was source-only. It performed no network access, node or VM
execution, transaction construction, file mutation, or activation.

## Confirmed current-BCH mappings

The current native introspection surface authenticates transaction version,
locktime, the evaluation site's input index, ordered input/output counts,
input outpoints and sequences, source/output values and locking bytecode,
input unlocking bytecode, and the category/commitment/amount token projection.
The opcodes are defined at `src/script/script.h:188-210`; index bounds and
post-token-activation locking-bytecode behavior are implemented at
`src/script/interpreter.cpp:1948-1992`; token projection is implemented at
`src/script/interpreter.cpp:2076-2216`.

The source-derived current constants used here are:

- `MAX_CONSENSUS_COMMITMENT_LENGTH_UPGRADE12 = 128`;
- `MAX_SCRIPT_SIZE = 10000`; and
- `MAX_STANDARD_TX_SIZE = 100000`.

## Three blocking contradictions

### 1. Arbitrary complete CashToken records are not introspectable

`OP_*TOKENCATEGORY` appends a capability byte only for mutable or minting
NFTs. `OP_*TOKENCOMMITMENT` returns empty bytes for both no NFT and an NFT with
an empty commitment. `OP_*TOKENAMOUNT` returns only the numeric amount. The
locking-bytecode introspection opcodes return `scriptPubKey` without the native
token prefix after token activation.

Therefore a fungible-only token and an immutable-NFT-plus-fungible token with
the same category, amount, and empty commitment have the same observable
projection. A caller-supplied token kind or digest cannot repair this.

The narrower frozen role language may be repairable, but that is not yet an
approved conclusion: the state role requires mutable capability, amount zero,
and a nonempty exact 128-byte commitment, while all carrier, funding, payout,
and transparent-change roles require the token-free projection. The normative
claim must be role-specific and must not claim universal CashToken decoding.

### 2. Physical chain identity is not introspectable

No current BCH opcode exposes mainnet, chipnet, or regtest identity. A supplied
`networkId` is an injected fact. A deployment constant can authenticate a
deployment-domain tag, and exact genesis/category ancestry may make a pool
instance chain-specific in practice, but neither is evidence that the VM has
authenticated the physical chain. The relation must not claim otherwise.

### 3. `OP_INPUTINDEX` is evaluation-site-relative

`OP_INPUTINDEX` returns `context->inputIndex()` at the currently executing
input (`src/script/interpreter.cpp:1878-1910`). State and carrier roles at
different inputs therefore observe different values. A single shared canonical
transaction view cannot contain one dynamic active-input value while also being
byte-identical across every verifier role.

A possible repair is to omit the dynamic value from the shared view, encode a
fixed absolute role map, and require each concrete role to check its own
`OP_INPUTINDEX` against its compiled expected index. This remains pending the
architecture ruling.

## Additional seams exposed by the audit

1. The paused draft's `CanonicalJsonV1` authenticated view is not an
   on-chain-reconstructible codec claim. The relation needs a fixed binary
   encoding built directly from authenticated values.
2. Runtime roles cannot accept a caller-provided provenance DAG as authority.
   Full DAG and byte-origin recomputation belongs to independent
   compile/deployment-time recomputers; runtime roles may rely only on exact
   constants embedded by the proven concrete-lock derivation.
3. The current charter's single envelope-bearing slot is not justified while
   the verifier may require several persistent carriers and each unlocking
   script is limited to 10,000 bytes. Carrier count and proof-section schedule
   remain measurement variables. Any structural envelope must bind the exact
   ordered set of whole proof-bearing unlocking bytecodes without selecting a
   final count.
4. Normalizing only a parsed payload is insufficient: noncanonical wrappers,
   push encodings, or suffixes would remain outside the binding. External
   signature bytes also require an explicit non-circular exclusion rule.

## Current decision boundary

The normative and recomputer drafts are retained as failed-route evidence but
receive no closure credit. Work remains paused pending a root/SOL ruling on:

- the exact role-restricted token grammar;
- deployment-domain semantics versus physical chain identity;
- shared-view versus role-local input-index binding;
- multi-carrier whole-byte session framing; and
- compile-time provenance versus runtime authenticated constants.

Any repair must keep `PoolActionFv1` immutable, remain under a distinct
`PoolActionFv2` relation identity, preserve every frozen product and security
constraint, and introduce no injected digest, runtime selector, coordinator,
or activation authority.

## Reproduction commands

```bash
git rev-parse HEAD
git -C /home/toorik/Projects/BCH/bchn-src rev-parse HEAD
git -C /home/toorik/Projects/ZK-Proofs/verifier.cash/vendor/cashc-resched rev-parse HEAD
node -p "require('./node_modules/@bitauth/libauth/package.json').version"
sha256sum /home/toorik/Projects/BCH/bchn-src/src/script/script.h \
  /home/toorik/Projects/BCH/bchn-src/src/script/interpreter.cpp \
  /home/toorik/Projects/BCH/bchn-src/src/primitives/token.h
PYTHONPATH=/home/toorik/.agents/skills/bch-constants/src python -c \
  'import bch_constants; print(bch_constants.source_commit()); print(bch_constants.lookup("script size")); print(bch_constants.lookup("nft commitment")); print(bch_constants.lookup("tx size"))'
```
