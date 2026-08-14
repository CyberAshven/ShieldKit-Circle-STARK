# P1 canonical semantic machinery

Status: implemented research machinery; not a proof system, deployable covenant,
valid spend, or qualification result.

P1 makes the frozen P0 language executable without selecting any field, hash,
accumulator, authorization scheme, Circle-FRI parameters, AIR, proof parser, or
carrier scripts:

- `codec/` implements the exact `PoolStateFv1`, token-record,
  `TxContextFv1`, and fixed transcript-statement byte codecs.
- `codec/statement-projection.mjs` bridges the JSON statement's exact payout
  lock to the transcript's domain-separated payout-lock digest. Withdrawal
  projection requires an injected digest adapter; no digest is implemented.
- `oracle/` checks deposit/withdrawal semantics and requires explicit injected
  facts/adapters for every still-unselected cryptographic predicate.
- `shell/` uses pinned Libauth to serialize deterministic proof-free BCH and
  CashToken fixtures, source outputs, and predecessor bundles.
- `integration.test.mjs` proves the schema, semantic oracle, codecs, projection,
  and shell agree on both actions. Its opaque digest result is test-only.

## Exact shell geometry under current fixture assumptions

The values below use one 128-byte mutable state NFT, deterministic 35-byte
P2SH32 state/carrier fixture locks, one 25-byte P2PKH external source, a
107-byte invalid-signature placeholder, and no change output. The two
**proof-free empty-shell** columns use zero-length proof-bearing placeholders;
they are transaction-structure lower bounds, not valid spends. The two
**unlocking-envelope** columns instead require at least one byte in every
proof-bearing unlocking bytecode and count each complete future
statement/wrapper/proof byte. They are not Circle-FRI proof-size estimates.

| Persistent carriers `N` | Proof-free deposit shell (zero proof bytes) | Proof-free withdrawal shell (zero proof bytes) | Deposit unlocking envelope (min 1 B/input) | Withdrawal unlocking envelope (min 1 B/input) | First binding limit |
| ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 491 B | 525 B | 20,000 B | 20,000 B | 10,000 B per input |
| 2 | 576 B | 610 B | 30,000 B | 30,000 B | 10,000 B per input |
| 5 | 831 B | 865 B | 60,000 B | 60,000 B | 10,000 B per input |
| 8 | 1,086 B | 1,120 B | 90,000 B | 90,000 B | 10,000 B per input |
| 9 | 1,171 B | 1,205 B | 98,809 B | 98,775 B | 100,000 B transaction |
| 12 | 1,426 B | 1,460 B | 98,554 B | 98,520 B | 100,000 B transaction |

This gives one early, non-cryptographic result: with these fixed-width output
locks, aggregate proof-bearing capacity scales by 10,000 bytes per state/carrier
input through `N=8`; at `N=9`, the whole-transaction limit starts binding. It
does not select `N`, because verifier partition costs and actual proof bytes are
still unmeasured.

## Evidence boundary

Real here: canonical protocol bytes, full-consumption rejection, exact Libauth
wire serialization, CashToken conservation, source-output encoding,
predecessor-bundle equality, satoshi accounting, and size arithmetic.

Not real here: proof generation/verification, cryptographic digest checking,
signatures, script execution, BCHN policy acceptance, concrete deployment
locks, privacy, soundness, prover speed, or a complete valid transaction.

Run all P1 checks:

```bash
npm run lane:shielded-pool:p1:test
```
