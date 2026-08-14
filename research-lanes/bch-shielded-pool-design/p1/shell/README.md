# P1 proof-free transaction shells

This directory computes exact BCH wire bytes for the frozen `PoolActionFv1`
input/output topology while every deployment script and cryptographic proof
remains unselected.

`shell.mjs` deliberately produces **invalid-spend placeholders**, not candidate
transactions:

- state and carrier locks are deterministic 35-byte P2SH32 fixture locks;
- the transparent source is a deterministic 25-byte P2PKH fixture;
- proof-bearing unlocking bytecodes are opaque, length-exact placeholders;
- the external signature is also an invalid, length-exact placeholder; and
- no script VM, BCHN policy path, proof verifier, or signature verifier is run.

The serializer, CashToken prefix, mutable 128-byte commitment, source outputs,
predecessor bundle, role order, satoshi conservation, and transaction byte count
are real Libauth encodings. `maximumProofBearingUnlockEnvelope` is exact only for
those stated fixture lock/value/signature-length assumptions. Its result budgets
the **entire proof-bearing unlocking bytecodes**, including future wrappers,
statements, and proof sections. It is not a Circle-FRI proof-size estimate and
cannot qualify a carrier count.

Run:

```bash
node --test research-lanes/bch-shielded-pool-design/p1/shell/*.test.mjs
```

