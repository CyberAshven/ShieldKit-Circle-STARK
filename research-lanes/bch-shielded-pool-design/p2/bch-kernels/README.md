# P2 BCH kernel: canonical M31 multiplication

Status: measured isolated Script fixture; not a field/tower/Circle/hash/AIR/proof
selection, deployable covenant, complete transaction, BCHN result, or qualification.

This thin adapter exercises only the neutral `field:m31-base-control` substrate
shared by the still-unselected M31 extension rows:

```text
p = 2^31 - 1 = 2147483647
raw element = exactly four unsigned little-endian bytes
accepted raw element iff unsignedLE32(raw) < p
accepted relation iff c = a * b mod p
```

Before `OP_BIN2NUM`, the locking program duplicates each exact-four-byte raw
word and appends a generated literal zero byte (`OP_0 OP_1 OP_NUM2BIN OP_CAT`).
`raw || 00` is a positive ScriptNum encoding of the complete unsigned 32-bit
value, so the subsequent `< p` check cannot reinterpret a high-bit value as a
negative number or negative zero. This rejects `ffffff7f` (`p`), `00000080`
(`p+1`), `01000080`, and `ffffffff`; no numeric mask test is used.

The exact locking script is 78 bytes:

```text
82549d760051807e81777600a2697604ffffff7f9f697c82549d760051807e81777600a2697604ffffff7f9f697b82549d760051807e81777600a2697604ffffff7f9f696b9504ffffff7f976c9c
```

The full-product boundary fixture is `(p-1) * (p-1) mod p = 1` with unlocking
bytes `040100000004feffff7f04feffff7f` (15 bytes). It proves only that current
native Script arithmetic accepts this 62-bit intermediate before `OP_MOD`; it
does not establish any extension arithmetic or FRI relation.

On the pinned `@bitauth/libauth 3.1.0-next.8` standard-mode fixture, the boundary case measures
65 evaluated instructions, 0 signature checks, 0 hash iterations, arithmetic
cost 57, 114 pushed stack bytes, and operation cost 6,671. Its measured maxima
are 6 primary items, 1 alternate item, 6 cumulative memory items, and an 8-byte
largest element. Against the 44,800 operation-cost budget it retains 38,129
headroom. The existing LeanBCH `costprobe` reports the same acceptance and all
six metric values for this exact transaction/source-output wire fixture.

The fixed corpus contains 30 acceptance/rejection cases, including the full
width-transition list, `p`, `p+1` negative-zero, `p+2`, maximum-u32, lengths
0/1/2/3/5/6, a wrong product, `(p-1)^2`, and `(p-2)^2`. Libauth standard mode,
the native BCHN standard script leg, and LeanBCH agree on all 30 verdicts.
Libauth and LeanBCH agree on all six raw metrics for the primary boundary; BCHN
agrees on the operation cost, hash iterations, and signature checks its leg
exposes. The synthesized fifth-zero mutation is a separate regression test.

Artifact SHA-256 values emitted by
`run.mjs` are locking `0800aa8e43d2d413ef69b7769fc12527ed1eea53fea8941f940931062a6622c0`
and boundary unlocking `ed83d2a66b2471e982f18ae967e3c5b2fe9e0d0c8f86a2ce72ba29752130cf33`;
the synthetic transaction and source-output wires hash to
`3e49a284e31daa125d4aaf02b9f0a5ffbbbdb077b7ef929f298109d09d212f7d` and
`bbc148678eee166973897e3ff3b43fb3a7783f6361a78b42d1fc55d947fdea79`.

Run from the repository root:

```bash
node --test research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.test.mjs
node research-lanes/bch-shielded-pool-design/p2/bch-kernels/run.mjs
```

`run.mjs` uses standard-mode `@bitauth/libauth` BCH-2026 evaluation with debug
traces, the native BCHN `bchn-leg --mode standard`, LeanBCH `vmbconf`, and
LeanBCH `costprobe`. The existing loose optimizer-cost adapter is emitted only
under `diagnostics` and never treated as evidence. A missing engine or
non-comparable reject metric is reported explicitly; no value is synthesized.

The compact, strict-schema evidence record is
[`../evidence/m31-base-mul-v1.json`](../evidence/m31-base-mul-v1.json). Its
status remains `partial`: addition, subtraction, negation, square, inverse-hint,
and deterministic randomized/metamorphic corpora must still pass before the
neutral M31 base gate can advance.

Current-rule provenance is [the pinned BCH profile](../../profiles/bch-current-2026-08-08.json):
100,000-byte standard transactions, 10,000-byte scripts/stack elements, and
128-byte NFT commitments. This kernel is far below those byte limits, but it is
not a policy or complete-transaction qualification result.
