# Gate-B formula schedule freeze

This directory freezes a premeasurement arithmetic-formula envelope only. It
does not implement a BCH kernel, run an engine, qualify a field, select a
tuple, assign a protocol role, or make a proof-system claim.

The generated artifact contains four direct-power-basis constructions and
fourteen precommitted arms: four canonical-schoolbook and ten optimized. Tower
arms for M31-d6 are internal coordinate schedules for the same direct
`Fp[x]/(x^6-5)` construction. Their inputs and outputs remain the direct
fixed-width little-endian power-basis codec.

Every field residue and interpolation-matrix entry is a canonical unsigned
decimal string. Intentionally signed formula constants (for example `-1` and
`-2`) are canonical signed decimal strings. JavaScript `Number` is never an
accepted field representation; structural indices and count declarations are
the only safe JSON numbers.

`generate.mjs` is deterministic. It constructs JCS-style canonical content
digest input, generates the Toom-5/Toom-6 finite evaluation and inverse
interpolation matrices with `BigInt`, and writes the artifact and digest
manifest only when invoked with `--write`.

Commands:

```sh
node research-lanes/bch-shielded-pool-design/p2/schedule-freeze/generate.mjs
node --test research-lanes/bch-shielded-pool-design/p2/schedule-freeze/schedule-freeze.test.mjs
cd research-lanes/bch-shielded-pool-design/p2/schedule-freeze && sha256sum -c SHA256SUMS
```

The external Fp6 source pin is rationale for the unimplemented M31-d6 r18
formula only. It is not imported, executed, or treated as measurement or
selection evidence.
