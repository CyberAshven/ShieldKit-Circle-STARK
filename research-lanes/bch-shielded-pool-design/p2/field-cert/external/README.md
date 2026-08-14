# M89 external CAS replay

Labels: `external-cas-replay`, `component-only`, `root-reviewed-component-pass`,
`not-selection`, `not-protocol-qualification`.

This additive artifact replays the stored fixture
`fixture:m89-x2-plus-1-rabin-v1` with the independently maintained SymPy CAS,
pinned to SymPy `1.14.0` through isolated `uvx`. It checks that the stored
modulus is exactly `2^89 - 1`, that the stored polynomial is `X^2 + 1`, that
SymPy reports the polynomial irreducible over `GF(p)`, and that factorisation
returns the polynomial as one irreducible factor. It also obtains the
independent Legendre result `(−1/p) = −1`, which is the direct quadratic
irreducibility criterion.

The prime boundary is deliberately explicit. SymPy's generic `isprime(p)` is
recorded only as probable-prime corroboration for this input size. The replay
also calls SymPy 1.14.0's source-pinned private Lucas--Lehmer routine for
exponent `89`, which independently returns `true` after the algorithm's `87`
iterations. The fixture's separately stored deterministic Lucas--Lehmer
result (`87` iterations, residue `0`) remains the canonical certificate input.
Use of the private SymPy API is reproducible only because both the release and
source module are pinned. This replay is component evidence only and does not
select M89 or qualify any protocol.

## Reproduction

Run the commands in `COMMAND.txt` from the repository root. The first command
regenerates `raw-output.json`; the second runs the local tests. The UV cache is
outside the repository and is task-specific.

## Evidence verdict

PASS for independent SymPy polynomial irreducibility, factorisation, Legendre,
and source-pinned deterministic Lucas--Lehmer replay against the exact stored
fixture. The generic `isprime` result alone remains insufficient and is labeled
accordingly. Root review passes this independent component replay only; all
field-comparison, protocol-composition, and selection gates remain pending.
