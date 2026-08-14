# External signed construction search v2

Labels: `heuristic`, `construction-only`, `not-family-elimination`,
`not-protocol-selection`, `external-cross-check-complete-not-evidence`.

This is an isolated SymPy 1.14.0 external construction search. It does not
modify or replace the external-cohort v1 evidence and does not select a field
or protocol construction.

Frozen search:

- targets `(q,d) = (31,5), (31,6), (61,3)`;
- `K=16`, with each nonzero coefficient ordered `-1,+1,-2,+2,...,-16,+16`;
- monic direct polynomial `x^d + sum(t_i x^i)`, `t0 != 0`;
- support 1, then support 2; secondary index ascending; `t0` then secondary
  value order;
- direct SymPy irreducibility is evaluated before score minimization;
- reduction rows use centered lifts and `R_k = -sum_i(t_i R_(k-d+i))` with
  `R_j=e_j` for `j<d`.

The independent run records the complete ordered 11,360-row transcript and its
SHA-256 digest. Expected diagnostics reproduced:

| Target | Tested | Irreducible | Winner coefficients `t0..t(d-1)` |
| --- | ---: | ---: | --- |
| M31/d5 | 4,128 | 752 | `[-1,2,0,0,0]` |
| M31/d6 | 5,152 | 831 | `[-5,0,0,0,0,0]` |
| M61/d3 | 2,080 | 650 | `[-5,0,0]` |

The checker-neutral transcript is independently generated at
`neutral-transcript.json`: 8,260,251 bytes, SHA-256
`58edd442a8700d9d2014f8d238ea6d7116e64baa427b3c89c33bc9d4878c20fe`, with
contentDigest `8eb2039920ae163c3584ca7a4b55ab5804f836760420b9cda185c4487ecf0dea`.
It is byte-identical to the frozen construction transcript only as a
post-generation cross-check; the frozen bytes are not read or copied by the
generator. `checker-transcript.json` is the separate 11,360-row SymPy
factorization/classification record and is bound independently in
`raw-output.json` and `MANIFEST.json`.

The prime boundary is the content-pinned Lucas--Lehmer fixture
`p2/field-cert/fixtures/frontier-prime-checks.v1.json`; this run does not claim
SymPy's primality API is the prime proof. `Poly.is_irreducible` supplies every
neutral-row irreducibility boolean. Polynomial support and L1 are computed over
the full monic coefficient vector, while signed lexical ranks cover only the
lower vector.

The scorer is implemented entirely in this Python command and does not invoke
the repository Node checker. Results remain heuristic construction evidence;
they do not establish BCH reduction cost, codec, VM, protocol, soundness, or
family elimination. There is no tuple/protocol/field-family selection here;
selection is `none`; this is an external cross-check, not qualification evidence.
