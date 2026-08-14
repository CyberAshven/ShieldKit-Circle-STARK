# External cohort CAS replay v1

Labels: `external-cas-replay`, `external-cohort`, `component-only`,
`root-review-pending`, `not-selection`, `not-protocol-qualification`.

This isolated artifact challenges the first arithmetic shortlist using SymPy
1.14.0 through pinned `uvx`. It searches monic direct polynomials with a
nonzero constant coefficient. Coefficients are unsigned and ascending
`c0..cd`, with the monic coefficient fixed to `1`. The frozen total order is:

```text
coefficientBound = 1, then 2, then 3;
nonzero coefficient weight;
lexicographic ascending coefficient tuple
```

The search stops at the first directly irreducible polynomial and retains
every rejected predecessor. The exact winners are:

| Base | Degree | Polynomial | Ascending coefficients | Predecessors |
| --- | ---: | --- | --- | ---: |
| M31 | 5 | `x^5 + x^4 + x^3 + x^2 + 1` | `[1,0,1,1,1,1]` | 11 |
| M31 | 6 | `x^6 + x^5 + x^3 + x + 1` | `[1,1,0,1,0,1,1]` | 21 |
| M61 | 3 | `x^3 + x^2 + 2` | `[2,0,1,1]` | 7 |

The raw output also enumerates every directly irreducible binomial/trinomial
(`nonzeroWeight <= 3`) reached in the complete bounded coefficient window
through bound 3, so later cost review has a fixed candidate set rather than a
post-measurement cherry-pick.

Three separately supplied root challenge inputs are tested verbatim as signed
polynomials: M31/d5 `x^5 + 2x - 1`, M31/d6 `x^6 - 5`, and M61/d3 `x^3 - 5`.
SymPy reports all three directly irreducible with one factor. They are outside
the primary nonnegative bound-1..3 search domain, so the raw output records
that exclusion and an empty predecessor set rather than silently substituting
them into the canonical winners.

SymPy directly reports each winner irreducible and factorization returns one
factor with multiplicity one. The existing content-pinned deterministic
Lucas--Lehmer frontier fixture is the primality proof input; SymPy `isprime`
is recorded only as probable-prime corroboration for these input sizes. The
small deterministic Lucas--Lehmer replay in the external command checks the
fixture residue and iteration count; it is not substituted for the fixture's
canonical proof provenance.

This does not freeze a descriptor, codec, tower, role assignment, Circle,
soundness worksheet, field selection, protocol selection, or performance claim.
Root review remains pending.
