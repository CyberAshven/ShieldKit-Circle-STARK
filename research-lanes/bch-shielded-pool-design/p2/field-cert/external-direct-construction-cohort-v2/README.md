# External direct-construction cohort v2 review

This directory is an independent, pinned Python 3.13.12/SymPy 1.14.0 replay
of the frozen direct-construction certificate cohort. It reads the exact JSON,
schema, and repository raw replay report bound in the source artifact, but
does not import or invoke repository JavaScript, repository Python checkers, or
any process bridge.

Two checker families are explicit in every entry:

- `python-stdlib-certificate-replay`: canonical envelope checks, independent
  trial-division primality of q, complete Lucas--Lehmer replay, polynomial
  Frobenius/Rabin arithmetic, prime-divisor inventory, gcds, and Bezout checks.
- `sympy-cas-irreducibility`: `Poly.is_irreducible` and `factor_list` exact
  polynomial verification.

All four entries pass. The report records exact certificate and normalized
statement digests. Statements are canonical minified UTF-8 JSON over
`certificateEntryId`, `constructionId`, `fieldSpecRef`, `q`, `p`, `degree`, and
`polynomialCanonical`, with sorted keys and one LF in the containing artifact.

This is certificate evidence for exact prime and direct-polynomial
irreducibility only. It makes no BCH-cost, field-family, proof-system,
protocol, Circle-domain, systemic-soundness, tuple, or selection conclusion;
selection is `none`.
