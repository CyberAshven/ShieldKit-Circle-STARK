# Direct-construction cohort v2

This directory freezes four exact direct-polynomial Rabin certificates in schedule order:

1. M89, degree 2, `X^2+1`.
2. M61, degree 3, `X^3-5`.
3. M31, degree 5, `X^5+2X-1`.
4. M31, degree 6, `X^6-5`.

The artifact is generic mathematical material only: `status` is `generic-math-certificate-set-frozen`, `evidenceClassification` is `not-evidence`, `selection` is `none`, `tupleRef` is `null`, and `protocolBoundary` is `component-only`. A replay-passing entry establishes only base-prime and direct-polynomial irreducibility for its exact bound construction. It makes no BCH-cost, field-family, proof-system, protocol, Circle-domain, execution, or systemic-soundness claim.

The certificate set binds the current construction summary, normalized transcript, and schedule-freeze files by repository-relative path, file SHA256, and content digest. It also pins the imported repository generator, replay, canonical, polynomial, and Mersenne source files. External review remains pending and is intentionally outside this canonical certificate set.

Run `node generate.mjs`, then `node --test direct-construction-cohort-v2.test.mjs`, `node repository-replay.mjs direct-construction-cohort-v2.v2.json`, and `sha256sum -c SHA256SUMS`.
