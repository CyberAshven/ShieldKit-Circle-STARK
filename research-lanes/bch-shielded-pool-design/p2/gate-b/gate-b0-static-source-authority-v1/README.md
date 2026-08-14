# Gate B0 static source authority v1

Lifecycle form: static and non-operational.

This package resolves only authenticated static source-contract language required by the sealed Gate B0 execution-admission contract. It creates no provider, owner, fact, root, order, projection, private-byte, artifact-map, validator, attempt, runtime, result, evidence, qualification, ranking, selection, admission, or execution instance.

The 17 source contracts are generated from the raw-pinned upstream provider source map and UOPC using the exact primary-map aggregation contract. Existing catalogs remain constraint inputs, never source authority.

The independent-result-validator record is a source contract only. No implementation locator, hash, module, export, or source leaf exists here.

Lifecycle and closure:

1. The authored closure is exactly 24 files and 3 directories.
2. An unsealed package has only those 24 authored files. A sealed package, whether produced later or already present, has an exact 26-file closure: the 24 authored files plus paired `MANIFEST.json` and `SHA256SUMS`.
3. The sealed sibling review anchor remains outside the package closure.
4. Determine the package's on-disk lifecycle state from the paired presence or paired absence of `MANIFEST.json` and `SHA256SUMS`; this prose does not assert a transient state.

The package validator accepts an explicit `--mode unsealed` or `--mode sealed`. It never reads lane state.

Self-authentication boundary: a local validator cannot authenticate the raw bytes of the validator implementation that is already evaluating. Before any later import or CLI invocation, the external caller or lane must independently raw-pin and SHA-256-check `validate-static.mjs`. Sealed validation also requires the caller or lane to independently raw-pin the sibling review anchor outside the package; neither local source nor the anchor may self-certify those bytes.

Commands and tests validate a caller-selected lifecycle form only. No command, import, test, manifest, checksum file, or review anchor grants authority, creates an instance, or authorizes sealing, lane integration, admission, or execution.
