# Gate B0-R evidence plan v1

This is a static, nonauthorizing reconciliation contract. It creates no
candidate, tuple, provider instance, parameter assignment, execution
authority, measurement, qualification, ranking, or selection.

## Lifecycle

The source-stage contract is the unsealed, exact 15-authored-file form. A
mechanically sealed checkout has the same authored files plus `MANIFEST.json`
and `SHA256SUMS`. This document defines both states; it does not infer an
arbitrary checkout's state from prose.

`unsealed` accepts exactly the 15 authored files and rejects either envelope.
It checks the embedded lane projection against the live lane input. `sealed`
accepts exactly 17 files, recomputes the canonical manifest, domain-separated
raw-file digests, roster digest, and LF checksum rows, and does not read the
live lane.

Sealed validation requires an outside-package review-anchor pin supplied by
the caller: an absolute anchor root, safe relative locator, exact byte count,
and lowercase raw SHA-256. The validator has no environment fallback, anchor
auto-discovery, pin-file loader, or package-derived anchor hash. The caller
must obtain those values from an immutable external review record; constructing
them from the untrusted sibling anchor at invocation time is nonauthoritative.

Use explicit arguments in both modes:

```sh
# Source-stage package only
node validate-static.mjs --mode unsealed
node test/static.test.mjs --mode unsealed
node test/future-schema.test.mjs
node test/mutation.test.mjs --mode unsealed
node test/package-boundary.test.mjs --mode unsealed

# Mechanically sealed package, with caller-owned external pin material
node validate-static.mjs --mode sealed \
  --anchor-root "$B0R_REVIEW_ANCHOR_ROOT" \
  --anchor-locator "$B0R_REVIEW_ANCHOR_LOCATOR" \
  --anchor-bytes "$B0R_REVIEW_ANCHOR_BYTES" \
  --anchor-raw-sha256 "$B0R_REVIEW_ANCHOR_RAW_SHA256"
```

`static.test.mjs`, `mutation.test.mjs`, and `package-boundary.test.mjs` accept
the same explicit lifecycle arguments. Mutation cases copy only the authored
source closure before creating temporary envelopes and temporary external
anchors; they never convert a production anchor into a package authority.

The exported manifest helper is a shape validator only. It never trusts a
manifest's self-declared digest values. Sealed validation safe-reads the
caller-pinned anchor before accepting any closure claim and derives the file
bytes, raw-file framing, roster digest, and checksum rows anew.

Future measurement and adversarial semantic helpers likewise require an
externally maintained exact artifact-pin map. A map made from the untrusted
result or mutation record itself is only shape data and is not an admission
authority.

Filesystem walking rejects symlinks throughout and requires `nlink === 1` for
every external or package file. Directory link counts are intentionally not
used as a hard-link defense: they are filesystem-dependent and do not establish
file immutability. Directory type, non-symlink status, and realpath containment
are checked separately from file hard-link protection.
