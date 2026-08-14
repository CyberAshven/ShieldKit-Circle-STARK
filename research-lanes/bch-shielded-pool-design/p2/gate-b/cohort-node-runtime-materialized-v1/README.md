# Cohort Node runtime materialized v1

This additive package freezes the package-local authority image for the fixed
Circle-FRI cohort: exact Node.js `v22.23.1`, Linux x86-64, its ELF interpreter,
and the exhaustive recursive six-DSO closure. Every image entry is a regular,
single-link file copied by bytes; no symlinks, hardlinks, host library lookup,
PATH lookup, inherited environment, native addon, or unlisted descriptor is
allowed.

The future direct-loader recipe is a typed template only:

```text
<package-absolute-root>/image/root/lib64/ld-linux-x86-64.so.2 --inhibit-cache --library-path <absolute-package-node-libdir> <package-absolute-root>/image/root/bin/node --no-addons <exact-reviewed-controller> --authorization-fd=3
```

The controller remains a later reviewed binding and is deliberately not
invented here. The exact replacement environment is `LANG=C`, `LC_ALL=C`,
`TZ=UTC`, and `NODE_ENV=production`. `NODE_OPTIONS`, loader variables, PATH
resolution, inherited variables/descriptors, and native addons are forbidden.

This is static materialization only. `executionAllowed`,
`imageLaunchQualification`, and `semanticQualification` are false. The Node
license text and GCC runtime exception notices are copied. glibc remains an
explicit metadata-only distribution-license gap; that gap does not become
launch, semantic, or execution evidence.

`generate.mjs --check` only reads and recomputes sealed bytes, ELF metadata,
dependency closure, schemas, canonical domain-separated digests, manifest,
and checksums. It invokes no subprocess and cannot rebuild or execute the
materialized image.
