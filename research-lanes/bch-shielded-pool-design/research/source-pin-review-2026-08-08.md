# Circle-FRI blocking-source review — 2026-08-08

This note records source identity only. Content pinning makes a construction
eligible for analysis; it does not select it, validate its security argument,
or qualify it on BCH.

## Zero-knowledge note

The current IACR metadata for ePrint 2024/1037 reports revision
`2025-02-22T13:42:00Z`. An Internet Archive `id_` replay captured after that
revision returns the original IACR PDF bytes. Its CDX SHA-1 digest was also
independently recomputed and matched.

```text
official source: https://eprint.iacr.org/2024/1037
exact replay:    https://web.archive.org/web/20250722110926id_/https://eprint.iacr.org/2024/1037.pdf
bytes:           457880
sha256:          b6bd98453a64b26c7a08bf02fe9f82f3bde7dd730ecaa3fe9769b1e0f15cf270
sha1/base32:     AYJSL6IMJQZHQCXCMLIJQJXJMTBW63A3
pages:           21
```

The paper makes witness masking, quotient decomposition, the complete opened
view, and permutation-argument leakage explicit. It is a design-warning and
analysis source, not a drop-in ZK construction for `PoolActionFv1`. Its source
gate is now open; the leakage worksheet, simulator argument, repeated-proof
tests, and root/SOL review remain mandatory.

## RPO-M31 / XHash-M31 provenance

The initial ePrint 2024/1635 PDF is preserved as historical construction input:

```text
exact replay:    https://web.archive.org/web/20250527213018id_/https://eprint.iacr.org/2024/1635.pdf
bytes:           745346
sha256:          677a0badfb8996ca3c5e0d604d13d442c1967c19ae6c899ab06e565b641f4641
pages:           18
```

It is not current selection authority. The official 2024/1635 page, revised
`2026-05-15T09:00:30Z`, says the work was merged into ePrint 2023/1045 and
instructs readers to use the merged version. The pre-merge 2023/1045 artifact
is also retained only to preserve the earlier XHash-family lineage:

```text
exact replay:    https://web.archive.org/web/20260113164224id_/https://eprint.iacr.org/2023/1045.pdf
bytes:           728806
sha256:          bdf95685639a47e3575e40b1efe1d1306e4a1da9681f82745ccea6c957b1bbc3
pages:           14
```

The exact current metadata pages were content-pinned:

```text
2024/1635 HTML sha256: bb42818fa6e6bcf6706c973a02d49bf6eb5fd17adf8e1bdb7253402c82377340
2023/1045 HTML sha256: dbda71c5fdb93679dcd9e8181cdc4506987de2e82419fd7379066c0a1e01a68e
2023/1045 revision:    2026-05-11T14:08:47Z
```

The current merged 2023/1045 PDF has not yet been retrieved and content-pinned.
The algebraic-hash row therefore remains blocked. Historical parameters may be
used for a cheap negative/control measurement, but no widened
RPO-M31/XHash-M31 security claim or selection may rely on them alone.

## Selection consequences

- `zk:trace-composition-fold-preserving` moves from source-blocked to
  unmeasured; its cryptographic/ZK gate is still unrun.
- `hash:rpo-m31-widened` remains source-blocked until the current merged PDF is
  content-pinned and its exact parameters and security claims are reviewed.
- SHA-256, algebraic hashes, fields, masking, AIR layout, FRI schedule, and
  carrier topology all remain unselected.
