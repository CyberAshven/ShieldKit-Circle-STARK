# Cohort RuntimeBinding v1

This package is the static runtime authority for the five-endpoint cohort. It
binds exactly three independent leaves: the final materialized Node runtime
package (N), the reviewed endpoint-module package (E), and the existing
materialized BCHN/Lean external-runtime image (X). It freezes the ordered
endpoint union, codec/isolation boundaries, loader identities, DSO closures,
deadlines, output limits, replacement environments, and private workdir
templates.

R is static, attempt-agnostic, and non-authorizing. `executionAllowed` is
false. Concrete activation/attempt authorization and result data are absent
by schema; the static `runtimeAuthority` is the purpose of R. R never imports
an endpoint or references execution, journal, snapshot, or live-executor
packages. Paths in the authority are templates or package-relative provenance
records; no live CWD is selected.

The sealed envelope is produced only after independent E validation. The
generator stages a complete candidate in a same-parent temporary directory,
validates it, then publishes the three envelope files with no-replace links
under an exclusive fail-closed build-state record. This publication is not
treated as a set-wide atomic operation: a crash leaves the state record and
the next check reports manual recovery. The state record is never removed by
`--check`.

All checks are static byte, JSON, schema, native-manifest, closure, digest,
provenance, endpoint-union, and causal mutation checks. No image, endpoint,
loader, VM, authorization, or execution is launched.
