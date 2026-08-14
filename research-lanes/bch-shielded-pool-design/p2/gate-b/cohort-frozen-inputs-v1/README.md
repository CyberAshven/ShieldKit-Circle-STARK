# Cohort Frozen Inputs v1

`F` is an isolated, static, content-addressed two-leaf binding for the P2
design lane. It accepts only `source-set-v1` and `cohort-freeze-v2`, and its
sole result is an immutable description of the exact accepted input bytes.

It is attempt-agnostic and non-authorizing. `executionAllowed` is false. It
does not create or carry an instance, authorization, claim, run, evidence,
metric, ranking, selection, process, worker, VM, live writer, or executable
endpoint. Build tooling is outside runtime authority: it reads bytes and JSON
only, never imports or runs a leaf program or artifact.

The validator fails closed over both leaf package closures: manifest file
records, checksum envelope, paths, modes, directories, symlink/hardlink state,
and exact accepted roots. Wrapper raw/file-content digests are distinct from
the source leaf's native semantic root. The freeze leaf has no native semantic
digest field and none is inferred.

`MANIFEST.json` is acyclic: it rosters every package file except itself and
`SHA256SUMS`; `SHA256SUMS` then binds that manifest and every rostered file.
All root, leaf, file, and manifest-roster digests are SHA-256 domain-separated
frames over canonical JSON or exact bytes.
