# Cohort engine runtime v1

This sibling package is a read-only runtime-closure preflight for Gate-B
cohort execution. The frozen `cohort-execution-v3` package is not modified.

The Native source is self-contained and intentionally unexecuted. It has no
imports, dynamic imports, `require`, filesystem, network, or native-addon
surface and consumes only construction/relation/operand bytes. Expected corpus
values are forbidden from the evaluator input.

The exact Libauth 3.1.0-next.8 static import graph is bound in
`libauth-input-graph.v1.json`. No acceptable installed deterministic bundler
exists on this host, so the Libauth bundle is deliberately absent and the
recipe is fail-closed. This package does not import Libauth or execute a VM.

The external descriptor binds host binaries, ELF interpreters, recursive DSO
targets, hashes, cwd, environment, argv/argv0, fd map, output cap, deadline,
and termination grace. It is host-pinned and unmaterialized; execution is
disabled until a package-local runtime image is separately authorized.

The three descriptor schemas are exact and closed. `semantic-validators.mjs`
additionally checks endpoint relations, installed-file identity, Libauth graph
closure/static imports, fail-closed receipt semantics, and full package
coverage. `structural-mutation.test.mjs` contains positive and negative KATs;
it never imports the Native source or Libauth and never launches a process.
