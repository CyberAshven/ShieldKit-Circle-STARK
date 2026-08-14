# Cohort engine runtime materialized v1

This is an additive, package-local materialization of the frozen
`cohort-engine-runtime-v1` preflight. The v1 package is not modified.

The package contains the exact Libauth 3.1.0-next.8 input graph, an esbuild
0.28.1 toolchain copied from the verified verifier.cash pnpm installation, a
deterministic single-file ESM bundle, and a regular-file Linux x86-64 image
for the three external endpoints and their 17-library recursive closure.

The bundle was built twice from distinct temporary roots with fixed locale,
timezone, source epoch, and no inherited environment. The output and
canonicalized metafile were byte-identical. The bundle is only statically
checked: it is not imported or evaluated. The image is only statically
checked: no loader, engine, VM, `dlopen`, or process launch was performed.

All qualification flags remain false:

- `executionAllowed: false`
- `bundleSemanticQualification: false`
- `imageLaunchQualification: false`
- `downstreamAuthorization: null`

The image preserves executable bytes and ELF metadata. Executable
`PT_INTERP`, recursive `DT_NEEDED`, DSO `SONAME`, RPATH/RUNPATH absence,
regular-file/single-link identity, package-local paths, license notices, and
source/image SHA-256 values are recorded. The two image workdir paths are
sealed `cwdTemplates`; a future launch must create a separate per-attempt
uid-owned 0700 fsynced CWD and must not write the package tree. The future
launch probe must invoke the package-local loader directly with
`--inhibit-cache` and an absolute package-root-derived library path; this
package deliberately does not perform that probe. Host fallback, inherited
loader variables, and `dlopen` behavior remain unqualified.

`generate.mjs --check` is static and non-mutating. The explicit
`generate.mjs --reproduce-check` rebuilds twice with the vendored native
esbuild in disposable roots and compares both outputs to the frozen package.
`validate.mjs` and the two test files perform only static JSON, byte,
metafile, ELF-header, and mutation checks; no bundle is imported and no engine
or VM is launched.
