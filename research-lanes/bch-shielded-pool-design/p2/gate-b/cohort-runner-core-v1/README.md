# Cohort runner core K v1

K freezes the mechanism boundary for a future binding. It contains no runtime
image, endpoint program, external byte payload, authority material, concrete
location, or activation permission. `executionAllowed` is permanently `false`
in its sealed metadata.

The public surface is intentionally small:

- retain and brand descriptor B only after strict validation and cloning;
- model exclusive C after B;
- open evidence-only J, which cannot grant authority and knows the dispatch-plan root
  but no D receipt;
- admit private D only when B, C, J, roster, plan root, and row root agree;
- derive worker envelopes containing identity and byte authority only;
- construct a purely in-memory journal index, then model private observation and fail-closed lifecycle
  transitions; and
- describe the storage and external-boundary contracts without opening files,
  launching programs, or writing evidence.

The brands are held in module-private weak collections. JSON, cloning, and
fresh objects cannot substitute for B, D, a journal entry, a journal index, or
an observation. A journal entry is authenticated from its J/D receipts,
sequence, prior chain root, kind, and event root; an observation additionally
requires that branded entry to be present in its branded ordered index. D is
never placed in a worker envelope. A later binder must provide any activation
capability; K exports none.

The storage model is exact but declarative: private directories and captures
use `0700`; created regular files use `0600` with `O_CREAT|O_EXCL|O_NOFOLLOW`;
the terminal protocol is Linux `renameat2(RENAME_NOREPLACE)` or fail closed.
Closed locators are one normalized segment, and sibling locators must be
disjoint. The model also requires a regular single-link object before capture.
The exclusive-C descriptor is paired with the same declarative `openat`-style
create contract; K never opens it.

The runtime core is exactly the closure declared in `runtime-core.v1.json`.
It has no CLI, writer, or import-time activation. `generate.mjs`,
`validate.mjs`, and `src/integrity.mjs` are explicitly build-time-only: the
sole `--seal` write is the deterministic `MANIFEST.json` and `SHA256SUMS`
envelope refresh. The sealed manifest binds that classification, and the
runtime-closure KAT proves the core import graph cannot reach build tooling.
`--check`, `validate.mjs`, and all tests only inspect bytes or in-memory
models. They do not launch endpoints, authorize, activate a worker, or emit
evidence.
