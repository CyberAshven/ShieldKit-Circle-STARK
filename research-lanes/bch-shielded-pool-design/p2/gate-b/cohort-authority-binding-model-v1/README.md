# Cohort authority-binding model v1

Status: `static-authority-binding-catalog-non-authorizing-external-origins-unavailable-unqualified`.

This is a static requirements catalog. Its final envelope records only pinned byte/type relationships and abstract fact grammar. It creates no authority, admits no live origin, and has no I/O, construction, transition, replay, writer, endpoint, worker, or runtime surface.

The pinned authority DAG is the exact 17-node, 22-edge v2 prefix. Static dependencies are ordered `R`, `K`, `F`, `P`, `V2`. The catalog keeps the three unavailable external origins distinct from the seven abstract facts:

- `RETRY_PREDECESSOR` is required only for retry `Q`; retry therefore stays empty and `BLOCKED_EXTERNAL`.
- `LIVE_F_CAPTURE` is an unavailable private capture origin. `LIVE_F_TEMPLATE` is a P static template and `LIVE_F` is an abstract, non-authorizing fact; neither static material satisfies capture.
- `WORKER_ROWS_ROOT` remains unavailable. `D` is prerequisite-denied until `B`, `C`, and `J` are present, then remains `BLOCKED_EXTERNAL`.

Every catalog entry has `grantsAuthority:false`. Static authenticators are byte/type identifiers, never facts or state predecessors. `J` has exactly `B`,`C` state predecessors and remains non-authorizing. Abort-close, crash policy, `J`, and `D` cannot synthesize `RETRY_PREDECESSOR`.

The catalog intentionally separates P's 4,608 workloads per endpoint from K's 1..4,096 worker rows per dispatch plan. No equality, ratio, batching rule, row ordering, row-root domain, or projection is authenticated. K worker aliases are `native`, `libauth`, `bchn`, `leanbch-primary`, and `leanbch-secondary`; they are not interchangeable with `engine:*` labels.

`validate-static.mjs` is a read-only build-time checker. It checks static upstream raw pins, root semantics, schema closure, pure source boundaries, the canonical manifest, and checksums. It cannot establish integrity if it and the sealed package bytes are changed together. Any future lane integration must independently pin the validator raw SHA-256 together with the root, manifest, and checksum bytes.
