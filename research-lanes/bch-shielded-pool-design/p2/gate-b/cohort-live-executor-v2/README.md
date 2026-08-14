# cohort-live-executor-v2

This package is a bounded, non-executing pure model of the Gate-B cohort/live transition vocabulary. It neither opens files nor creates capabilities, handles, workers, callbacks, claims, runs, or external-guard satisfiers.

The only external authority is the exact raw P root pinned in `model-root.v2.json`. Its 22-edge prefix ends at `WORKER_ROWS_ROOT→D`; the six P downstream journal/observation/terminal edges are intentionally excluded. `J` grants no authority.

State is a canonical ordered subset, not an event log. `LIVE_F` may arrive before `Q`; after `Q` it normalizes to `[Q,LIVE_F]`. `A` requires `Q`; `B` requires `A` and `LIVE_F`; `C` requires `B`; `J` requires `B` and `C`. `D` is never admitted. In an initial state, `MATCH_D` is prerequisite-denied until `B,C,J` exist, then remains externally blocked by the unsatisfiable `WORKER_ROWS_ROOT` guard. Retry remains empty: `MATCH_Q` is blocked by `RETRY_PREDECESSOR`; no retry event can satisfy it. Abort is only `Q → A → CLOSE_ABORT`, after which all known events are closed-denied.

All semantic framed digests use SHA-256 of `UTF-8(domain) || 0x00 || canonical-json-utf8 || 0x0a`. Each manifest `fileDigest` instead uses SHA-256 of `UTF-8(file-domain) || 0x00 || exact raw file bytes`, with no appended LF. The pure closure is exactly `src/canonical.mjs`, `src/sha256.mjs`, `src/model.mjs`, and `src/state-machine.mjs`.

`validate-static.mjs` is build-time/read-only. It does not import the pure closure and reads no external artifact except the pinned P-root byte file for exact raw-hash and semantic-projection verification. It cannot self-authenticate a jointly mutated validator: future lane integration must independently pin the validator raw SHA-256 together with this root, manifest, and sums file.
