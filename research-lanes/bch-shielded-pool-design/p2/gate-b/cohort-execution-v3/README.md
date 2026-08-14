# Cohort execution v3: static contract only

This package freezes attempt-001 execution semantics after the sealed attempt-000 abort accounting and retry wrapper. It contains no authorization, run directory, evidence, VM evaluation, process invocation, metrics, ranking, or selection.

The inherited epoch, four v2 engine records, source-set, canonical corpus, fixture/work rosters, retry wrapper, and accounting envelope are raw-byte and content-digest bound. The contract fixes 4,732 fixture rows per engine, 18,928 terminal obligations, 124 preflight fixtures (496 obligations), 15 metric identifiers, and 70,980 metric cells per engine.

The only admissible comparison surface is arithmetic component/script-engine behavior. BCHN transaction checks are explicit unsupported and no complete pool transaction or policy claim is made. Lean `vmbconf` is aggregate corroboration only; CostProbe is the per-item authority for `verifyInput` and six exposed metrics, and every eligible `SKIP` or malformed line is fail-closed.

A later separately authorized executor may use the external one-use authorization transport and external run base fixed by this contract. Before any engine it must durably create the exact exclusive no-follow attempt claim, then stage a complete attempt, validate it fully, and atomically no-replace rename the whole container to either `success` or `failure`; partial results are never reusable. A complete success has 26 payloads and 28 container files, including byte-exact authorization and claim copies.
