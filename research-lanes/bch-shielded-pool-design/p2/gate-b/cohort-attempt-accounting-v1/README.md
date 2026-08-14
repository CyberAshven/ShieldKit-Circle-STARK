# Cohort attempt accounting v1

This is an immutable, post-hoc operator receipt for the authorized
`cohort-executor-v2` attempt-000 invocation. It records an aborted, unattested
invocation only. It is not VM evidence, does not contain raw streams or
observations, and cannot authorize execution, normalization, agreement,
metrics, ranking, or selection.

The recorded failure was the Lean primary aggregate parser rejecting the real
Lean `List String` rendering (`[id1, id2]`, without JSON quotes) as a JSON
string list. The host command exited 1. No attempt output package was
retained: the output directory was absent and the executor `runs` directory
contained only `.gitkeep`.

All v2 authority and executor package bindings are immutable. Any mutation of
the consumed authorization, contract, epoch, engine pins, manifests,
checksums, receipt, or causal state is rejected by `validator.mjs`.

This package has no runtime materializer or regeneration path.

The future structural core is
`validateFailureStructureNonAuthoritative(failureRoot, expectedAuthorityProjection)`.
It validates only a caller-derived *narrow structural projection*: endpoint
order and caller-supplied descriptors, lifecycle facts, durable stream slots,
caps, causal order, and the failure-package DAG. It deliberately does not read
authority, retry, epoch, engine, or entrypoint files; therefore a coherent
synthetic descriptor swap is structurally valid here. It neither discovers nor
authenticates v3 authority, and the projection is not the full SOL authority
model. A future v3 validator must authenticate its richer
authorization/contract/runtime context, narrow it to this projection, and then
call this core. Synthetic fixtures are test support only and are not imported
by production modules.

For a future controller-triggered external stop, the structural model records
ordered monotonic `killAttempts` separately from the observed process close.
Dispatch return/throw facts, requested TERM/KILL timing, and the observed exit
or Linux/Node signal are bound without asserting causal attribution: controller
closures carry `not-attributed-to-requested-signal`. These are lifecycle facts,
not benchmark timing or execution evidence.
