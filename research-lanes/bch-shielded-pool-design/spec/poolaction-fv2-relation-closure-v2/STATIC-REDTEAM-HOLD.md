# Static red-team HOLD

Status: `UNQUALIFIED_FAILED_ROUTE_P0_UNAUTHENTICATED_RUNTIME_FIELDS`.

The frozen charter/package bytes and their existing checksums are retained for
reproducibility. They are no longer an active implementation authority.

Independent counterexamples showed that the validator accepts a changed valid
deployment manifest without changing the state/carrier locked bytes, and that
the encoded action tag is selected by an unauthenticated caller field. The
field-source table is also incomplete. Hard Gate 1 therefore remains `HOLD`.

See
`../../analysis/poolaction-fv2-v2-static-redteam-hold-2026-08-14.md` for the
reproduced counterexamples and bounded repair requirements. No fixture,
recomputer output, or passing static test in this directory earns relation,
BCH VM, proof, measurement, deployment, or activation credit.
