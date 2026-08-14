# PoolActionFv2 ABI-v2 interrupted recomputer evidence

Status: `UNQUALIFIED_FAILED_ROUTE_EVIDENCE_P0_MANIFEST_AND_ACTION_SOURCE_UNAUTHENTICATED`.

The Node recomputer and four N=1/N=3 deposit/withdrawal raw/KAT pairs in this
directory were created before independent static review found two P0 source
failures in the underlying ABI: deployment-manifest bytes were not
authenticated by the locked runtime bytes, and `actionTagHex` remained a caller
fact.

The files are retained to preserve the failed route. Raw-to-KAT recomputation
is internally consistent, but these artifacts provide no relation-closure,
independent-recomputer, BCH VM, transaction, proof, measurement, deployment,
or activation credit. Do not extend or use them as inputs to a repaired ABI.
