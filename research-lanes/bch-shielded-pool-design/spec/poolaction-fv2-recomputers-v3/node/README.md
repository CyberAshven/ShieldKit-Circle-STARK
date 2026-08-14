# PoolActionFv2 ABI-v3 Node recomputer

Standalone Node implementation derived only from the pinned charter SHA-256
`bb89cdc724aabefbe8f2dfced3c9e4934dc4ee48fecb92856b2982523cc81b4f`.
It imports no relation package, Python recomputer, fixture, or generated expected value.

Run `npm test`, then `node recompute.mjs raw-evidence.json`. The input must be
the exact `poolaction-fv2-recomputer-v3/raw-evidence-v1` JSON shape enforced by
the parser. Hex is lowercase, unprefixed, and every numeric wire value is its
exact fixed-width byte encoding. The result is canonical-key JSON and includes
all structural preimages as lowercase hex plus their digests.

The raw transport carries only lock-selected manifest bytes, anchor bytes,
complete introspected input/output observations, and two package-evidence
interface statuses. `sourceTableStatus` and `provenanceStatus` can only be
`NOT_SUPPLIED` or `SUPPLIED_UNVERIFIED`: the charter requires package schemas
and a leaf roster, but does not itself supply either artifact. They therefore
never contribute to an accepting verdict here.

This recomputer checks P3RT/P3TS, P3PI, P3DM, P3RI, P2SH20 locks, exact PAF1
state bounds, token observations, topology, economics, P3TV, P3SG, carrier
session, envelope, schedule, context, and session. A structurally valid input
always returns `REJECT_UNSELECTED_PROOF_SUITE`.

Nonclaims: no selected proof grammar or verification, BCH VM/node execution,
standardness, complete serialized transaction, proof/hash/field selection,
security, privacy, qualification, deployment, or activation evidence.
