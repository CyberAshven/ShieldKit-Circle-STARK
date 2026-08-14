# Gate B1 profile-identity interface v1

This exact five-file package is a detached, intentionally unsealed, schema-only draft of the four-layer profile-identity interface authorized by `gate-b1-profile-identity-interface-authority-v1`.

The acyclic identity order is `primitiveTupleId -> candidateId -> proofProfileId -> deploymentProfileId`. Each future downstream preimage exposes only its immediate upstream identity layer. All four current identity layers remain uninstantiated, with null identity values, preimage-schema bindings, and digest algorithms. The candidate preimage plan keeps `relationSemanticsId` null and unassigned outside the eleven core fields; it contains no successor-artifact digest.

The root records the exact eleven core-field owners, three proof-session subrole owners, and eighteen multi-layer surface owners without assigning any role, parameter, profile, candidate, tuple, relation version, or pending surface. Identity-layer digest algorithms remain distinct from the unassigned proof-session `DIGEST_ALGORITHM` axis.

The source decision and source snapshot are raw-byte and semantic-digest bound. Their snapshot transitively pins exactly fourteen upstream source files. Legacy raw remains absent, source closure remains false, and `UOPC_EAC_FUTURE_PROVIDER_DAG_DIVERGENCE` remains unresolved.

The JSON root is constrained by the three local Draft 2020-12 schemas under `schemas/`. There is deliberately no manifest, checksum list, command, validator, test, review anchor, package identity, lane binding, or executable. This package is prospective, unratified, grants no lane credit or gate effect, and authorizes no later work.
