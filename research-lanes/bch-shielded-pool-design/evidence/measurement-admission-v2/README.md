# Measurement admission v2: immutable zero state

This sealed additive package records only a closed measurement-admission state. The PoolAction relation disposition is `BLOCKED_VERSION_PIVOT_NO_REFREEZE`; no relation is admitted, every candidate and measurement count is zero, and qualification, ranking, selection, execution, and full-prover start remain forbidden.

This record is immutable. It must not be changed to activate measurement. Any activation requires a separately authorized later additive record that binds an admitted relation and independently satisfies the closed authority boundary.

The typed gate plans preserve the frozen bounds without admitting work: relevant scripts at most 10,000 B; each complete serialized action transaction at most 100,000 B; complete local unilateral-withdrawal proving under 60 seconds on the pinned ordinary-desktop profile; and at least 128 bits of end-to-end complete-transaction soundness. The at-least-100-bit fallback is dormant and requires both a measured 128-bit complete-transaction failure and a separate authority record. No statistical aggregation rule is invented for the proving-time bound.

The six named evidence classes are planning-language only. They have no records, candidates, measurements, parameters, or execution authority. Existing preflight and cohort evidence is not imported and receives no ranking credit here.

The CPSB binding authenticates only its pinned static grammar and content-hash ordering. It contributes zero relation, authority, admission, execution, qualification, ranking, or selection credit. Its receipt remains externally TCB-bound, unsigned, replayable, and non-authorizing.

## Inert validation

Run only static JSON, checksum, roster, and upstream-pin checks from the repository root:

```bash
admission_pkg=research-lanes/bch-shielded-pool-design/evidence/measurement-admission-v2

test "$(find "$admission_pkg" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 5
test "$(find "$admission_pkg" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 0
(cd "$admission_pkg" && sha256sum -c SHA256SUMS)
jq -e . "$admission_pkg/admission.v2.json" "$admission_pkg/admission.v2.schema.json" "$admission_pkg/MANIFEST.json" >/dev/null
diff -u "$admission_pkg/admission.v2.json" <(jq -S . "$admission_pkg/admission.v2.json")
diff -u "$admission_pkg/admission.v2.schema.json" <(jq -S . "$admission_pkg/admission.v2.schema.json")
diff -u "$admission_pkg/MANIFEST.json" <(jq -S . "$admission_pkg/MANIFEST.json")

jq -e '
  .relationDisposition == "BLOCKED_VERSION_PIVOT_NO_REFREEZE" and
  .admittedRelationRef == null and
  .admittedMeasurementCount == 0 and
  .candidateCount == 0 and
  .authority == "NONE" and
  .b0ExecutionAuthorization == "CLOSED" and
  .immutable == true and
  .activation.thisRecordMayBeMutated == false and
  .activation.laterAdditiveRecordRequired == true and
  .executionAllowed == false and
  .qualificationAllowed == false and
  .rankingAllowed == false and
  .selectionAllowed == false and
  ([.counts[]] | all(. == 0)) and
  ([.liveState[] | length] | all(. == 0)) and
  .plannedEvidenceClasses == [
    "CIRCLE_DOMAIN",
    "MERKLE_PATH_MULTIPROOF",
    "TRANSCRIPT_ORDERING_DOMAIN_REJECTION",
    "DEEP_OOD",
    "FRI_SCHEDULE_INDEX",
    "MASKING_EXPOSURE_REUSE"
  ] and
  [.typedGatePlans[] | [.metric, .threshold, .quantifier, .scope, .failurePropagation] | length] == [5, 5, 5, 5, 5] and
  .typedGatePlans[0].threshold == {"comparator":"LTE","unit":"B","value":10000} and
  .typedGatePlans[1].threshold == {"comparator":"LTE","unit":"B","value":100000} and
  .typedGatePlans[2].threshold == {"comparator":"LT","unit":"SECONDS","value":60} and
  .typedGatePlans[3].threshold == {"comparator":"GTE","unit":"BITS","value":128} and
  .typedGatePlans[4].threshold == {"comparator":"GTE","unit":"BITS","value":100} and
  .typedGatePlans[4].lifecycle == "DORMANT_CLOSED" and
  .typedGatePlans[4].activationConditions == ["MEASURED_128_BIT_COMPLETE_TRANSACTION_FAILURE", "SEPARATE_AUTHORITY_RECORD"] and
  .bindings.cpsbExact29.relationCredit == false and
  .bindings.cpsbExact29.authorityCredit == false and
  .bindings.cpsbExact29.admissionCredit == false and
  .bindings.cpsbExact29.executionCredit == false
' "$admission_pkg/admission.v2.json" >/dev/null
```

These checks execute no authored project code, BCHN, Libauth, VM, Node, test harness, or network operation.
