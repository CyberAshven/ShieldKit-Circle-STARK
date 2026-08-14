# PoolActionFv2 ABI-v3 falsifier contract

Status: `AUTHORIZED_SUCCESSOR_STATIC_FALSIFIER_CONTRACT_ONLY`.

This package is a static, row-complete adversarial contract for the ABI-v3 successor of the failed ABI-v2 route. The normative byte authority is the pinned `poolaction-fv2-relation-closure-charter-v3.md`; the ABI3 successor checkpoint is retained only as historical architecture input. It preserves every v2 contract row as `V2_RETAINED` lineage and adds the mandatory ABI3 families from the frozen charter. It does not execute relation falsifiers, BCH VM/node code, proof systems, or qualification work.

Every row has one of `PLANNED`, `MATERIALIZED`, `EXECUTED`, or `PASSED`. All rows in this package begin `PLANNED`; `metaValidation` records only contract/schema checks and never advances relation status. The top-level materialized, executed, and passed counts are therefore zero.

## Validation

```sh
node research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v3/validate.mjs --self-check
node --test research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v3/validate.test.mjs
(cd research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v3 && sha256sum -c SHA256SUMS)
```

The validator checks ABI3 namespace/version identity, exact retained lineage, exact additive family IDs, source pins, mutation metadata, status transitions, zero execution claims, and rejection of v2 namespace/magic/domain/schema reuse. It performs no BCH or VM execution.

Gate verdict: `PASS_STATIC_CONTRACT_ONLY_HOLD_RELATION_EXECUTION`. Independent recomputation and relation/VM falsifier execution remain HOLD.
