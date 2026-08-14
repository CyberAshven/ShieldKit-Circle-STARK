# PoolActionFv2 falsifier contract v2

Status: `AUTHORIZED_BOUNDED_ABI_IMPLEMENTATION_NO_REFREEZE`

This package is the deterministic migration contract for all 57 retained
PoolActionFv1 falsifier families plus additive Fv2-only families required by
the v2 relation-closure charter. It grants no BCH execution, proof selection,
measurement, qualification, deployment, refreeze, or activation credit.

`contract.v2.json` contains exactly one mapping row for every retained `RF-*`
family and one row for every additive `F2-*` family. Rows distinguish:

- `CONTRACT_FROZEN`: ABI-level obligation and stable variant formula fixed;
- `DEFERRED_VM_OR_SUITE`: explicit later VM/proof/complete-transaction gate;
- `HISTORICAL_CONTROL_ONLY`: retained Fv1 control with no Fv2 closure credit.

No row is materialized or executed by the Node recomputer in this package.
`materializedVariantCount` and `executedVariantCount` are therefore zero.

The v2 repair is explicit in the rows:

- `networkId` is static deployment metadata, not physical-chain identity;
- the retained runtime-selection family is retargeted only to comparison of a
  disclosed label with the embedded deployment-domain label;
- identical-history fork replay remains deliberately undetectable;
- `OP_INPUTINDEX` is local role enforcement and is absent from `TxViewV2Bytes`;
- all `N >= 1` carrier full unlocking scripts are framed and session-bound;
- equal extracted payload under different full unlocking bytes remains a
  required session-root mutation;
- token observation admits only `NONE` and the state mutable-NFT-zero form;
- JSON, numeric endian/range, alias, caller-digest, caller-provenance, and
  runtime-provenance controls are explicit additive families.
- Structural always-false compiler, role-template, accepting-opcode, and
  genesis/provenance-preimage substitutions are explicit additive families.

## Validation

From the repository root:

```sh
node research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v2/validate.mjs
node --test research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v2/validate.test.mjs
for f in research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v2/*.json; do jq -e . "$f" >/dev/null; done
sha256sum --check research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-falsifier-contract-v2/SHA256SUMS
```

The validator checks duplicate-free row identity, exact 57-family coverage,
group totals, classification/status counts, additive-family presence, formula
and dependency fields, zero materialized/executed counts, and proof-rejected
status boundaries. It performs no BCH or VM execution.

## Source and authority boundary

The v2 charter is authoritative for the repaired ABI. The v1 roster and its
outside-package review anchor are preserved as historical source material.
The package-local source pins identify exact input hashes and the v2 charter
hash supplied by the root orchestrator. The validator re-hashes each local
pinned input and checks the charter byte/line counts. `MANIFEST.json` is closed
by `manifest.v2.schema.json`; `SHA256SUMS` excludes itself to avoid checksum
self-reference.

## Gate verdict

`PASS_CONTRACT_ONLY_HOLD_EXECUTION`: the mapping is row-complete as a contract,
but Hard Gate 1 remains HOLD until materialized fixtures, two independent
recomputers, independent review, and all deferred gates exist.
