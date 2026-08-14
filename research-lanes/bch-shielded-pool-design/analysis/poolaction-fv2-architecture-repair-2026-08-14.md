# PoolActionFv2 bounded architecture repair

Status: `FAILED_STATIC_REVIEW_GATE_1_HOLD_UNAUTHENTICATED_RUNTIME_FIELDS`.

Adversarial update: the ABI-v2 attempt described below is preserved as an
unqualified failed route. Static counterexamples showed that the locked bytes
do not authenticate the caller-provided deployment manifest and that
`actionKind` has no byte-level authenticated source. See
[`poolaction-fv2-v2-static-redteam-hold-2026-08-14.md`](poolaction-fv2-v2-static-redteam-hold-2026-08-14.md).

This note records the root architecture ruling after the current-BCH
introspection audit. It authorizes a bounded relation-closure evidence package;
it does not refreeze the relation, select a proof suite, establish BCH VM
acceptance, qualify Hard Gate 1 or Hard Gate 5, or begin the full prover.

## Attempted repair (failed static review)

The attempted byte-level contract was
[`../spec/poolaction-fv2-relation-closure-charter-v2.md`](../spec/poolaction-fv2-relation-closure-charter-v2.md):

- relation identity remains `PoolActionFv2`, relation version `2`, ABI version
  `2`;
- runtime objects use the fixed binary codec defined by the charter, never
  Canonical JSON;
- native token observations are admitted only for the role-derived closed
  language `STATE_MUTABLE_NFT_ZERO` and `NONE`; no artifact may claim complete
  arbitrary CashToken introspection;
- `networkId` is an embedded deployment-domain label, not physical-chain
  identity or identical-history fork protection;
- the shared transaction view excludes evaluation-site-relative
  `OP_INPUTINDEX`; each role instead checks its manifest-fixed absolute input
  index locally;
- `N >= 1` manifest-fixed ordered carrier segments bind every complete carrier
  unlocking bytecode, the reconstructed envelope, and its schedule;
- runtime authority is the deployment commitment embedded before lock
  derivation; the full byte-origin/provenance DAG remains independent
  compile/deployment evidence and is never caller authority; and
- `UNSELECTED` proof-suite status always produces
  `REJECT_UNSELECTED_PROOF_SUITE`.

The charter also defines a deterministic always-failing structural template
compiler and genesis-evidence preimages for fixtures. Those bytes are only
relation-closure test material. They are not deployable covenants, standard
transactions, VM acceptance evidence, or proof verification.

## Preserved contradictions and residuals

The three introspection findings remain facts rather than being rewritten:

1. current native token projections collide for fungible-only and immutable
   empty-NFT records outside the admitted role language;
2. current BCH introspection exposes no physical mainnet/chipnet/regtest
   identity; and
3. `OP_INPUTINDEX` is evaluation-site-relative.

The repair narrows the accepted language or changes the authenticated
representation around those limits. It does not claim that the opcodes expose
more information than they do. Cross-chain replay on an identical deployment
history remains an explicit residual outside the frozen product contract.

## Superseded route

The v1 charter and v1 package are retained under
`SUPERSEDED_UNQUALIFIED_FAILED_ROUTE`. They receive zero closure credit because
they relied on an arbitrary token projection, physical-chain semantics, a
shared dynamic input index, runtime Canonical JSON, caller-facing provenance,
and a singular envelope slot.

## Current pin

At this checkpoint the active charter is exactly:

```text
lines   635
bytes   23967
sha256  aa1a63b17c74bc5f4f09c4c5009914a42c0942cd320cbf82fce6bad19d45191e
```

Reproduce with:

```bash
wc -l -c research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-charter-v2.md
sha256sum research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-charter-v2.md
git diff --check
```

## Evidence required before any refreeze

1. closed schemas and a validator that reject every extra field, injected
   digest, runtime selector, unsupported token role, and physical-network
   claim;
2. independent Node and Python recomputers deriving identical bytes and
   digests from raw inputs without importing one another;
3. deterministic deposit and withdrawal fixtures for carrier counts `N=1` and
   `N=3`;
4. a row-complete migration of every retained Fv1 falsifier plus additive Fv2
   controls for token, domain-label, role-index, carrier framing, provenance,
   and structural-template defects;
5. full falsifier execution with exact logs, hashes, and mutation accounting;
   and
6. a fresh root/SOL architecture review after the decisive results.

Until all six exist and pass, Hard Gates 1 and 5 remain `HOLD`, proof-suite
selection remains closed, and no complete-transaction, VM, standardness,
soundness, privacy, byte-fit, or prover-performance claim follows.
