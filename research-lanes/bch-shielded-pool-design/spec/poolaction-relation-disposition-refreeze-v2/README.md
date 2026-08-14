# PoolAction relation disposition/refreeze v2

This is an additive, inert disposition package for four observed PoolActionFv1
qualification blockers. Its binding status is
`BLOCKED_VERSION_PIVOT_NO_REFREEZE`. It preserves the raw bytes of all eleven
historical P0 artifacts and their declared aggregate; it does not amend or
supersede them.

The six normative objects record:

- the blocked disposition, exact historical/capsule pins, and Fv2 kill rules;
- the planned three-value network enum plus exact deployment-network pin;
- authenticated reconstruction, complete parsing, and digesting of the
  unchanged `TxContextFv1` boundary;
- typed, acyclic template-to-concrete-lock provenance with complete-script and
  no-`OP_CODESEPARATOR` identity;
- an acyclic proof-session wrapper/root/checkpoint/ordinal plan under which the
  state covenant at input 0 and every carrier authenticate the same sole anchor
  and session facts, while leaving the exact 589-byte `PAST` statement unchanged
  and never relying on a funding signature to bind sibling unlocking bytecodes;
  and
- the immutable `PAST`/`TxContextFv1` wire identity preconditions.

All four blocker dispositions remain `OPEN_BLOCKED`. The materialized
falsifier count is zero. The token-kind bridge is also open: the available
projection is non-injective for fungible-only versus immutable-empty-NFT.
Selecting an exact already-permitted deployment token kind (the simplest
candidate is token kind `none` for every carrier) is not the same as narrowing
the universal P0 token language, and this package does neither.

## Authority boundary

This package grants no execution, proof, measurement, admission,
qualification, ranking, selection, promotion, deployment, or refreeze
authority. It contains no selected proof system, digest implementation,
deployment manifest, runtime adapter, script template, concrete lock,
transaction, proof, prover, node result, VM result, Libauth result, or network
result. A future closure must materialize and reject each single-invariant
falsifier, satisfy every unchanged-wire precondition, avoid every Fv2 kill
condition, and receive a separate root/SOL refreeze ruling.

For the proof session, the state covenant at input 0 is the sole authoritative
all-section root enforcer: it recomputes every leaf from the ordered raw section
payloads read from all carrier inputs and recomputes the root from the exact
PAST, PAST-extracted profile and manifest digests, count, checkpoint, and leaf
sequence. Root-bearing wrapper bytes are excluded. Every carrier completely
parses its own wrapper, recomputes its local leaf, verifies its exact ordinal and
membership in the sole anchor's ordered leaf vector, and authenticates the same
state-enforced root. A self-supplied or per-carrier root is never authoritative.

Every carrier unlocking bytecode and every canonical pushed wrapper,
membership, section, section-payload, and redeem-script element is explicitly
bounded by the current 10,000-byte `MAX_SCRIPT_SIZE` and May 2025 element
ceiling. The u16 length fields are encoding fields only. The actual
`maxSectionPayloadBytes` remains unavailable and refreeze-blocking until the
concrete encoding derives `10000 - exact encoded wrapper/redeem overhead`; no
number is projected here. Complete-consumption evidence and an aggregate
standard transaction size at most 100,000 bytes remain a later qualification
gate and are not claimed by this package. These constants were checked against
BCHN source commit `864c53ee34924cca6c6b6d96607ff2cedcdccf02`.

## Inert static validation

Run from this directory. These commands parse JSON, validate each normative
object against the local Draft 2020-12 schema, verify the envelope checksums,
verify the pinned historical files and contradiction capsule, and recompute the
historical P0 aggregate. They do not import or execute project code.

```sh
for f in disposition.v2.json network-domain-fv1.v1.json tx-context-authentication-fv1.v1.json carrier-lock-provenance-fv1.v1.json proof-session-topology-fv1.v1.json fv1-wire-identity.v1.json normative-object.v2.schema.json MANIFEST.json; do jq -e . "$f" >/dev/null; done
python3 - <<'PY'
import fastjsonschema, json, pathlib
schema = json.loads(pathlib.Path('normative-object.v2.schema.json').read_text())
validate = fastjsonschema.compile(schema)
for name in (
    'disposition.v2.json',
    'network-domain-fv1.v1.json',
    'tx-context-authentication-fv1.v1.json',
    'carrier-lock-provenance-fv1.v1.json',
    'proof-session-topology-fv1.v1.json',
    'fv1-wire-identity.v1.json',
):
    validate(json.loads(pathlib.Path(name).read_text()))
    print('schema-valid', name)
PY
sha256sum --check SHA256SUMS
root='../..'
sha256sum "$root/spec/p0-freeze-manifest.json" "$root/security/threat-model-fv1.json" "$root/security/threat-model-fv1.schema.json" "$root/spec/pool-action-fv1.json" "$root/spec/pool-action-fv1.schema.json" "$root/spec/pool-config-fv1.json" "$root/spec/pool-state-fv1.md" "$root/spec/pool-state-fv1.schema.json" "$root/spec/responsibility-map-fv1.json" "$root/spec/tx-binding-fv1.md" "$root/vectors/pool-action-fv1/index.json" "$root/vectors/pool-action-fv1/index.schema.json" "$root/evidence/poolactionfv1-contradiction-capture-v1/contradiction-capture.v1.json" "$root/evidence/poolactionfv1-contradiction-capture-v1/SHA256SUMS"
python3 - <<'PY'
import hashlib, json, pathlib
root = pathlib.Path('../..')
manifest = json.loads((root / 'spec/p0-freeze-manifest.json').read_text())
preimage = b''.join(
    item['path'].encode() + b'\0' + item['sha256'].encode() + b'\n'
    for item in sorted(manifest['artifacts'], key=lambda item: item['path'])
)
assert hashlib.sha256(preimage).hexdigest() == manifest['aggregate']['sha256']
print(manifest['aggregate']['sha256'])
PY
```

`MANIFEST.json` inventories the eight non-envelope files. `SHA256SUMS` covers
those eight files plus `MANIFEST.json`; it intentionally excludes itself to
avoid checksum self-reference.
