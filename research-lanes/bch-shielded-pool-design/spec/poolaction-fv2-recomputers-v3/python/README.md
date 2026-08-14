# PoolActionFv2 ABI-v3 independent Python recomputer

This directory is an independent structural recomputer derived only from the
normative charter:

`research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-relation-closure-charter-v3.md`

Pinned authority: 1,064 lines, 42,494 bytes, SHA256
`bb89cdc724aabefbe8f2dfced3c9e4934dc4ee48fecb92856b2982523cc81b4f`.

`recompute.py` accepts strict raw/source evidence JSON, parses the P3DM/P3PI,
P3RI/P2SH, PAF1, token, P3TV, P3SG, carrier-session, envelope, schedule,
context, session, template, anchor, ancestry, source-table, and dependency
interfaces, and emits canonical lowercase hexadecimal preimages and digests.
Raw runtime numbers use exact 16-digit lowercase LE8 strings; the anchor
output index uses exact eight-digit BE4 hex. Token tags and role instances are
derived from the fixed topology, while the state active redeem is checked
against the manifest-derived P3RI/structural redeem and source lock.
Malformed, noncanonical, incomplete, out-of-range, cyclic, caller-authority,
and reserved inputs fail closed with stable error codes.

The only structural positive result is
`REJECT_UNSELECTED_PROOF_SUITE`. Proof selection, proof acceptance, BCH
VM/node execution, complete transaction construction, standardness, byte
measurement, soundness, privacy, qualification, deployment, and activation are
explicitly unclaimed. No relation fixtures, generated expected values, Node
code, network, or proof parameters are consumed.

## Checks

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-recomputers-v3/python \
  -p 'test_*.py' -v
python3 -m json.tool \
  research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-recomputers-v3/python/raw-evidence.schema.json \
  >/dev/null
python3 -m json.tool \
  research-lanes/bch-shielded-pool-design/spec/poolaction-fv2-recomputers-v3/python/derived-result.schema.json \
  >/dev/null
```

CLI usage:

```sh
python3 recompute.py raw-evidence.json -o derived-result.json
```

The package currently contains only self-constructed primitive and structural
vectors. It does not claim fixture agreement or relation closure.

The charter specifies the permitted source classes and coverage obligations,
but does not publish a machine-readable leaf-identifier vocabulary. This
implementation therefore does not invent one: its source-table interface
rejects malformed, duplicate, wildcard, and invalid-class entries, while the
full exact leaf-roster comparison remains an explicit HOLD item.
