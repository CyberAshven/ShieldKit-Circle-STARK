# PoolActionFv1 contradiction capture v1

This immutable, additive capsule records four observed qualification blockers in
the current P0/P1 research material. It is evidence about the material named
in `source-snapshot.v1.json`; it is not a relation amendment, executable test,
transaction witness, cryptographic proof, BCH acceptance result, or selection.

The P0 freeze manifest currently contains **11** artifact entries. Earlier
planning text saying ten is stale; this capsule records the current 11-entry
manifest without modifying P0.

Every captured item is `observed-open-blockers-not-a-relation-amendment` and
blocks qualification, candidate selection, and beginning a full prover until
the relation is re-frozen through an authorized later process. The item-specific
boundaries are in `witness-boundary.v1.json`.

## Files

- `contradiction-capture.v1.json` is the four-item claim register.
- `source-snapshot.v1.json` pins the P0 manifest, all its referenced artifacts,
  and the five P1 source files used for the observations.
- `witness-boundary.v1.json` records the evidence tier and explicit non-claims.
- `contradiction-capture.v1.schema.json` closes the capture register.
- `COMMAND.txt` contains only inert parsing, hash, stat, line-display, and
  generic JSON checks. It must not be treated as an authorization to import or
  execute P1 or any BCH tool.

`SHA256SUMS` covers the other six files in the declared order and deliberately
does not self-hash.
