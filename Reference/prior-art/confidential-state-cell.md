# Prior art: Confidential Protocol State Cell (Chipnet demo)

Public Chipnet facts below.

## Public chain facts

- Txid: `be8b9832a2a95bf9b09838cb085bc667e9eedacd2c71ae8422269816ca93737b0`
- Token category: `639ec70a6c555246d62e2473fb5395b4e858b9d533be33815b3a883bb77ca53f`
- Version 2, 1 input, 13 outputs
- Output 0 (Plane A): 51,000 sats, mutable NFT, 128-byte CEv1 commitment
- Outputs 1–12 (Plane B): 1,000 sats each, immutable NFT, OP_TRUE, 128-byte ML-KEM-768 packets
- Fee: 5,000 sats (~1.93 sat/B)
- No transparent change
- ShieldKit later observed output 0 still unspent at their observation — **no proof-bearing transition spend** was demonstrated by this artifact

## Architecture drawn

```text
private note (off-chain)
        |
        v
membership proof + state-transition proof  (witness, off-chain)
        |
        v
Plane A continuation UTXO  --locks-->  covenant
   CEv1 128 B = control32 | lineage32 | stateCommit32 | recovery32
        |
        +--> hashes to StateCellV2
                poolId, stateCellId, noteRoot, nullRoot,
                nextNoteRoot, nextNullRoot, meta
        |
        +--> next continuation UTXO (new Plane A)

Plane B: 12 x ML-KEM-768 ciphertexts, 128 B each, encrypted to recipient
```

That Chipnet demo is a **state carrier + encrypted delivery** prototype. It does not include:

- deposit/import
- withdrawal/export
- value conservation / range
- batching / sequencer
- a concrete STARK

Those appeared later as competing proposals. ShieldKit froze a *narrower* Fv1: fixed ticket, Circle FRI, no transfers.

## Design rule this demo supports

The public layout names a membership proof and a state-transition proof. They are not labeled "Circle STARK" or "Groth16". That is the STARK-agnostic pool: the covenant checks a proof against committed roots. The proof system behind those boxes is a backend.

Current backend we are researching: Circle FRI.

The transaction is on Chipnet. Do not add wallet seeds or off-chain notes to this file.
