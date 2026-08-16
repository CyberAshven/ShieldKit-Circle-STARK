# Prior art: toorik BCH_Knowledge_Base

- Upstream: https://github.com/toorik2/BCH_Knowledge_Base

This is the CashScript / CashTokens / UTXO knowledge base for the joint work. It is not a STARK repo.

## Use it for

- UTXO vs account mental model
- CashTokens: category identity, mutable vs minting, commitment size (40 B historically, **128 B after May 2026** — this is why `PoolStateFv1` is 128 bytes)
- Multi-contract / pinned input positions
- CashScript syntax and SDK transaction building
- FAQ corpus under `faq/`
- Security notes under `best-practices/security/`

## Do not use it for

- FRI, Circle group, M31, soundness formulas

When a Circle FRI verifier is lowered to CashScript or Libauth, follow this repo's UTXO rules: contracts validate, they do not "call"; state lives in NFT commitments; input positions are pinned.

`Knowledge-Base-V2/CORE_REFERENCE.md` is the condensed version.
