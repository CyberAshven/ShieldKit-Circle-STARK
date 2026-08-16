# Prior art: ABL early zk-STARK CashVM ZIP

Extracted from `Reference/zk-stark-cashvm early work ref.zip` to `prior-art/zk-stark-cashvm-early/zkstark_pkg/`.

This is the ABL line that the Bastian chat calls "plain FRI, not DEEP-FRI or STIR".

## What is in the ZIP

| Path | Role |
| --- | --- |
| `stark.py` | Self-contained Goldilocks FRI-AIR prover+verifier. Statement: iterated \(x \mapsto x^2+C\). Salted Merkle, composition, FRI, Fiat–Shamir, grind, \(Z_H R\) mask |
| `cashvm.py` | Token VM model of 2026 script |
| `structures_*.py` | Merkle, FRI, grind, loop helpers |
| `apps/membership_stark.py` | Membership statement (closer to a pool) |
| `apps/mixer.py`, `apps/private_mixer.py` | Early mixer sketches |
| `apps/swap/` | HTLC swap (the "start from the application, hook the proof" direction) |
| `apps/quantumroot/` | Quantumroot comparison artifacts |
| `cashscript/*.cash` | Merkle, composition, Fiat–Shamir, grind, FRI fold, stark verifier |
| `cashscript/handasm/fold.asm` | Hand-written fold (CashScript could not emit nested loops) |
| `cashscript/membership/` | Membership composition + selector Horner + fused loop status |
| `cashscript/fused/` | Fused verifier hex/asm |

## Honest status from `membership/fused/STATUS.txt`

Validated on real `createVirtualMachineBch2026`:

- One redeem **program** of 94 bytes, query-count-constant, uses OP_DEFINE + OP_BEGIN/OP_UNTIL + nested modexp via OP_INVOKE
- Correct query `x` accepts; tampered `x` rejects
- Whole membership openings ~64 KB **cannot** fit in one 10 KB unlocking
- Planned layout: a few inputs, total tx ~74 KB (see missing `apps/txplan.py` — not in this ZIP)

Not done in the fused loop:

- Multi-column Merkle opening
- 8-constraint composition
- FRI fold chain
- Selector-Horner
- On-chain Fiat–Shamir recomputation

Those pieces were validated **separately**. Fusing them is the remaining work. That is the same integration cliff 0zkbrewer later climbed, and where the extra 28 KB appeared.

## Field and hash

`stark.py` uses Goldilocks and SHA-256. Poseidon2 appears in the later 0zkbrewer native CT-AIR, not in this ZIP's core `stark.py`.

## What to reuse vs leave

Reuse:

- The "program is tiny, witness is huge, shard the witness" topology
- Separate validation of Merkle / composition / fold / FS, then fuse
- The statement that CashScript-without-nested-functions is the wrong authoring layer for FRI

Do not reuse as the product backend:

- Goldilocks
- The toy \(x^2+C\) AIR
- LLM-emitted CashAssembly (the chat itself says not to trust it)

Circle FRI work should be specified first (field, domain, fold, queries), then lowered to Libauth/script the way ShieldKit P2 already lowers M31 arithmetic.
