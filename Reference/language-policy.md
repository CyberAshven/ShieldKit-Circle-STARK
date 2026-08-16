# Language policy

New code in this workspace and on the joint-repo personal branch: **TypeScript or CashScript or Rust**. Never new JavaScript.

## Why no `.js`

Plain JS cannot catch the class of bugs we will hit (field-element widths, proof offsets, statement encodings, vk ids). If it runs on Node or in a harness, it is **strict TypeScript** (`.ts` / `.mts`). `allowJs` stays off.

Existing toorik `.mjs` / `.js` in ShieldKit stays his. Do not convert it on `main`. New files on the personal branch are `.ts` / `.mts`, not more `.mjs`.

## What each language is for

| Language | Use | Do not use for |
| --- | --- | --- |
| **TypeScript (strict)** | Libauth harnesses, codecs, tx builders, plugin ABI, tests, CLI glue | On-chain redeem bodies |
| **CashScript** | Covenant / verifier programs when cashc can emit the loops/functions | FRI folds cashc still cannot express — then lower explicitly |
| **Libauth / CashAssembly** | Only the bits CashScript cannot emit (nested FRI loop), written and reviewed as TS-generated or checked-in `.asm`, never LLM-only | New product logic |
| **Rust** | Heavy prover, FRI worker, codecs that need speed — same role as toorik’s `ShieldKit-SDK/designs/fri` (`fri-prover`, `fri-worker`) and pf10 crates | On-chain script; do not start a second prover stack |
| **Python** | One-off CAS / SymPy field certificates (already in the Circle-STARK lane) | New verifiers or product CLI |

## What toorik actually uses (checked on disk)

- **ShieldKit-Circle-STARK** (joint lane): mostly `.mjs` + some `.js` / `.py`. Research notebooks, not a product compiler.
- **ShieldKit-SDK**: `.mjs` + **TypeScript** (294 `.ts`, 53 `.mts`) + **118 `.cash`** + **Rust** FRI crates. Product CLI is Node ≥ 22.
- **0zkbrewer FRI**: Python prover + `.mjs` Libauth harness.

So: yes, we should have Rust **for the prover**, like toorik, when we implement Circle FRI. We should **not** rewrite the pool in Rust. On-chain stays CashScript/Libauth. Wallet/harness stays TypeScript.

## Rules

1. `tsc --strict` (or equivalent) on every TS package we add.
2. No new `*.js` or untyped `*.mjs`.
3. CashScript first for covenants; measure; only then hand-lower.
4. Rust only behind a crate with tests; pin toolchain.
5. Never mainnet. Chipnet + Libauth 2026 VM.
6. Bastian chat files are **not source code** and are **not committed** (see `AGENTS.md` Privacy).
