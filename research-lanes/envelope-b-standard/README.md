# Research lane: envelope B → one standard tx

**Work only here.** Snapshot of `workspaces/any-amount` from `Optimization` @ `5c05571` (ABL merge). The source tree is frozen for this track.

Hypothesis: FRI9 **B completeness** in **one May 2026 standard transaction** (100 KB, 10 KB inputs, `standard=true` hash meters, no dummy pad). Rules: [`RULES.md`](RULES.md). Next: [`NEXT.md`](NEXT.md).

## What this is

A self-contained Chipnet lab: Circle-FRI9 prover/verifier, 2026 VM kernels, envelopes A/B/C as **controls**, step kernel, compile/measure/land scripts.

| Control | Role |
|---|---|
| **B** | the object (36 folds + 36 R-slots + note-auth, recorded 498 398 B consensus) |
| **A** | standard 100 KB, 4 slots, no note-auth |
| **C** | B chunked to 19 standard hops (~1.66 MB total) |

A and C stay in-tree so every candidate compiles against both. They are not the product.

## Run

```bash
cd research-lanes/envelope-b-standard
npm ci
npm test
npx tsc --noEmit
npx tsx src/cli.ts pool measure-tx --envelope b
```

Chipnet land and RPC: `$bchn-rpc`, SSH `layer1-node` (see RULES §6). Do not land until the inner loop (`standard=true` VM + bytes) passes.

## Outside this lane (tools, not edit targets)

| Path | Use |
|---|---|
| `/home/toorik/Projects/ShieldKit/LeanBCH` | op-cost floors, `VM.Standard`, bytecode optimizer |
| `$cashscript-next` | cashc `0.14.0-next.4` language facts |
| `$bch-constants` | May 2026 consensus/policy numbers |
| `workspaces/any-amount` | frozen ABL snapshot — do not edit for this track |
| `research-lanes/bch-shielded-pool-design` | sealed Fv1 — do not edit |
