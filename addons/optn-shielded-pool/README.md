# OPTN Shielded Pool addon (pre-release stub)

Chipnet-only screen for the any-amount lab. **Not** registered in OPTN
upstream (`src/addons/builtin/index.ts`). Zero-touch: do not edit OPTN
from this repo.

Until a separate OPTN PR exists, this folder is the manifest + screen.
The first client is the lab CLI: `workspaces/any-amount` (`npx tsx src/cli.ts`).

If the lab sidecar is running (`npx tsx src/cli.ts serve` in
`workspaces/any-amount`), the screen reads `http://127.0.0.1:17432/status`.
Deposit/withdraw buttons do **not** build or broadcast a pool tx yet.

TypeScript only. No new JavaScript.
