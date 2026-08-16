# Roadmap: four increments after the 10-fold Chipnet land

Same plan as the workspace file `D:\Circular-STARKs\plans\2026-08-16-pq-confidential-increments.md`.
Scoreboard: [`STATUS.md`](STATUS.md). Lands: [`MILESTONE.md`](MILESTONE.md).

## Now

Chipnet Circle-FRI shielded covenant. Standard 1 fold + 6 C=QZ (`2acb1196…`). Consensus lock compiles **36** folds + 36 C=QZ (**382203 B**). Prior Chipnet 10-fold land `18c74b49…`. Published note preimage is one-time-padded (increment 4). Production note amounts: tagged SHA-256 commit (increment 3). Pool UTXO stays `STATE_BASE`. Not better-than-XMR.

## Next, in order

1. **36 on-chain folds** — lock+VM+measure done (382203 B). Chipnet land `b1415faf…` height 319402. `18c74b49…` remains the 10-fold land.
2. **Conservation on chain** — done (`4414ff3`). seq+1 and reserve-field=0 on the lock; leak test on successor hex. Hidden reserve **value** residuals stay in `verifyFri`.
3. **Replace Pedersen** — done. Production path is tagged SHA-256 (`hash-commit.ts`), bound in `checkAuthRelation`. `encodeStatement` commits the public net. Pedersen remains a comparison plugin.
4. **Statistical ZK** — done for the published preimage (OTP + unlocking leak test). Viewing-key delivery / FRI-polynomial mask still later. Do not claim better-than-XMR.

Each increment: tests + measure + honest docs + commit + push `@ABLalgorithm` (origin and upstream), then stop and start the next.

Envelopes: 100 KB relay, **1 MB** one nonstandard tx, **32 MB** chained, 10 KB unlocking. Chipnet only. JSON-RPC for >100 KB, not Electrum/P2P.
