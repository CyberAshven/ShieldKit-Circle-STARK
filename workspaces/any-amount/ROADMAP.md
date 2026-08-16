# Roadmap: four increments after the 10-fold Chipnet land

Same plan as the workspace file `D:\Circular-STARKs\plans\2026-08-16-pq-confidential-increments.md`.
Scoreboard: [`STATUS.md`](STATUS.md). Lands: [`MILESTONE.md`](MILESTONE.md).

## Now

Chipnet Circle-FRI shielded covenant. Standard 1 fold + 6 C=QZ (`2acb1196…`). Consensus lock compiles **36** folds + 36 C=QZ (**382203 B**). Prior Chipnet 10-fold land `18c74b49…`. Not ZK. Pedersen amounts (not PQ).

## Next, in order

1. **36 on-chain folds** — lock+VM+measure done (382203 B). Chipnet JSON-RPC land of this lock still required (new txid, not `18c74b49…`).
2. **Conservation on chain** — seq+1 and reserve-field=0 execute on the lock; leak test on successor hex. Hidden reserve **value** residuals stay in `verifyFri`.
3. **Replace Pedersen** with a hash/PQ amount commit; hide or commit the public P2PKH net.
4. **Statistical ZK** (mask openings). Viewing keys after that.

Each increment: tests + measure + honest docs + commit + push `@ABLalgorithm` (origin and upstream), then stop and start the next.

Envelopes: 100 KB relay, **1 MB** one nonstandard tx, **32 MB** chained, 10 KB unlocking. Chipnet only. JSON-RPC for >100 KB, not Electrum/P2P.
