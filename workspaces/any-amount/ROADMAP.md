# Roadmap: four increments after the 10-fold Chipnet land

Scoreboard: [`STATUS.md`](STATUS.md). Lands: [`MILESTONE.md`](MILESTONE.md).

## Now

Chipnet Circle-FRI shielded covenant. ZKP plugin hook is **off-chain + registry**: default `circle-fri-m31`, second family `hash-lab-v0` on the same statement (`hash-lab-v0` is not private or sound). On-chain redeem is still Circle fold/C=QZ. Internal hash is a drop-in knob (default SHA-256, BLAKE2s alternate). Poseidon2 and Monolith are not shipped; a later swap is a table entry + `digest()`, not a Merkle/FS/note rewrite. On-chain `OP_SHA256` is the SHA-256 backend of the default knob, not a second tree. Latest lands: standard `23fd1b7d…` (**79525 B**) and consensus `9362df54…` (**283992 B**). Pool UTXO stays `STATE_BASE`. Not better-than-XMR, Zcash, Voidify, or Tornado Cash. SHA-256 as the internal hash does not change that.

## Next, in order

1. **36 on-chain folds** — lock+VM+measure done (382203 B). Chipnet land `b1415faf…` height 319402. `18c74b49…` remains the 10-fold land.
2. **Conservation on chain** — done (`4414ff3`). seq+1 and reserve-field=0 on the lock; leak test on successor hex. Hidden reserve **value** residuals stay in `verifyFri`.
3. **Replace Pedersen** — done. Production path is tagged SHA-256 (`hash-commit.ts`), bound in `checkAuthRelation`. `encodeStatement` hiding-commits the public net and reserve (`PAA1-HASH-NET-v1` / `PAA1-HASH-RSV-v1` + blind32). Pedersen remains a comparison plugin. Not Bulletproofs/Orchard.
4. **Statistical ZK** — published preimage OTP; FRI openings use \(R_{\mathrm{on}}+Z R_{\mathrm{off}}\) (SHA-256; off-domain as 2024/1037; deg 7 / 35). Fiat–Shamir rejection-samples 36 unique first-fold orbits (`FRI_VERSION` 7). Consensus high-index kernels dummy-pad unlocking for 2026 density; standard 0–5 stay short. Degree-0 contrast still cancels. 10 KB lock does not evaluate \(R\). Cannot Maxwell-hide `STATE_BASE` or the fee UTXO in script. Not a Lean HVZK theorem. Not better-than-Voidify or Tornado Cash.

Each increment: tests + measure + honest docs + commit + push `@ABLalgorithm` (origin and upstream), then stop and start the next.

Envelopes: 100 KB relay, **1 MB** one nonstandard tx, **32 MB** chained, 10 KB unlocking. Chipnet only. JSON-RPC for >100 KB, not Electrum/P2P.
