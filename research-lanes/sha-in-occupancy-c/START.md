# Starting artifact (evidence, not the product)

Copied from `research-lanes/ideal-bch-shielded-pool-stark` at `1b18a98`.

| | |
|---|---|
| Occupancy pack | [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/) |
| Occupancy Chipnet | `60d186de…` / 99043 B |
| HASH_BIT host Chipnet | `5de68272…` / 99144 B / Electrum / padSum 0 / leftover-binds 0–6 |
| Genesis of that host | `11d9673b…` |
| Pins | TRACE 64, blowup 16, q 36, grind 20, FRI 10, B=M31, F_fri=QM31 (~124), H=SHA-256 |
| Lock | 40 B hash-commit trampoline (`DUP HASH256 <digest> EQUALVERIFY` / `DEFINE 0` / `INVOKE 0`) |
| Input 0 unlocking | leftover 7200 + HASH_BIT+pool body 2533 = 9738 |
| Extra-input SHA AIR meter | 36 × (41 + 576×4 + 9×32) = **94788 B**; occupancy+AIR ≈ 194 kB |

The host omits rho/owner/amount8 from unlocking. TRACE-w unpack of mined unlockings does not recover the walked leaf. HASH_BIT is merkle/prefix of leftover mix samples vs public tags. Preimage check stays in `verifyFri`. Occupancy FRI is algebraicC.

This lane’s first compile replaces that sticker-matching with SHA residuals in occupancy C. Do not relabel `5de68272…` as that compile.
