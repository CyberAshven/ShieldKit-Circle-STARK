# Lane: ideal BCH shielded-pool STARK

**Work only here.** Parent freeze in `research-lanes/envelope-b-standard` is evidence. Walk-in generic-step prior in `research-lanes/batch-exit-walkin` is construction notes for RULES §7, not this product.

## Named end (only the human declares done)

One Chipnet Electrum transaction that is **B** under [`RULES.md`](RULES.md): one standard May-2026 tx, soundness min(FRI-query, field, SZ, hash-RO) ≥ 100, miner runs every numbered check, Circle FRI + SHA-256, on-chain money relation, shielded unlocking (no rho/owner/amount preimage), walk-in batch exit with N on-chain walks, encoding ≡ spec.

That object does not exist yet. The 91 KB M31 freeze is a measured wall, not this end. Occupancy pack [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/) (vk `circle-fri-m31-qm31-t64-b16-q36-g20-fri10-` + full `RULES.md` SHA-256, Chipnet `60d186de…` 99043 B) is a later measured wall. §6 / §7 still open.

## Why a new lane

- Parent freeze fits §1’s box and a query worksheet of 128, **on M31**. RULES §2 forbids claiming 100 bits while the field is ~31.
- Parent note-auth / baked step kernels publish amount/rho/owner. RULES §6: anonymity set 1 is not shielded.
- Baked Option B paints `(rIn, rOut, prevNf)` at genesis. RULES §7: walk-in deposits then one N-note exit.
- Envelope A and C hops are types. RULES §8: they are not B.

## vk

No vk string until a construction satisfies every RULES line. Then the vk **includes** the SHA-256 of `RULES.md`. Editing RULES is a new family.

Parent freeze vk `circle-fri-m31-t64-b16-q36-g20-fri9` stays that freeze’s name. Do not reuse it here.

## Out of scope as product (controls stay in-tree)

- Envelope A
- Envelope C as a substitute for one standard B tx
- Relabeling the 91 KB freeze, ABL’s 12-note A `ce421f05…`, or walk-in Chipnet `e63ccf03…` as this named end
