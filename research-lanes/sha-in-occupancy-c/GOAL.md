# Lane: SHA in occupancy C

**Work only here.** Sibling 100 KB HASH_BIT leftover walks live in `research-lanes/ideal-bch-shielded-pool-stark` (`1b18a98`, Chipnet `5de68272…`). Sibling 1 MB SHA-AIR-on-own-inputs lives in `research-lanes/nonstandard-ideal-circle-stark`. Parent freeze in `research-lanes/envelope-b-standard` is evidence.

## Named end (only the human declares done)

One Chipnet Electrum transaction that is **B** under [`RULES.md`](RULES.md): one standard May-2026 tx, soundness min(FRI-query, field, SZ, hash-RO) ≥ 100, miner runs every numbered check, Circle FRI + SHA-256, on-chain money relation, leaf↔nf↔amount in occupancy composition C (same 36 queries), unlocking silent (no rho/owner/amount preimage), encoding ≡ spec.

That object does not exist yet. Do not say shielded until §6 holds in script.

## Construction (this lane)

SHA residuals live in occupancy composition C. The miner already FRIs that polynomial at 36 queries. Spend or replace the 7200 B SHA-LDE leftover slot; do not stack HASH_BIT sticker-matching on top of it. Do not add 36 extra SHA-AIR inputs (meter **94788 B**). Do not drop q/grind/TRACE. Do not drop the 100 kB box.

A wall is a number (bytes, density, TRACE width), then the next packing. Only the human declares done.

## Starting artifact

Copy of the sibling occupancy + HASH_BIT host at `1b18a98`. Chipnet `5de68272…` / 99144 B is evidence: leftover-bound occupancy FRI, hash-commit trampoline, unlocking omits rho/owner/amount8, miner does **not** run SHA of the note. Occupancy pack: [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/) / `60d186de…` / 99043 B. See [`START.md`](START.md).

## Why this lane exists

The HASH_BIT sibling pays ~9.7 kB to merkle-walk leftover mix samples and prefix-check public tags. That is sticker-matching. The SHA preimage relation stays in `verifyFri`. Dumping 576 felt-columns as 36 extra inputs is a measured ~194 kB miss. STARK composition does not require that dump. This lane is that compile, inside the same Electrum box.

## vk

No vk string until a construction satisfies every RULES line. Then the vk **includes** the SHA-256 of `RULES.md`. Editing RULES is a new family.

Sibling occupancy vk `circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22` stays that sibling’s name. Do not reuse it here.

## Out of scope as product (controls stay in-tree)

- HASH_BIT leftover merkle/prefix as the money relation
- 36 extra SHA-AIR inputs
- The 1 MB consensus fork
- Relabeling `5de68272…`, `60d186de…`, or the 91 KB freeze as this named end
