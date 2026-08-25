# Starting artifact

**This lane starts from the QM31 occupancy freeze**, not leftover SHA-LDE.

| | |
|---|---|
| Pack | [`survey/artifacts/qm31-fri10/`](survey/artifacts/qm31-fri10/) |
| Frozen at | `008dd6b` (`feat: freeze QM31 occupancy pack`) |
| vk (sibling RULES) | `circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22` |
| FRI | **10** |
| Field | QM31 SecureField, **124 bits**; circle/qTable/layer-0 stay M31 |
| min(query, field, SZ, hash-RO) | **124 ≥ 100** (query 128 is speculative, named) |
| Chipnet | `60d186ded18897a50d0a4205ed446ab02339a53eb6d8f4a7043b4e405796edc4` / **99043 B** / Electrum |
| Lab compile | 99175 B, 18 inputs, leftover bound 7200 B, padSum 0 |
| Lock | fused 6-query fold+R, grind 20, algebraicC, bind-T, note-auth **with preimage in unlocking** |

Live compiles in this lane pin **this** `RULES.md` (`bc64c18b…`), so they are a new family with the **same occupancy lock shape**. The packed Chipnet hex pins sibling RULES `de1f4dcf…`. Both are occupancy FRI10 / 124-bit. Neither is the named end (§6 / §7 still open).

Leftover SHA-LDE (`a598b1f`, depth-6 revert) is a sibling 100 KB squeeze. It is not wired. Next construction is the SHA-256 AIR on extra inputs ([`NEXT.md`](NEXT.md)).
