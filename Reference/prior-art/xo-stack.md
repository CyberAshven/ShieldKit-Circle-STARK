# XO Stack (General Protocols)

Public product: [xo.cash](https://xo.cash/) · docs: [stack.xo.cash](https://stack.xo.cash) · GP: [generalprotocols.com](https://generalprotocols.com)

**Code is on GitLab, not GitHub:** [gitlab.com/groups/GeneralProtocols/xo](https://gitlab.com/groups/GeneralProtocols/xo)

This is a **UTXO application stack** from the AnyHedge team. It is **not** Libauth, **not** CashScript, **not** Cash Stack (PSF), **not** our shielded pool.

## Packages (read 2026-08-16)

All early-alpha. npm `@xo-cash/*`. Branch `development`.

| Repo | npm | Job |
| --- | --- | --- |
| [xo/templates](https://gitlab.com/GeneralProtocols/xo/templates) | `@xo-cash/templates` | Wallet/app **templates** (currently exports `p2pkhTemplate`) |
| [xo/engine](https://gitlab.com/GeneralProtocols/xo/engine) | `@xo-cash/engine` | Runtime: seed + Electrum + template hub → import template, list actions, **create invitations** |
| [xo/primitives](https://gitlab.com/GeneralProtocols/xo/primitives) | `@xo-cash/primitives` | Validated `PublicKey` / `PrivateKey` etc. No business logic |
| [xo/state](https://gitlab.com/GeneralProtocols/xo/state) | `@xo-cash/state` | Local state/storage for the engine |
| [xo/crypto](https://gitlab.com/GeneralProtocols/xo/crypto) | `@xo-cash/crypto` | Keys / signing |
| [xo/types](https://gitlab.com/GeneralProtocols/xo/types) | `@xo-cash/types` | `XOTemplate` types |
| [xo/utils](https://gitlab.com/GeneralProtocols/xo/utils) | `@xo-cash/utils` | Parser/utils |
| [xo/transports](https://gitlab.com/GeneralProtocols/xo/transports) | `@xo-cash/transports` | Transport layer |
| [xo/coordinator-server](https://gitlab.com/GeneralProtocols/xo/coordinator-server) | `@xo-cash/coordinator-server` | Coordinator for multi-party apps |
| [xo/invitations](https://gitlab.com/GeneralProtocols/xo/invitations) | `@xo-cash/invitations` | Invitation objects (TBD) |

Engine sketch (their README): `Engine.create(seed, electrumClient, { defaultTemplateHubUrl })` → `importTemplate` → `listStartingActions` → `createInvitation`.

## What a template actually is

`p2pkh.ts` is a **libauth wallet-template-v0 JSON** plus XO fields:

- `$schema`: `https://libauth.org/schemas/wallet-template-v0.schema.json`
- `supported`: BCH 2023–**2026_05**
- **roles** (owner / receiver / sender) last for one action
- **start** actions + **actions** (receive, request sats/FT/NFT, send, burn, sign/verify)
- **transactions** / **outputs** / **inputs** / **lockingScripts** / **scripts** (CashAssembly)
- **variables**, **constants** (dust 546), **scenarios** (happy-path fixtures)
- Composable txs: invitation fills missing inputs
- Change policy on the template (`defaults.change`)

Published pack today is **P2PKH only**. Branch `more_templates` also has AnyHedge, Cauldron, wrap (see `xo-templates.md`). The *format* is what we steal. Do not wait on GP to merge those to write CashScript.

Public blog is **seven posts only** (2025-10-15 … 2026-08-12). Inventory + per-template actions: `xo-templates.md`. V2R4 (2026-08-05): still improving P2PKH; Blaze Nov 2026; alpha CLI/TUI wallet promised, not shipped.

## AnyHedge (the mature GP covenant)

GitLab: [anyhedge/contracts](https://gitlab.com/GeneralProtocols/anyhedge/contracts) · [anyhedge/library](https://gitlab.com/GeneralProtocols/anyhedge/library)

- Versioned `contracts/v0.9` … `v0.12`: `contract.cash` + `bytecode.asm` + `artifact.json`
- Library: create, register for settlement, fund, mature/liquidate, **mutual redemption** (both parties sign, no shared key)
- Optional settlement *service* (auth token) — we must **not** require that for the pool
- Dust defined from BCR worst-case dust thread

Steal: versioned artifacts, mutual/coop exit pattern, oracle-bound conservation. Do not steal their coordinator as a pool dependency.

## Steal / do not steal

Steal:

- Libauth-schema template + roles + scenarios as the **portable** description of deposit/withdraw
- Invitation/composable tx for “someone else broadcasts”
- AnyHedge versioned `.cash` + artifact pin
- Mutual redemption shape if we ever add coop cancel

Do not steal:

- XO Engine as Circle FRI prover or on-chain verifier
- Required coordinator / template-hub
- Putting seeds into `Engine.create` from chat
- Treating alpha `@xo-cash/*` as Chipnet-safe

Our compiler remains **CashScript + Libauth VM**. First client remains the Chipnet CLI. An XO template can wrap that later so OPTN / XO wallet can open the same action.

## What they publish

| Piece | Meaning |
| --- | --- |
| **Templates** | Standardized contract/app templates. “One template, any interface” (XO Portability, 2026) — same template in wallet / CLI / other UI |
| **XO Engine** | Runtime + state. npm `@xo-cash/state` is described as state/storage for the XO Engine |
| **Primitives** | Reusable UTXO building blocks ([stack.xo.cash/tools/primitives.html](https://stack.xo.cash/tools/primitives.html)) |
| **Modular adapters** | Swap indexers / wallets / backends |
| **XO wallet** | Non-custodial GP wallet that is supposed to open XO apps |

Example apps they list: BCH BULL, XO MultiSig, AnyHedge, Flipstarter, Oracles Cash, XO vault.

Stack site says: **in active development**, code is for learning, expect breakage until a production release.

GitHub org `GeneralProtocols` did not list public repos to this token (empty API). Do not invent a clone path.

## Steal / do not steal

Steal:

- Template as the portable contract description (same idea as libauth wallet templates)
- UTXO covenant discipline from AnyHedge (conservation, oracle bounds) as *patterns*

Do not steal:

- XO Engine as the Circle FRI prover or on-chain verifier
- Their wallet as our first client
- Treating XO “Blaze” / marketing timelines as consensus

Our compiler/engine remains **CashScript + Libauth VM**. Our first client remains the Chipnet CLI (OPTN addon later).
