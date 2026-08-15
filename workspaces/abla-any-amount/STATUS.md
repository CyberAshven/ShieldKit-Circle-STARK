# Status (2026-08-16)

Honest overnight snapshot. This is **not** a sound shielded pool.

## Passing

- `npm test` — 14/14
- PAA1 128-byte any-amount state (not Fv1 `PAF1`)
- Plugin ABI: `hash-lab-v0` (not private) + `circle-fri-m31` (M31, circle group, one fold; `verify` refuses)
- Deposit / partial withdraw / change note / nullifier machine
- NIP-44 encrypt + NIP-59 gift-wrap round-trip
- Tor required → fail closed
- P2PKH + PAA1 OP_RETURN marker **compiles and signs** with libauth 3.1 (`test/chipnet-compile.test.ts`)
- Electrum Chipnet reachable (`wss://chipnet.imaginary.cash:50004`)
- `lab demo --wallets 4` — sequential any-amount rehearsal

## Not done (do not claim)

- Sound Circle FRI membership / query / Merkle FRI on chain
- Hidden amounts / confidential assets
- Steal-resistant 5-point P2S that accepts only a plugin proof
- OPTN builtin register (zero-touch)
- **Broadcast Chipnet txid** — googol faucet is captcha-gated; lab wallet is empty (0 sats)

## Lab address (empty until you faucet it)

Created locally in `.local/lab-wallet.json` (gitignored). Fund it at
https://tbch.googol.cash/ (network **chipnet**), then:

```bash
npx tsx src/cli.ts balance
npx tsx src/cli.ts pool chipnet-marker
```

That marker is a conservation-profile announcement (OP_RETURN PAA1), not a
shielded withdraw.

## Sidecar for the OPTN addon

```bash
npx tsx src/cli.ts serve
```

Addon reads `http://127.0.0.1:17432/status`. Not wired into OPTN upstream.
