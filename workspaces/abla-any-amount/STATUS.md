# Status (2026-08-16)

Honest leftover list. This is **not** a sound shielded pool and **not** a 128-bit on-chain theorem.

## Passing (this workspace)

- Circle FRI prove **and** verify on shipped functions (`circle-fri-m31`, `sound: false`, n=32, 8 queries).
- Honest deposit, partial withdraw, and **spend-change** accept (change notes mint a fresh `rho` + new Merkle index so the nullifier is not reused).
- False statements reject: tampered reserve, wrong note commitment, wrong nullifier (statement polynomial binds all three).
- Pedersen-style 32-byte amount commits on the statement; ML-KEM and Quantumroot stay **off** `Verify`.
- P2S program + P2SH32 shell compile; five-point genesis and successor **compile and sign** locally; unlocking and full-tx measured under 10 KB / 100 KB (proof slot is a 40-byte digest, full FRI is off-chain).
- CLI `status`, `bench`, `lab demo --wallets 100`, `pool measure-tx`, `pool chipnet-covenant`.
- Optional Rust prove worker (`crates/circle-fri-worker`) in the Toorik `fri-worker` role.

## Not done (do not claim)

- Sound Circle FRI membership / query / Merkle FRI **on chain** (would need shards; Goldilocks sound wiring ~120 KB).
- Hidden amounts as EC points (CHIP 2025-05) or a finished Bulletproof.
- Steal-resistant 5-point P2S that accepts only a plugin proof (current script checks lock/category/token/commitment magic, not the FRI blob).
- OPTN builtin register (zero-touch).
- 100 **funded** on-chain wallets (faucet captcha-gated). Local 100-wallet rehearsal is the bar.
- `sound: true` / 128-bit parameters.
- A cryptanalysis that Aztec, Zcash, or Monero are “less sound.”

## Chipnet

Lab address (gitignored `.local/lab-wallet.json`):

`bchtest:qqf9c6rdd52wwdws5flgfe9kq4ftnzp5vv6763aw48`

Broadcast (2026-08-16), Electrum-accepted:

| Step | txid |
| --- | --- |
| First genesis (OP_SIZE leak, unspendable 11k) | `0adce2cac20c3dae0e2913b4bb6f8db09b7d8a249b5f9a52cb64efcc7cdcb8a8` |
| Prep vout=0 (CashTokens genesis parent must be output 0) | `095acda13ed11873c6024d1ac2229f8705bcf147e8d8517e0c7d7d71cf634efc` |
| Fixed P2SH32 genesis | `f6ebcf57a8b19f8788ffea522a9453d95602f3e80775ea6235aa7734ee746545` |
| Five-point successor (unlocking 35 B, tx 519 B) | `1c772b594dd28e90724054f8e55feb70c6224d2f5c5fc2fc6e04723586faa6e6` |

Explorer: `https://chipnet.imaginary.cash/tx/<txid>` (imaginary.cash returned 502 when we fetched; Electrum accepted all four).

These are a **covenant cell** (PAA1 NFT + proof-slot OP_RETURN), not a sound shielded withdraw. `chipnet-marker` is only an announcement.

## Sidecar for the OPTN addon

```bash
npx tsx src/cli.ts serve
```

Addon reads `http://127.0.0.1:17432/status`. Not wired into OPTN upstream.
