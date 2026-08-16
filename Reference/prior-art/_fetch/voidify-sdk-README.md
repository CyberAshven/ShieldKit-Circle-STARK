# @voidifydao/sdk

English | [简体中文](./docs/README.zh-CN.md) | [Русский](./docs/README.ru.md) | [日本語](./docs/README.ja.md)

[![npm version](https://img.shields.io/npm/v/%40voidifydao%2Fsdk.svg)](https://www.npmjs.com/package/@voidifydao/sdk)
[![license](https://img.shields.io/npm/l/%40voidifydao%2Fsdk.svg)](https://www.npmjs.com/package/@voidifydao/sdk)

TypeScript SDK reference for adding Voidify Nova SOL and SPL-token deposits and relayed withdrawals to a Solana frontend.

## Embed Nova in a browser frontend

The frontend creates Nova proofs locally, keeps synchronization data in IndexedDB, submits deposits through the connected wallet, and sends withdrawal proofs to a relayer.

### What you need

- A browser with IndexedDB, Web Crypto, and `fetch`.
- A connected Solana wallet that can sign transactions and deterministically sign messages.
- An RPC URL for Solana mainnet-beta. This guide uses Voidify program `4WJnXP7mFxFY45SYvfyGDwEBdcwafVqdgbYYSHpoded4`.
- The matching public proof artifacts. Step 3 downloads `nova-transaction-artifacts.zip`, extracts `nova-transaction.wasm` and `nova-transaction.zkey`, and serves both from your app. The SDK does not download or extract these files. If the asset is not shown there, stop rather than substituting files from another circuit.
- A compatible relayer. The mainnet deployment supports SOL, USDC, and VOID; its SPL Nova pools are USDC and VOID.

### 1. Install

```bash
npm install @voidifydao/sdk@3.1.2 @coral-xyz/anchor@^0.32.1 \
  @solana/web3.js@^1.98.4 @solana/spl-token@^0.4.14 buffer@^6.0.3
npm install --save-dev vite-plugin-node-polyfills@^0.25.0
```

### 2. Configure the Nuxt 4 browser bundle

The SDK is ESM-only. The supported copy-and-paste route for this release is a Nuxt 4 SPA (`ssr: false`) with the configuration below. This configuration was build-verified in Nuxt 4.4.2. Merge the `vite` object with your existing Nuxt configuration rather than declaring it twice.

```ts
// nuxt.config.ts
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineNuxtConfig({
  // Keep SDK imports out of the server bundle.
  ssr: false,

  vite: {
    plugins: [
      nodePolyfills({
        include: ["buffer", "process", "util", "stream", "crypto", "http", "https"],
        globals: { Buffer: true, global: true, process: true },
      }),
    ],
    optimizeDeps: {
      include: [
        "@voidifydao/sdk",
        "@solana/web3.js",
        "@solana/spl-token",
        "@coral-xyz/anchor",
        "bn.js",
        "buffer",
        "fixed-merkle-tree",
        "circomlibjs",
        "ffjavascript",
        "vite-plugin-node-polyfills/shims/buffer",
        "vite-plugin-node-polyfills/shims/global",
        "vite-plugin-node-polyfills/shims/process",
      ],
    },
  },
});
```

Add a client-only Nuxt plugin so runtime code that uses the global `Buffer` sees the browser implementation:

```ts
// app/plugins/buffer.client.ts
import { Buffer } from "buffer";

declare global {
  interface Window {
    Buffer: typeof Buffer;
  }
}

export default defineNuxtPlugin(() => {
  window.Buffer = Buffer;
  (globalThis as typeof globalThis & { Buffer: typeof Buffer }).Buffer = Buffer;
});
```

Create and use `Context` only in client-side code after the browser and wallet are available. This recipe is specific to Nuxt 4 SPA builds; a standard Vite/React or Next.js build is not zero-configuration and needs an equivalent, separately tested browser-bundle setup.

### 3. Download and serve the Nova proof artifacts

In a Nuxt application, files under `public/` are served at the site root. Download the released asset, verify it, and extract it into `public/artifacts`:

```bash
mkdir -p public/artifacts
curl -fL -O \
  https://github.com/VoidifyCommunity/voidify-ceremony-record/releases/download/v1.1.0/nova-transaction-artifacts.zip
curl -fL -O \
  https://github.com/VoidifyCommunity/voidify-ceremony-record/releases/download/v1.1.0/nova-transaction-artifacts.zip.sha256
shasum -a 256 -c nova-transaction-artifacts.zip.sha256
unzip -j nova-transaction-artifacts.zip -d public/artifacts
```

After extraction, the browser URLs must be `/artifacts/nova-transaction.wasm` and `/artifacts/nova-transaction.zkey`. Do not put the ZIP URL in the SDK configuration. If you host the files on another origin, configure CORS and use HTTPS.

### 4. Create a browser context

Create a context after the wallet connects, and recreate it if the wallet changes. The proof files must match the Nova circuit used by the mainnet deployment and be reachable by the browser (same origin or with CORS enabled).

A normal wallet-adapter has a nullable `publicKey` before connection and may not expose `signTransaction` or `signMessage`. Nova requires all three. The current SDK TypeScript type is Anchor's Node `Wallet`, which includes a `payer: Keypair`; the bridge below is therefore a temporary type assertion. It does not add missing wallet capabilities; the Nuxt browser-bundle setup above is still required.

```ts
import type { Wallet as AnchorWallet } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { Context, makeIndexedDBStores } from "@voidifydao/sdk";

const MAINNET_PROGRAM_ID = new PublicKey(
  "4WJnXP7mFxFY45SYvfyGDwEBdcwafVqdgbYYSHpoded4",
);

const MAINNET_NOVA_TOKEN_FEEDS: Record<string, string> = {
  So11111111111111111111111111111111111111112:
    "0xc5844a98ff37b7ea928409eb08507e1bfe54f5493c3d7f6012ef9c5e457ec031",
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v:
    "0xc07d7198b8683c594dae1ca8e0a40b0059a30f80f7179ee4481b7dbc9c1fd9ab",
  J2bUGZDxRDpsVfjZqKwn6yYCUKFmqzHgt8UajhGtpump:
    "0x5ee19b1c371f5e085f161e8c32b300a6a178df4e6c4bf73ced62b58a2ccfb150",
};

type BrowserWalletAdapter = {
  publicKey: PublicKey | null;
  signTransaction?: AnchorWallet["signTransaction"];
  signMessage?: (message: Uint8Array) => Promise<Uint8Array>;
};

function asTemporaryAnchorWallet(
  adapter: BrowserWalletAdapter,
): AnchorWallet {
  if (!adapter.publicKey || !adapter.signTransaction || !adapter.signMessage) {
    throw new Error(
      "Connect a wallet that supports transaction and message signing first.",
    );
  }

  // Temporary bridge only. It does not add Anchor's Node-only payer Keypair.
  return adapter as unknown as AnchorWallet;
}

export function createNovaContext(
  adapter: BrowserWalletAdapter,
) {
  const wallet = asTemporaryAnchorWallet(adapter);

  return new Context({
    rpcUrl: "<SOLANA_MAINNET_RPC_URL>",
    programId: MAINNET_PROGRAM_ID,
    wallet,
    // Keep the adapter as the method receiver.
    messageSigner: (message) => adapter.signMessage!(message),
    novaWasmPath: "/artifacts/nova-transaction.wasm",
    novaZkeyPath: "/artifacts/nova-transaction.zkey",
    switchboardNetwork: "mainnet",
    tokenFeeds: MAINNET_NOVA_TOKEN_FEEDS,
    substream: {
      type: "peer",
      makeRepos: () =>
        makeIndexedDBStores(
          `voidify-nova:mainnet:${MAINNET_PROGRAM_ID.toBase58()}`,
        ),
    },
  });
}
```

`novaWasmPath` and `novaZkeyPath` must point to the extracted files served by your app, not the ZIP download URL.

The bridge must only be used after the readiness check above; it cannot add message signing to an unsupported wallet. `messageSigner` must produce the same signature for the same message. Nova uses this signature, plus the optional passphrase, to recover the same private balance later. Use the same wallet and passphrase for every operation on that balance. The three feed IDs are the mainnet SOL, USDC, and VOID feeds; they are required to quote USDC/VOID relayed-withdrawal fees. Keep the IndexedDB name unique per network and program deployment.

### 5. Current mainnet Nova amount limits

For both `deposit` and `withdraw`, the Nova Pool enforces the same **inclusive** external-amount range. The following mainnet values were read from the three pool accounts on 2026-08-12:

| Token | Nova Pool | Minimum | Maximum |
| --- | --- | ---: | ---: |
| `SOL` | [`AYUp…9rtR`](https://solscan.io/account/AYUpbbQx5faj6jnMeTwj7RshNByT7TEJdmtf3hhi9rtR) | 0.1 SOL | 1,000,000 SOL |
| `USDC` | [`CGNt…Wo6k`](https://solscan.io/account/CGNtm4utUdTLk5B3SjHA5kzdkbD22Fo2DQCvPakVWo6k) | 0.1 USDC | 10,000,000 USDC |
| `VOID` (on-chain ticker `∅`) | [`Bko1…Bsz5`](https://solscan.io/account/Bko1EsrQdfmwzgmYUXWDznBemPEmPq25YEM45J5SBsz5) | 1 VOID | 100,000,000 VOID |

These values are on-chain pool configuration, not SDK constants. The protocol can update them, so use the table only as a current reference and query `fetchNovaExternalAmountLimits` before enabling a form or submitting an operation:

```ts
const { minExternalAmount, maxExternalAmount } =
  await voidify.nova.fetchNovaExternalAmountLimits(ctx, "SOL");
```

The returned values are raw-unit `bigint`s. Compare them with `voidify.nova.parseNovaAmount(userInput, "SOL")`, rather than hard-coding the table in an application. The examples below use `"1"` SOL, which is within the current range but is not a promise that the range will remain unchanged.

### 6. SOL: deposit and withdraw through a relayer

Amounts are UI-unit strings such as `"1"`, never JavaScript floating-point amounts. The wrapper below intentionally returns only the deposit signature: `result.note` is a serialized secret and must not be logged, displayed, uploaded, or persisted by the application.

```ts
import { voidify, type Context } from "@voidifydao/sdk";

export async function depositSol(
  ctx: Context,
  amount: string,
  passphrase?: string,
) {
  const { signature } = await voidify.nova.deposit(
    ctx,
    amount,
    "SOL",
    passphrase,
  );
  return signature;
}

export async function withdrawSol(
  ctx: Context,
  amount: string,
  recipient: string,
  passphrase?: string,
) {
  return voidify.nova.withdraw(
    ctx,
    amount,
    recipient,
    undefined, // Automatically choose a healthy relayer.
    undefined, // Use default synchronization settings.
    false, // Do not send the frontend RPC URL to the relayer.
    "SOL",
    passphrase,
  );
}
```

await depositSol(ctx, "1");
await withdrawSol(ctx, "1", "<RECIPIENT_PUBLIC_KEY>");

`recipient` is the recipient owner's base58 public key. `withdrawSol` generates the proof in the browser and submits it to the selected relayer. Show progress while synchronization and proof generation run, and handle the wallet approval for deposits. The deployment must have the matching SOL Pool, OracleConfig, and a compatible relayer already configured.

### 7. Mainnet SPL tokens: USDC and VOID

Use `USDC` or `VOID` as the token argument. Both are built into the SDK for this mainnet deployment; do not pass a custom mint.

| SDK token | Mint | Decimals | Nova Pool | Allowed amount |
| --- | --- | ---: | --- | --- |
| `USDC` | [`EPjFW…Dt1v`](https://solscan.io/token/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v) | 6 | [`CGNt…Wo6k`](https://solscan.io/account/CGNtm4utUdTLk5B3SjHA5kzdkbD22Fo2DQCvPakVWo6k) | 0.1–10,000,000 USDC |
| `VOID` (on-chain ticker `∅`) | [`J2bU…pump`](https://solscan.io/token/J2bUGZDxRDpsVfjZqKwn6yYCUKFmqzHgt8UajhGtpump) | 6 | [`Bko1…Bsz5`](https://solscan.io/account/Bko1EsrQdfmwzgmYUXWDznBemPEmPq25YEM45J5SBsz5) | 1–100,000,000 VOID |

The Context above supplies the USDC and VOID Switchboard feeds required for relayed withdrawals. The values in the table are the same current deposit/withdraw limits shown above; they can change. Before enabling an action, read the active pool limit with `await voidify.nova.fetchNovaExternalAmountLimits(ctx, "USDC")` (or `"VOID"`).

```ts
import { voidify, type Context } from "@voidifydao/sdk";

type MainnetNovaSplToken = "USDC" | "VOID";

export async function depositSpl(
  ctx: Context,
  amount: string,
  token: MainnetNovaSplToken,
  passphrase?: string,
) {
  const { signature } = await voidify.nova.deposit(
    ctx,
    amount,
    token,
    passphrase,
  );
  return signature;
}

export function withdrawSpl(
  ctx: Context,
  amount: string,
  token: MainnetNovaSplToken,
  recipient: string,
  passphrase?: string,
) {
  return voidify.nova.withdraw(
    ctx,
    amount,
    recipient,
    undefined,
    undefined,
    false,
    token,
    passphrase,
  );
}

await depositSpl(ctx, "10", "USDC");
await withdrawSpl(ctx, "10", "VOID", "<RECIPIENT_PUBLIC_KEY>");
```

Both mints use the legacy SPL Token program; Token-2022 and other SPL mints are not currently deployed Nova pools. A pool and OracleConfig do not guarantee that a relayer is currently available or that its treasury has enough liquidity, so handle those failures in the UI. An SPL deposit needs the connected wallet's source ATA and sufficient balance. For a relayed SPL withdrawal, the relayer creates the recipient ATA when necessary and pays its rent. If it cannot fund transaction fees or rent, the request fails with HTTP 503 and code `RELAYER_INSUFFICIENT_SOL`; present this as a retryable relayer error.

### Security and UX

- Treat the passphrase and serialized `note` as secrets. Never send either to a backend, relayer, logs, analytics, error tracker, URL, clipboard helper, or browser storage.
- The same wallet and passphrase are needed to rediscover encrypted Nova outputs. Clearing IndexedDB causes a resync; it is not a reason to store serialized Notes.
- Use HTTPS and verify the RPC URL, program ID, proof artifacts, token mint, and feeds before handling funds.
- Initial synchronization and proof generation can take time. Run these operations from user actions, not a render loop, and show wallet/progress states.

## Nova CLI

The optional CLI is for local Nova operations and requires Node.js 22 or later. It uses a local Solana keypair and is not part of a browser integration.

### Install and configure

```bash
npm install --global @voidifydao/sdk
voidify config init --type default

# Mainnet Nova deployment
voidify config set programId 4WJnXP7mFxFY45SYvfyGDwEBdcwafVqdgbYYSHpoded4

# Your local Solana signer and the extracted proof artifacts
voidify config set keypair.path "/absolute/path/to/solana-keypair.json"
voidify config set proof.novaWasmPath "/absolute/path/to/nova-transaction.wasm"
voidify config set proof.novaZkeyPath "/absolute/path/to/nova-transaction.zkey"
```

The default template already contains the mainnet RPC URL, local SQLite path, and SOL/USDC/VOID metadata and feeds. Set `rpcUrl` only when using another mainnet RPC endpoint. The CLI does not download Nova WASM or ZKey artifacts: download and extract the same release asset, then use the extracted local files in the commands above. By default, it reads `$XDG_CONFIG_HOME/voidify/config.json` on Linux/macOS, falling back to `~/.config/voidify/config.json` when `XDG_CONFIG_HOME` is unset; on Windows it reads `%APPDATA%\voidify\config.json`. Use another config with `-c`:

```bash
voidify -c ./voidify.json nova --help
```

### Nova commands

```bash
# Deposit
voidify nova deposit 1 --token SOL

# Read the latest balance
voidify nova pool latest --token SOL

# Withdraw through a relayer
voidify nova withdraw 1 \
  --token SOL \
  --recipient "<RECIPIENT_PUBLIC_KEY>"

# Withdraw directly
voidify nova direct-withdraw 1 \
  --token SOL \
  --recipient "<RECIPIENT_PUBLIC_KEY>"

# List pool records, deposits, and withdrawals
voidify nova pool list --token SOL --limit 20
voidify nova deposit list --token SOL --limit 20
voidify nova withdraw list --token SOL --limit 20

# See available Note commands without placing a Note in shell arguments
voidify nova note --help
```

`nova deposit` prints a serialized Note, which is a spendable secret. Run it only in a private terminal and keep stdout out of logs, transcripts, and tickets. If you use a passphrase, append `--passphrase` and enter it only in a private terminal; do not pass a value inline because it is stored in shell history. The current interactive prompt echoes input. Do not put a serialized Note in a shell argument; use `voidify nova note --help` to inspect the available Note tools.
