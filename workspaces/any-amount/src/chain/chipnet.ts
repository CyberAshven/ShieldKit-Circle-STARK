import {
  binToHex,
  encodeTransaction,
  generateTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { sha256 } from "../pool/bytes.ts";
import { encodeState, emptyState, type AnyAmountState } from "../pool/state.ts";
import { connectChipnet, listUnspent, broadcast } from "./electrum.ts";
import { type LabWallet, privateKeyOf } from "./wallet.ts";

function compiler() {
  return walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
}

export async function requestFaucet(address: string): Promise<string> {
  const urls = [
    `https://tbch.googol.cash/?address=${encodeURIComponent(address)}`,
    `https://rest-chipnet.fullstack.cash/v5/faucet/bch/${address}`,
  ];
  const notes: string[] = [];
  for (const url of urls) {
    try {
      const res = await fetch(url);
      const text = (await res.text()).slice(0, 200);
      notes.push(`${url} -> ${res.status} ${text.replace(/\s+/g, " ")}`);
    } catch (e) {
      notes.push(`${url} -> ${e instanceof Error ? e.message : e}`);
    }
  }
  return `Fund ${address} at https://tbch.googol.cash/ if empty.\n${notes.join("\n")}`;
}

export async function walletBalance(address: string) {
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, address);
    const sats = utxos.reduce((n, u) => n + BigInt(u.value), 0n);
    return { sats, utxos };
  } finally {
    client.close();
  }
}

/** OP_RETURN <0x4c 0x80> + 128-byte PAA1. */
function paa1OpReturn(state: AnyAmountState): Uint8Array {
  const payload = encodeState(state);
  return Uint8Array.of(0x6a, 0x4c, payload.length, ...payload);
}

export function buildMarkerTransaction(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  state: AnyAmountState,
) {
  const fee = 500n;
  const change = BigInt(utxo.value) - fee;
  if (change < 546n) throw new Error("utxo too small for marker tx");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: utxo.tx_pos,
        outpointTransactionHash: hexToBin(utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(utxo.value),
        },
      },
    ],
    outputs: [
      {
        lockingBytecode: { compiler: c, script: "lock", data },
        valueSatoshis: change,
      },
      { lockingBytecode: paa1OpReturn(state), valueSatoshis: 0n },
    ],
  });
  if (!generated.success) {
    throw new Error(`compile failed: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  return generated.transaction;
}

export async function broadcastMarkerTx(wallet: LabWallet, state: AnyAmountState): Promise<string> {
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, wallet.address);
    if (utxos.length === 0) throw new Error("no Chipnet coins — fund the lab address");
    const tx = buildMarkerTransaction(wallet, utxos[0]!, state);
    const hex = binToHex(encodeTransaction(tx));
    return await broadcast(client, hex);
  } finally {
    client.close();
  }
}

export function genesisStateFor(wallet: LabWallet): AnyAmountState {
  return emptyState(sha256(Buffer.from(wallet.publicKeyHex, "hex")));
}
