/**
 * Land standard (100 KB / 6 slots) and consensus (1 MB / 36 slots) spends on Chipnet.
 * Writes a report. Never prints WIF or keys.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { binToHex, hexToBin } from "@bitauth/libauth";
import { loadLabWallet } from "../src/chain/wallet.ts";
import { broadcast, connectChipnet, getTx, listUnspent } from "../src/chain/electrum.ts";
import { rpcConfigFromEnv } from "../src/chain/bchn-rpc.ts";
import { broadcastSized } from "../src/chain/broadcast-tx.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
  compileSelfSendVout0,
} from "../src/chain/covenant-spend.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../src/pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import type { TxEnvelope } from "../src/chain/envelope.ts";

const scratch = process.argv[2];
const only = (process.argv[3] ?? "both") as "both" | "standard" | "consensus";
if (!scratch) throw new Error("usage: land-chipnet <scratchDir> [both|standard|consensus]");

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function broadcastRetry(
  client: Awaited<ReturnType<typeof connectChipnet>>,
  raw: Uint8Array,
  expectedTxid: string,
): Promise<{ txid: string; path: string }> {
  const sent = await broadcastSized({
    raw,
    electrum: async (hex) => {
      let last: Error | undefined;
      for (let i = 0; i < 3; i += 1) {
        try {
          return await broadcast(client, hex);
        } catch (e) {
          last = e instanceof Error ? e : new Error(String(e));
          const msg = last.message.toLowerCase();
          if (
            !msg.includes("missing") &&
            !msg.includes("orphan") &&
            !msg.includes("bad-txns-inputs") &&
            !msg.includes("timed out")
          ) {
            break;
          }
          await sleep(1200 * (i + 1));
        }
      }
      try {
        await getTx(client, expectedTxid);
        return expectedTxid;
      } catch {
        throw last ?? new Error("electrum broadcast failed");
      }
    },
    rpc: raw.length > 100_000 ? rpcConfigFromEnv() : undefined,
  });
  return sent;
}

async function waitForTxid(
  client: Awaited<ReturnType<typeof connectChipnet>>,
  txid: string,
): Promise<void> {
  for (let i = 0; i < 12; i += 1) {
    try {
      await getTx(client, txid);
      return;
    } catch {
      await sleep(1500);
    }
  }
}

const report: Record<string, unknown> = {
  network: "chipnet",
  started: new Date().toISOString(),
  slotKernelsStandard: SLOT_KERNEL_COUNT,
  slotKernelsConsensus: SLOT_KERNEL_COUNT_CONSENSUS,
  scenarios: {} as Record<string, unknown>,
};

async function landEnvelope(
  envelope: TxEnvelope,
  slots: number,
): Promise<Record<string, unknown>> {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots");
  const v = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!v.ok) throw new Error(`verify: ${v.reason}`);
  const wallet = await loadLabWallet();
  const client = await connectChipnet();
  let step = "connect";
  try {
    step = "listunspent";
    const utxos = await listUnspent(client, wallet.address);
    let picked =
      utxos.find((u) => u.tx_pos === 0 && u.value > 200_000) ??
      utxos.find((u) => u.value > 200_000);
    if (!picked) {
      return {
        envelope,
        slots,
        ok: false,
        error: `no funded utxo; count=${utxos.length} max=${utxos.reduce((m, u) => Math.max(m, u.value), 0)}`,
        address: wallet.address,
      };
    }
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0) {
      step = "prep-vout0";
      const prep = compileSelfSendVout0(wallet, picked);
      prepTxid = (await broadcastRetry(client, prep.raw, prep.txid)).txid;
      await waitForTxid(client, prep.txid);
      picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value, height: 0 };
    }
    step = "genesis";
    const genesis = compileCovenantSpend({
      wallet,
      utxo: picked,
      state: mix.oldState,
      proof: mix.proof,
      lockKind: "p2sh32",
      envelope,
      slotKernels: slots,
    });
    const genesisTxid = (await broadcastRetry(client, genesis.raw, genesis.txid)).txid;
    await waitForTxid(client, genesisTxid);
    if (genesis.changeValue === undefined || genesis.changeValue < 200_000) {
      return { envelope, slots, ok: false, genesis: genesisTxid, prep: prepTxid ?? null, error: `change too small ${genesis.changeValue}` };
    }
    step = "kernels";
    const funded = compileFundVerifierKernels(
      wallet,
      { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue },
      1_000,
      slots,
    );
    const kernelTxid = (await broadcastRetry(client, funded.raw, funded.txid)).txid;
    await waitForTxid(client, kernelTxid);
    step = "successor";
    const successor = compileCovenantSuccessor({
      wallet,
      feeUtxo: { tx_hash: funded.txid, tx_pos: funded.changePos, value: funded.changeValue },
      pool: {
        tx_hash: genesisTxid,
        tx_pos: 0,
        value: utxoValueFor(mix.oldState),
        category: hexToBin(picked.tx_hash),
        commitment: encodePublicPaa1(mix.oldState),
      },
      newState: mix.newState,
      proof: mix.proof,
      statement: mix.statement,
      lockKind: "p2sh32",
      envelope,
      slotKernels: slots,
      kernelUtxos: funded.fri,
      extraKernels: funded.extra,
    });
    writeFileSync(join(scratch, `successor-${envelope}.hex`), binToHex(successor.raw));
    const sent = await broadcastRetry(client, successor.raw, successor.txid);
    const succTxid = sent.txid;
    return {
      envelope,
      slots,
      ok: true,
      address: wallet.address,
      prep: prepTxid ?? null,
      genesis: genesisTxid,
      kernels: kernelTxid,
      successor: succTxid,
      txBytes: successor.txBytes,
      unlockingBytes: successor.unlockingBytes,
      broadcastPath: sent.path,
      explorer: {
        genesis: `https://chipnet.imaginary.cash/tx/${genesisTxid}`,
        kernels: `https://chipnet.imaginary.cash/tx/${kernelTxid}`,
        successor: `https://chipnet.imaginary.cash/tx/${succTxid}`,
      },
      verify: v,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`${envelope} ${step}: ${msg}`);
  } finally {
    client.close();
  }
}

if (only === "both" || only === "standard") {
  try {
    (report.scenarios as Record<string, unknown>).standard = await landEnvelope("standard", SLOT_KERNEL_COUNT);
  } catch (e) {
    (report.scenarios as Record<string, unknown>).standard = {
      envelope: "standard",
      ok: false,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}
if (only === "both" || only === "consensus") {
  try {
    (report.scenarios as Record<string, unknown>).consensus = await landEnvelope("consensus", SLOT_KERNEL_COUNT_CONSENSUS);
  } catch (e) {
    (report.scenarios as Record<string, unknown>).consensus = {
      envelope: "consensus",
      ok: false,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}
report.finished = new Date().toISOString();
const path = join(scratch, only === "both" ? "chipnet-land.log" : `chipnet-land-${only}.log`);
writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
