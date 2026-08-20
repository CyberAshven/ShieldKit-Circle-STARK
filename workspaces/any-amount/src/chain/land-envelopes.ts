/**
 * Land envelope A (100 KB), B (1 MB), and C (chained tape + last-hop pay)
 * on Chipnet, one after another. Not a Core 1p1c package.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { binToHex, hexToBin } from "@bitauth/libauth";
import { loadLabWallet } from "./wallet.ts";
import { broadcast, connectChipnet, getTx, listUnspent } from "./electrum.ts";
import { rpcConfigFromEnv } from "./bchn-rpc.ts";
import { start9NsenterRpc } from "./start9-nsenter-rpc.ts";
import { broadcastSized } from "./broadcast-tx.ts";
import {
  compileCovenantSpend,
  compileCovenantSuccessor,
  compileFundVerifierKernels,
} from "./covenant-spend.ts";
import { broadcastChained, compileChainedWithdraw, compileTapeFunder } from "./chained.ts";
import { circleFriPlugin } from "../backends/circle/plugin.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../pool/mix-successor.ts";
import { encodePublicPaa1, utxoValueFor } from "../pool/state.ts";
import { SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } from "./air-cqz.ts";
import { successorFeeCoinSats, type TxEnvelope } from "./envelope.ts";

export type LandWhich = "standard" | "consensus" | "chained" | "all";

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
    rpc:
      raw.length > 100_000
        ? process.env.BCHN_RPC_URL
          ? rpcConfigFromEnv()
          : start9NsenterRpc()
        : undefined,
  });
  return sent;
}

async function waitForTxid(client: Awaited<ReturnType<typeof connectChipnet>>, txid: string): Promise<void> {
  for (let i = 0; i < 12; i += 1) {
    try {
      await getTx(client, txid);
      return;
    } catch {
      await sleep(1500);
    }
  }
}

function pickFunded(
  utxos: Array<{ tx_hash: string; tx_pos: number; value: number; height: number }>,
  need: number,
) {
  const ok = utxos.filter((u) => u.value >= need).sort((a, b) => a.value - b.value);
  return ok[0];
}

async function landAB(
  envelope: "standard" | "consensus",
  slots: number,
  scratch: string,
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
    const need = envelope === "consensus" ? 800_000 : 400_000;
    const utxos = await listUnspent(client, wallet.address);
    let picked = pickFunded(utxos, need);
    if (!picked) {
      return {
        envelope,
        slots,
        ok: false,
        error: `no funded utxo >= ${need}; count=${utxos.length} max=${utxos.reduce((m, u) => Math.max(m, u.value), 0)}`,
        address: wallet.address,
      };
    }
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0 || picked.value > need + 50_000) {
      step = "split-off";
      const split = compileTapeFunder({
        wallet,
        utxo: picked,
        tapeSats: BigInt(need),
      });
      prepTxid = (await broadcastRetry(client, split.raw, split.txid)).txid;
      await waitForTxid(client, split.txid);
      picked = { tx_hash: split.txid, tx_pos: 0, value: need, height: 0 };
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
      return {
        envelope,
        slots,
        ok: false,
        genesis: genesisTxid,
        prep: prepTxid ?? null,
        error: `change too small ${genesis.changeValue}`,
      };
    }
    step = "kernels";
    const funded = compileFundVerifierKernels(
      wallet,
      { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue },
      1_000,
      slots,
      successorFeeCoinSats(envelope),
    );
    const kernelTxid = (await broadcastRetry(client, funded.raw, funded.txid)).txid;
    await waitForTxid(client, kernelTxid);
    step = "successor";
    const successor = compileCovenantSuccessor({
      wallet,
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
      note: mix.spent.note,
      change: mix.witness.created?.note,
    });
    mkdirSync(scratch, { recursive: true });
    writeFileSync(join(scratch, `successor-${envelope}.hex`), binToHex(successor.raw));
    const sent = await broadcastRetry(client, successor.raw, successor.txid);
    return {
      envelope,
      slots,
      ok: true,
      address: wallet.address,
      prep: prepTxid ?? null,
      genesis: genesisTxid,
      kernels: kernelTxid,
      successor: sent.txid,
      txBytes: successor.txBytes,
      unlockingBytes: successor.unlockingBytes,
      broadcastPath: sent.path,
      explorer: {
        genesis: `https://chipnet.imaginary.cash/tx/${genesisTxid}`,
        kernels: `https://chipnet.imaginary.cash/tx/${kernelTxid}`,
        successor: `https://chipnet.imaginary.cash/tx/${sent.txid}`,
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

async function landC(hops: number, scratch: string): Promise<Record<string, unknown>> {
  const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 1_000n });
  if (!mixChangedRootsAndReserve(mix)) throw new Error("mix did not update roots");
  const v = circleFriPlugin.verify(mix.statement, mix.proof);
  if (!v.ok) throw new Error(`verify: ${v.reason}`);
  const wallet = await loadLabWallet();
  const client = await connectChipnet();
  let step = "connect";
  try {
    step = "listunspent";
    const need = 400_000;
    const utxos = await listUnspent(client, wallet.address);
    let picked = pickFunded(utxos, need);
    if (!picked) {
      return {
        envelope: "chained",
        ok: false,
        error: `no funded utxo >= ${need}; count=${utxos.length} max=${utxos.reduce((m, u) => Math.max(m, u.value), 0)}`,
        address: wallet.address,
      };
    }
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0 || picked.value > need + 50_000) {
      step = "split-off";
      const split = compileTapeFunder({
        wallet,
        utxo: picked,
        tapeSats: BigInt(need),
      });
      prepTxid = (await broadcastRetry(client, split.raw, split.txid)).txid;
      await waitForTxid(client, split.txid);
      picked = { tx_hash: split.txid, tx_pos: 0, value: need, height: 0 };
    }
    step = "genesis";
    const genesis = compileCovenantSpend({
      wallet,
      utxo: picked,
      state: mix.oldState,
      proof: mix.proof,
      lockKind: "p2sh32",
      envelope: "standard",
      slotKernels: SLOT_KERNEL_COUNT,
    });
    const genesisTxid = (await broadcastRetry(client, genesis.raw, genesis.txid)).txid;
    await waitForTxid(client, genesisTxid);
    if (genesis.changeValue === undefined || genesis.changeValue < 200_000) {
      return { envelope: "chained", ok: false, genesis: genesisTxid, error: `change too small ${genesis.changeValue}` };
    }
    step = "tape-funder";
    const split = compileTapeFunder({
      wallet,
      utxo: { tx_hash: genesisTxid, tx_pos: 1, value: genesis.changeValue },
      tapeSats: 300_000n,
    });
    const splitTxid = (await broadcastRetry(client, split.raw, split.txid)).txid;
    await waitForTxid(client, split.txid);
    step = "kernels";
    const funded = compileFundVerifierKernels(
      wallet,
      split.funderUtxo,
      1_000,
      SLOT_KERNEL_COUNT,
      successorFeeCoinSats("standard"),
      true,
    );
    const kernelTxid = (await broadcastRetry(client, funded.raw, funded.txid)).txid;
    await waitForTxid(client, kernelTxid);
    step = "compile-chain";
    const chain = compileChainedWithdraw({
      wallet,
      tapeUtxo: split.tapeUtxo,
      hops,
      digest: mix.proof.slice(0, 32),
      proof: mix.proof,
      pool: {
        tx_hash: genesisTxid,
        tx_pos: 0,
        value: utxoValueFor(mix.oldState),
        category: hexToBin(picked.tx_hash),
        commitment: encodePublicPaa1(mix.oldState),
      },
      newState: mix.newState,
      statement: mix.statement,
      kernelUtxos: funded.fri,
      extraKernels: funded.extra,
      note: mix.spent.note,
      change: mix.witness.created?.note,
    });
    mkdirSync(scratch, { recursive: true });
    for (const hop of chain.hops) {
      writeFileSync(join(scratch, `chained-hop-${hop.index}-${hop.role}.hex`), binToHex(hop.raw));
    }
    step = "broadcast-chain";
    const sent = await broadcastChained({
      hops: chain.hops,
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
        throw last ?? new Error("electrum broadcast failed");
      },
      rpc: chain.hops.some((h) => h.raw.length > 100_000) ? rpcConfigFromEnv() : undefined,
    });
    const pay = sent[sent.length - 1]!;
    return {
      envelope: "chained",
      ok: true,
      address: wallet.address,
      prep: prepTxid ?? null,
      genesis: genesisTxid,
      tapeFunder: splitTxid,
      kernels: kernelTxid,
      hops: sent,
      shape: {
        hopBytes: chain.hops.map((h) => ({ index: h.index, role: h.role, txBytes: h.txBytes, payoutCount: h.payoutCount })),
        totalBytes: chain.totalBytes,
        payIndex: chain.payIndex,
      },
      successor: pay.txid,
      explorer: {
        genesis: `https://chipnet.imaginary.cash/tx/${genesisTxid}`,
        pay: `https://chipnet.imaginary.cash/tx/${pay.txid}`,
      },
      verify: v,
    };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`chained ${step}: ${msg}`);
  } finally {
    client.close();
  }
}

export async function landChipnetEnvelopes(args: {
  which: LandWhich;
  hops: number;
  scratch: string;
}): Promise<Record<string, unknown>> {
  mkdirSync(args.scratch, { recursive: true });
  const report: Record<string, unknown> = {
    network: "chipnet",
    started: new Date().toISOString(),
    which: args.which,
    slotKernelsStandard: SLOT_KERNEL_COUNT,
    slotKernelsConsensus: SLOT_KERNEL_COUNT_CONSENSUS,
    chainedHops: args.hops,
    scenarios: {} as Record<string, unknown>,
  };
  const scenarios = report.scenarios as Record<string, unknown>;
  const run = async (name: string, fn: () => Promise<Record<string, unknown>>) => {
    try {
      scenarios[name] = await fn();
    } catch (e) {
      scenarios[name] = { envelope: name, ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  };
  if (args.which === "all" || args.which === "standard") {
    await run("standard", () => landAB("standard", SLOT_KERNEL_COUNT, args.scratch));
  }
  if (args.which === "all" || args.which === "consensus") {
    await run("consensus", () => landAB("consensus", SLOT_KERNEL_COUNT_CONSENSUS, args.scratch));
  }
  if (args.which === "all" || args.which === "chained") {
    await run("chained", () => landC(args.hops, args.scratch));
  }
  report.finished = new Date().toISOString();
  writeFileSync(join(args.scratch, "chipnet-land.log"), `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

export type { TxEnvelope };
