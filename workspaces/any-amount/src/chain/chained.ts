/**
 * Envelope C: pre-signed unconfirmed chain. Tape hops commit digest+i+N
 * and never pay. The last hop spends the pool and the tape tip.
 * BCHN still takes one tx at a time (not Core 1p1c). A missing tape hop
 * makes the pay hop invalid (missing inputs). Notes stay unspent until pay lands.
 */
import {
  encodeTransaction,
  generateTransaction,
  hash256,
  hashTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { concatBytes } from "../pool/bytes.ts";
import { compileCovenantSuccessor, type MeasuredTx } from "./covenant-spend.ts";
import { FRI_QUERIES } from "../backends/circle/params.ts";
import { SLOT_KERNEL_COUNT } from "./air-cqz.ts";

import { broadcastSized, type BroadcastPath } from "./broadcast-tx.ts";
import type { BchnRpcConfig } from "./bchn-rpc.ts";
import {
  CHAINED_HOPS_DEFAULT,
  CHAINED_TX_BYTES,
  DUST_SATS,
  parseChainedHops,
  RELAY_STANDARD_TX_BYTES,
  STANDARD_SUCCESSOR_FEE_SATS,
  TAPE_TIMEOUT_CSV,
} from "./envelope.ts";
import type { CargoUtxo } from "./proof-cargo.ts";
import { p2pkhLockingOf, privateKeyOf, type LabWallet } from "./wallet.ts";
import type { AnyAmountState } from "../pool/state.ts";
import type { PoolStatement } from "../pool/statement.ts";

export const TAPE_MAGIC = new Uint8Array([0x54, 0x41, 0x50, 0x45, 0x31]); // TAPE1
const TIMEOUT_FEE_SATS = 400n;

export type ChainUtxo = { tx_hash: string; tx_pos: number; value: number };

export type ChainedHop = {
  role: "tape" | "pay";
  index: number;
  raw: Uint8Array;
  txid: string;
  txBytes: number;
  payoutCount: number;
  commitHex?: string;
};

export type ChainedWithdraw = {
  envelope: "chained";
  hops: ChainedHop[];
  totalBytes: number;
  payIndex: number;
  timeout: { raw: Uint8Array; txid: string; sequence: number };
};

function compiler() {
  return walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
}

function opReturnLocking(payload: Uint8Array): Uint8Array {
  if (payload.length <= 75) return Uint8Array.of(0x6a, payload.length, ...payload);
  if (payload.length <= 255) return Uint8Array.of(0x6a, 0x4c, payload.length, ...payload);
  throw new Error("tape OP_RETURN too large");
}

export function tapeCommit(digest: Uint8Array, index: number, hopCount: number, chunkHash: Uint8Array): Uint8Array {
  return concatBytes(TAPE_MAGIC, digest, Uint8Array.of(index & 0xff, hopCount & 0xff), chunkHash);
}

export function compileTapeHop(args: {
  wallet: LabWallet;
  utxo: ChainUtxo;
  digest: Uint8Array;
  index: number;
  hopCount: number;
  chunkHash: Uint8Array;
  proof?: Uint8Array;
  feeSats?: bigint;
}): { raw: Uint8Array; txid: string; nextUtxo: ChainUtxo; commit: Uint8Array; cargoCount: number } {
  const fee = args.feeSats ?? STANDARD_SUCCESSOR_FEE_SATS;
  const nextValue = BigInt(args.utxo.value) - fee;
  if (nextValue < DUST_SATS) throw new Error("tape utxo too small");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const commit = tapeCommit(args.digest, args.index, args.hopCount, args.chunkHash);
  const carrier = {
    outpointIndex: args.utxo.tx_pos,
    outpointTransactionHash: hexToBin(args.utxo.tx_hash),
    sequenceNumber: 0xffffffff,
    unlockingBytecode: {
      compiler: c,
      script: "unlock" as const,
      data,
      valueSatoshis: BigInt(args.utxo.value),
    },
  };
  const outputs = [
    { lockingBytecode: p2pkhLockingOf(args.wallet), valueSatoshis: nextValue },
    { lockingBytecode: opReturnLocking(commit), valueSatoshis: 0n },
  ];
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [carrier],
    outputs,
  });
  if (!generated.success) throw new Error(`tape hop: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  const raw = encodeTransaction(generated.transaction);
  if (raw.length > RELAY_STANDARD_TX_BYTES) {
    throw new Error(`tape hop ${raw.length} > ${RELAY_STANDARD_TX_BYTES}`);
  }
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    commit,
    cargoCount: 0,
    nextUtxo: { tx_hash: txid, tx_pos: 0, value: Number(nextValue) },
  };
}

export function compileTapeTimeout(args: {
  wallet: LabWallet;
  tapeUtxo: ChainUtxo;
}): { raw: Uint8Array; txid: string; sequence: number } {
  const nextValue = BigInt(args.tapeUtxo.value) - TIMEOUT_FEE_SATS;
  if (nextValue < DUST_SATS) throw new Error("tape timeout utxo too small");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: args.tapeUtxo.tx_pos,
        outpointTransactionHash: hexToBin(args.tapeUtxo.tx_hash),
        sequenceNumber: TAPE_TIMEOUT_CSV,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(args.tapeUtxo.value),
        },
      },
    ],
    outputs: [{ lockingBytecode: p2pkhLockingOf(args.wallet), valueSatoshis: nextValue }],
  });
  if (!generated.success) {
    throw new Error(`tape timeout: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  return { raw, txid: hashTransaction(raw), sequence: TAPE_TIMEOUT_CSV };
}

/** Split genesis-change into a tape carrier and kernel funder. No leftover-fill cargo. */
export function compileTapeFunder(args: {
  wallet: LabWallet;
  utxo: ChainUtxo;
  tapeSats?: bigint;
  feeSats?: bigint;
}): { raw: Uint8Array; txid: string; tapeUtxo: ChainUtxo; funderUtxo: ChainUtxo; cargo: CargoUtxo[] } {
  const tapeSats = args.tapeSats ?? 300_000n;
  const fee = args.feeSats ?? 2_000n;
  const rest = BigInt(args.utxo.value) - tapeSats - fee;
  if (rest < DUST_SATS) throw new Error("change too small to fund tape + kernels");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const lock = p2pkhLockingOf(args.wallet);
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: args.utxo.tx_pos,
        outpointTransactionHash: hexToBin(args.utxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(args.utxo.value),
        },
      },
    ],
    outputs: [
      { lockingBytecode: lock, valueSatoshis: tapeSats },
      { lockingBytecode: lock, valueSatoshis: rest },
    ],
  });
  if (!generated.success) {
    throw new Error(`tape funder: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    tapeUtxo: { tx_hash: txid, tx_pos: 0, value: Number(tapeSats) },
    cargo: [],
    funderUtxo: { tx_hash: txid, tx_pos: 1, value: Number(rest) },
  };
}

export function compileChainedWithdraw(args: {
  wallet: LabWallet;
  tapeUtxo: ChainUtxo;
  hops?: number;
  digest: Uint8Array;
  proof: Uint8Array;
  pool: {
    tx_hash: string;
    tx_pos: number;
    value: number | bigint;
    category: Uint8Array;
    commitment: Uint8Array;
  };
  newState: AnyAmountState;
  statement?: PoolStatement;
  kernelUtxos?: Array<ChainUtxo>;
  extraKernels?: Array<ChainUtxo>;
  extraPayouts?: Array<{ lockingBytecode: Uint8Array; sats: bigint }>;
  payoutLockingBytecode?: Uint8Array;
  note?: import("../pool/notes.ts").Note;
  change?: import("../pool/notes.ts").Note;
  /** Per tape hop: AIR carrier + FRI + extras. Tests omit (dummy prevouts). */
  tapeKernels?: Array<{
    carrier?: ChainUtxo;
    fri: ChainUtxo[];
    extra: ChainUtxo[];
  }>;
}): ChainedWithdraw {
  const digest = args.digest.length === 32 ? args.digest : hash256(args.digest);
  const hops: ChainedHop[] = [];
  let utxo = args.tapeUtxo;
  const qn = 2;
  const tapeN = Math.ceil(FRI_QUERIES / qn);
  const hopCount = parseChainedHops(args.hops ?? tapeN + 1);
  if (hopCount < tapeN + 1) {
    throw new Error(`chained needs ${tapeN + 1} hops for ${FRI_QUERIES} unique-orbit slices (got ${hopCount})`);
  }
  for (let i = 0; i < tapeN; i += 1) {
    const q0 = i * qn;
    const thisN = Math.min(qn, FRI_QUERIES - q0);
    const group = args.tapeKernels?.[i];
    const sliceTx = compileCovenantSuccessor({
      wallet: args.wallet,
      includePool: false,
      tapeUtxo: utxo,
      carrierUtxo: group?.carrier,
      queryStart: q0,
      foldQueries: thisN,
      slotKernels: thisN,
      kernelUtxos: group?.fri,
      extraKernels: group?.extra,
      pool: args.pool,
      newState: args.newState,
      proof: args.proof,
      statement: args.statement,
      lockKind: "p2sh32",
      envelope: "standard",
    });
    if (sliceTx.txBytes > RELAY_STANDARD_TX_BYTES) {
      throw new Error(`tape hop ${i} ${sliceTx.txBytes} > ${RELAY_STANDARD_TX_BYTES} (chunk queries across hops)`);
    }
    hops.push({
      role: "tape",
      index: i,
      raw: sliceTx.raw,
      txid: sliceTx.txid,
      txBytes: sliceTx.txBytes,
      payoutCount: 0,
      commitHex: Buffer.from(digest).toString("hex"),
    });
    utxo = { tx_hash: sliceTx.txid, tx_pos: 0, value: Number(DUST_SATS) * 2 };
  }
  const timeout = compileTapeTimeout({ wallet: args.wallet, tapeUtxo: utxo });
  const successor: MeasuredTx = compileCovenantSuccessor({
    wallet: args.wallet,
    tapeUtxo: utxo,
    pool: args.pool,
    newState: args.newState,
    proof: args.proof,
    statement: args.statement,
    lockKind: "p2sh32",
    envelope: "standard",
    slotKernels: SLOT_KERNEL_COUNT,
    kernelUtxos: args.kernelUtxos,
    extraKernels: args.extraKernels,
    extraPayouts: args.extraPayouts,
    payoutLockingBytecode: args.payoutLockingBytecode,
    note: args.note,
    change: args.change,
  });
  if (successor.txBytes > RELAY_STANDARD_TX_BYTES) {
    throw new Error(`C pay hop ${successor.txBytes} > ${RELAY_STANDARD_TX_BYTES}`);
  }
  const payoutCount =
    args.extraPayouts && args.extraPayouts.length > 0
      ? args.extraPayouts.length
      : args.statement && args.statement.publicAmountSats < 0n
        ? 1
        : 0;
  hops.push({
    role: "pay",
    index: tapeN,
    raw: successor.raw,
    txid: successor.txid,
    txBytes: successor.txBytes,
    payoutCount,
  });
  const totalBytes = hops.reduce((n, h) => n + h.txBytes, 0);
  if (totalBytes > CHAINED_TX_BYTES) throw new Error(`chained ${totalBytes} > ${CHAINED_TX_BYTES}`);
  return {
    envelope: "chained",
    hops,
    totalBytes,
    payIndex: tapeN,
    timeout,
  };
}

export async function broadcastChained(args: {
  hops: ChainedHop[];
  electrum?: (rawHex: string) => Promise<string>;
  rpc?: BchnRpcConfig;
}): Promise<Array<{ txid: string; path: BroadcastPath; index: number; role: "tape" | "pay" }>> {
  const sent: Array<{ txid: string; path: BroadcastPath; index: number; role: "tape" | "pay" }> = [];
  for (const hop of args.hops) {
    try {
      const r = await broadcastSized({ raw: hop.raw, electrum: args.electrum, rpc: args.rpc });
      sent.push({ txid: r.txid, path: r.path, index: hop.index, role: hop.role });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`chained hop ${hop.index} ${hop.role}: ${msg}`);
    }
  }
  return sent;
}

export function chainedShape(chain: ChainedWithdraw): Record<string, unknown> {
  return {
    envelope: "chained",
    hops: chain.hops.map((h) => ({
      index: h.index,
      role: h.role,
      txid: h.txid,
      txBytes: h.txBytes,
      payoutCount: h.payoutCount,
      commitHex: h.commitHex ?? null,
    })),
    payIndex: chain.payIndex,
    totalBytes: chain.totalBytes,
    timeoutCsv: chain.timeout.sequence,
    timeoutTxid: chain.timeout.txid,
    note: "tape hops run fold/C=QZ slices and never pay; last hop is the 36-query consensus verifier (same as envelope B)",
  };
}
