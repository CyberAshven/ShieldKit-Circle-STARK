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
import { broadcastSized, type BroadcastPath } from "./broadcast-tx.ts";
import type { BchnRpcConfig } from "./bchn-rpc.ts";
import {
  CHAINED_HOPS_DEFAULT,
  CHAINED_TX_BYTES,
  DUST_SATS,
  parseChainedHops,
  RELAY_STANDARD_TX_BYTES,
  STANDARD_HOP_TARGET_BYTES,
  STANDARD_SUCCESSOR_FEE_SATS,
  TAPE_TIMEOUT_CSV,
} from "./envelope.ts";
import { cargoInputs, packCargoUnlockings, proofCargoLock, type CargoUtxo } from "./proof-cargo.ts";
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
  packTo?: number;
  cargoUtxos?: CargoUtxo[];
  feeSats?: bigint;
}): { raw: Uint8Array; txid: string; nextUtxo: ChainUtxo; commit: Uint8Array; cargoCount: number } {
  const packTo = args.packTo ?? STANDARD_HOP_TARGET_BYTES;
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
  const bare = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [carrier],
    outputs,
  });
  if (!bare.success) throw new Error(`tape hop: ${JSON.stringify(bare.errors).slice(0, 400)}`);
  const baseBytes = encodeTransaction(bare.transaction).length;
  const unlockings =
    packTo > 0
      ? packCargoUnlockings({
          baseBytes,
          proof: args.proof ?? args.chunkHash,
          hopIndex: args.index,
          targetBytes: packTo,
        })
      : [];
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      carrier,
      ...cargoInputs({ unlockings, utxos: args.cargoUtxos, hopIndex: args.index }),
    ],
    outputs,
  });
  if (!generated.success) {
    throw new Error(`tape hop packed: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  if (raw.length > RELAY_STANDARD_TX_BYTES) {
    throw new Error(`tape hop ${raw.length} > ${RELAY_STANDARD_TX_BYTES}`);
  }
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    commit,
    cargoCount: unlockings.length,
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

/** Split genesis-change into a tape carrier, optional proof-cargo dust, and kernel funder. */
export function compileTapeFunder(args: {
  wallet: LabWallet;
  utxo: ChainUtxo;
  tapeSats?: bigint;
  cargoCount?: number;
  feeSats?: bigint;
}): { raw: Uint8Array; txid: string; tapeUtxo: ChainUtxo; funderUtxo: ChainUtxo; cargo: CargoUtxo[] } {
  const tapeSats = args.tapeSats ?? 300_000n;
  const cargoCount = args.cargoCount ?? 0;
  const cargoSats = DUST_SATS * BigInt(cargoCount);
  const fee = args.feeSats ?? 2_000n + BigInt(cargoCount) * 80n;
  const rest = BigInt(args.utxo.value) - tapeSats - cargoSats - fee;
  if (rest < DUST_SATS) throw new Error("change too small to fund tape + kernels");
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const lock = p2pkhLockingOf(args.wallet);
  const cargoLock = proofCargoLock();
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
      ...Array.from({ length: cargoCount }, () => ({
        lockingBytecode: cargoLock,
        valueSatoshis: DUST_SATS,
      })),
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
    cargo: Array.from({ length: cargoCount }, (_, i) => ({
      tx_hash: txid,
      tx_pos: 1 + i,
      value: Number(DUST_SATS),
    })),
    funderUtxo: { tx_hash: txid, tx_pos: 1 + cargoCount, value: Number(rest) },
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
  cargoUtxos?: CargoUtxo[];
}): ChainedWithdraw {
  const hopCount = parseChainedHops(args.hops ?? CHAINED_HOPS_DEFAULT);
  const digest = args.digest.length === 32 ? args.digest : hash256(args.digest);
  const hops: ChainedHop[] = [];
  let utxo = args.tapeUtxo;
  let cargoOff = 0;
  const tapeN = hopCount - 1;
  for (let i = 0; i < tapeN; i += 1) {
    const chunk = args.proof.subarray(0, Math.min(32, args.proof.length));
    const chunkHash = hash256(concatBytes(digest, Uint8Array.of(i, hopCount), chunk));
    const hop = compileTapeHop({
      wallet: args.wallet,
      utxo,
      digest,
      index: i,
      hopCount,
      chunkHash,
      proof: args.proof,
      cargoUtxos: args.cargoUtxos?.slice(cargoOff),
    });
    cargoOff += hop.cargoCount;
    if (hop.raw.length > RELAY_STANDARD_TX_BYTES) {
      throw new Error(`tape hop ${i} ${hop.raw.length} > ${RELAY_STANDARD_TX_BYTES}`);
    }
    hops.push({
      role: "tape",
      index: i,
      raw: hop.raw,
      txid: hop.txid,
      txBytes: hop.raw.length,
      payoutCount: 0,
      commitHex: Buffer.from(hop.commit).toString("hex"),
    });
    utxo = hop.nextUtxo;
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
    kernelUtxos: args.kernelUtxos,
    extraKernels: args.extraKernels,
    extraPayouts: args.extraPayouts,
    payoutLockingBytecode: args.payoutLockingBytecode,
    packTo: STANDARD_HOP_TARGET_BYTES,
    packHopIndex: tapeN,
    cargoUtxos: args.cargoUtxos?.slice(cargoOff),
  });
  if (successor.txBytes > RELAY_STANDARD_TX_BYTES) {
    throw new Error(`pay hop ${successor.txBytes} > ${RELAY_STANDARD_TX_BYTES}`);
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
    note: "tape hops do not spend the pool; last hop pays; each standard hop packs toward 99 KB",
  };
}
