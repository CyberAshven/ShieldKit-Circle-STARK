import {
  binToHex,
  encodeTransaction,
  generateTransaction,
  hashTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { encodePublicPaa1, encodeState, STATE_BASE_SATS, type AnyAmountState } from "../pool/state.ts";
import { createLabWallet, privateKeyOf, type LabWallet } from "./wallet.ts";
import { broadcast, connectChipnet, getTx, listUnspent } from "./electrum.ts";

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

async function broadcastWithRetry(client: Awaited<ReturnType<typeof connectChipnet>>, rawHex: string): Promise<string> {
  let last: Error | undefined;
  for (let i = 0; i < 5; i += 1) {
    try {
      return await broadcast(client, rawHex);
    } catch (e) {
      last = e instanceof Error ? e : new Error(String(e));
      const msg = last.message.toLowerCase();
      if (!msg.includes("missing") && !msg.includes("orphan") && !msg.includes("bad-txns-inputs")) {
        throw last;
      }
      await sleep(1500 * (i + 1));
    }
  }
  throw last ?? new Error("broadcast retry exhausted");
}

async function waitForTx(client: Awaited<ReturnType<typeof connectChipnet>>, txid: string): Promise<void> {
  for (let i = 0; i < 8; i += 1) {
    try {
      await getTx(client, txid);
      return;
    } catch {
      await sleep(1000);
    }
  }
}
import {
  compilePoolCovenant,
  p2sUnlocking,
  p2sh32Unlocking,
  poolLockP2s,
  poolLockP2sFor,
  poolLockP2sh32,
} from "./covenant-p2s.ts";
import { decodeFriProof } from "../backends/circle/fri.ts";
import { decodeState } from "../pool/state.ts";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import { CONSENSUS_TX_BYTES, RELAY_STANDARD_TX_BYTES, type TxEnvelope } from "./envelope.ts";
import { friShardUnlockings } from "./fri-openings.ts";
import {
  compileCqzLockP2sh32,
  compileSlotsLockP2sh32,
  cqzKernelUnlocking,
  encodeAirPacked,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  SLOTS_PER_KERNEL,
  slotsKernelUnlocking,
} from "./air-cqz.ts";
import type { PoolStatement } from "../pool/statement.ts";

export type LockKind = "p2s" | "p2sh32";

export type MeasuredTx = {
  raw: Uint8Array;
  txid: string;
  txBytes: number;
  unlockingBytes: number;
  lockP2sBytes: number;
  lockP2sh32Bytes: number;
  proofBytes: number;
  proofSlotBytes: number;
  lockKind: LockKind;
  changeValue?: number;
};

export function proofSlot(proof: Uint8Array): Uint8Array {
  return proof;
}

function compiler() {
  return walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
}

function lockOf(kind: LockKind, slotKernels = SLOT_KERNEL_COUNT): Uint8Array {
  return kind === "p2s" ? poolLockP2sFor({ slotKernels }) : poolLockP2sh32({ slotKernels });
}

function measureOf(
  raw: Uint8Array,
  unlockingBytes: number,
  proof: Uint8Array,
  lockKind: LockKind,
): MeasuredTx {
  return {
    raw,
    txid: hashTransaction(raw),
    txBytes: raw.length,
    unlockingBytes,
    lockP2sBytes: poolLockP2s().length,
    lockP2sh32Bytes: poolLockP2sh32().length,
    proofBytes: proof.length,
    proofSlotBytes: 0,
    lockKind,
  };
}

/**
 * Genesis: P2PKH funds a P2S / P2SH32 five-point cell.
 * NFT commitment is the 128-byte PAA1 state (Layla). Verify is the FRI-kernel
 * input on the successor — genesis only creates the cell.
 */
export function compileCovenantSpend(args: {
  wallet: LabWallet;
  utxo: { tx_hash: string; tx_pos: number; value: number };
  state: AnyAmountState;
  proof: Uint8Array;
  lockKind?: LockKind;
}): MeasuredTx {
  const lockKind = args.lockKind ?? "p2sh32";
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const fee = 1_200n;
  const value = STATE_BASE_SATS;
  const change = BigInt(args.utxo.value) - value - fee;
  if (change < 546n) throw new Error("utxo too small for covenant spend");

  const commitment = encodePublicPaa1(args.state);
  if (commitment.length !== 128) throw new Error("PAA1 must be 128 bytes");

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
      {
        lockingBytecode: lockOf(lockKind),
        valueSatoshis: value,
        token: {
          amount: 0n,
          category: hexToBin(args.utxo.tx_hash),
          nft: { capability: "mutable", commitment },
        },
      },
      {
        lockingBytecode: { compiler: c, script: "lock", data },
        valueSatoshis: change,
      },
    ],
  });
  if (!generated.success) {
    throw new Error(`covenant spend: ${JSON.stringify(generated.errors).slice(0, 500)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const measured = measureOf(raw, generated.transaction.inputs[0]!.unlockingBytecode.length, args.proof, lockKind);
  measured.changeValue = Number(change);
  return measured;
}

/**
 * Five-point successor: pool input 0 + FRI-kernel input 1 + P2PKH fee.
 * Output 0 keeps lock, category, token amount 0, and a new 128-byte PAA1.
 */
export function compileCovenantSuccessor(args: {
  wallet: LabWallet;
  feeUtxo: { tx_hash: string; tx_pos: number; value: number };
  pool: {
    tx_hash: string;
    tx_pos: number;
    value: number;
    category: Uint8Array;
    commitment: Uint8Array;
  };
  newState: AnyAmountState;
  proof: Uint8Array;
  statement?: PoolStatement;
  lockKind?: LockKind;
  kernelUtxo?: { tx_hash: string; tx_pos: number; value: number };
  kernelUtxos?: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  extraKernels?: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  envelope?: TxEnvelope;
  slotKernels?: number;
}): MeasuredTx {
  const lockKind = args.lockKind ?? "p2sh32";
  const slotKernels =
    args.slotKernels ??
    (args.envelope === "consensus" ? SLOT_KERNEL_COUNT_CONSENSUS : SLOT_KERNEL_COUNT);
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const fee = 100_000n;
  const value = STATE_BASE_SATS;
  const change = BigInt(args.feeUtxo.value) - fee;
  if (change < 546n) throw new Error("fee utxo too small for successor");
  const commitment = encodePublicPaa1(args.newState);
  const oldState = decodeState(args.pool.commitment);
  const decoded = decodeFriProof(args.proof);
  const packed = args.statement ? encodeAirPacked(args.statement, decoded) : decoded.layerRoots;
  const unlocking = lockKind === "p2s" ? p2sUnlocking(undefined, packed) : p2sh32Unlocking(undefined, packed);
  const shards = friShardUnlockings(args.proof);
  const dummy = "44".repeat(32);
  const kernels = args.kernelUtxos ??
    (args.kernelUtxo
      ? [args.kernelUtxo]
      : shards.map((_, i) => ({ tx_hash: dummy, tx_pos: i, value: 1000 })));
  if (kernels.length !== FRI_KERNEL_INPUTS) {
    throw new Error(`need ${FRI_KERNEL_INPUTS} FRI kernel UTXOs, got ${kernels.length}`);
  }
  const extras = args.extraKernels ?? [
    { tx_hash: dummy, tx_pos: 10, value: 1000 },
    ...Array.from({ length: slotKernels }, (_, i) => ({ tx_hash: dummy, tx_pos: 11 + i, value: 1000 })),
  ];
  if (extras.length !== 1 + slotKernels) {
    throw new Error(`need ${1 + slotKernels} extra kernel UTXOs, got ${extras.length}`);
  }

  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      {
        outpointIndex: args.pool.tx_pos,
        outpointTransactionHash: hexToBin(args.pool.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: unlocking,
      },
      ...shards.map((friUnlock, i) => ({
        outpointIndex: kernels[i]!.tx_pos,
        outpointTransactionHash: hexToBin(kernels[i]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: friUnlock,
      })),
      {
        outpointIndex: extras[0]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[0]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: cqzKernelUnlocking(),
      },
      ...Array.from({ length: slotKernels }, (_, i) => ({
        outpointIndex: extras[1 + i]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[1 + i]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: slotsKernelUnlocking(i * SLOTS_PER_KERNEL),
      })),
      {
        outpointIndex: args.feeUtxo.tx_pos,
        outpointTransactionHash: hexToBin(args.feeUtxo.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: {
          compiler: c,
          script: "unlock",
          data,
          valueSatoshis: BigInt(args.feeUtxo.value),
        },
      },
    ],
    outputs: [
      {
        lockingBytecode: lockOf(lockKind, slotKernels),
        valueSatoshis: value,
        token: {
          amount: 0n,
          category: args.pool.category,
          nft: { capability: "mutable", commitment },
        },
      },
      {
        lockingBytecode: { compiler: c, script: "lock", data },
        valueSatoshis: change + BigInt(args.pool.value) - value,
      },
    ],
  });
  if (!generated.success) {
    throw new Error(`covenant successor: ${JSON.stringify(generated.errors).slice(0, 500)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const poolUnlock = generated.transaction.inputs[0]!.unlockingBytecode.length;
  return measureOf(raw, poolUnlock, args.proof, lockKind);
}

export function measureCovenantSpend(state: AnyAmountState, proof: Uint8Array, lockKind: LockKind = "p2sh32"): MeasuredTx {
  return compileCovenantSpend({
    wallet: createLabWallet(),
    utxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: 1_000_000 },
    state,
    proof,
    lockKind,
  });
}

export function measureGenesisAndSuccessor(state: AnyAmountState, next: AnyAmountState, proof: Uint8Array): {
  genesisP2sh32: MeasuredTx;
  genesisP2s: MeasuredTx;
  successorP2sh32: MeasuredTx;
} {
  const wallet = createLabWallet();
  const genesisP2sh32 = compileCovenantSpend({
    wallet,
    utxo: { tx_hash: "11".repeat(32), tx_pos: 0, value: 2_000_000 },
    state,
    proof,
    lockKind: "p2sh32",
  });
  const genesisP2s = compileCovenantSpend({
    wallet,
    utxo: { tx_hash: "22".repeat(32), tx_pos: 0, value: 2_000_000 },
    state,
    proof,
    lockKind: "p2s",
  });
  const successorP2sh32 = compileCovenantSuccessor({
    wallet,
    feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
    pool: {
      tx_hash: genesisP2sh32.txid,
      tx_pos: 0,
      value: Number(STATE_BASE_SATS),
      category: hexToBin("11".repeat(32)),
      commitment: encodePublicPaa1(state),
    },
    newState: next,
    proof,
    lockKind: "p2sh32",
  });
  return { genesisP2sh32, genesisP2s, successorP2sh32 };
}

/** CashTokens genesis is only legal from a parent vout=0. */
export function compileSelfSendVout0(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
): { raw: Uint8Array; txid: string; value: number } {
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const fee = 400n;
  const value = BigInt(utxo.value) - fee;
  if (value < 546n) throw new Error("utxo too small to prep genesis vout0");
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
        valueSatoshis: value,
      },
    ],
  });
  if (!generated.success) {
    throw new Error(`self-send: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  return { raw, txid: hashTransaction(raw), value: Number(value) };
}

/** 10 FRI + bind-T + slot C=QZ carriers. */
export function compileFundVerifierKernels(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  kernelSats = 1_000,
): {
  raw: Uint8Array;
  txid: string;
  fri: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  extra: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  changeValue: number;
  changePos: number;
} {
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const extraCount = 1 + SLOT_KERNEL_COUNT;
  const count = FRI_KERNEL_INPUTS + extraCount;
  const fee = 1_000n;
  const change = BigInt(utxo.value) - BigInt(kernelSats) * BigInt(count) - fee;
  if (change < 546n) throw new Error("utxo too small to fund verifier kernels");
  const friOut = { lockingBytecode: compileFriQueryLockP2sh32(), valueSatoshis: BigInt(kernelSats) };
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
      ...Array.from({ length: FRI_KERNEL_INPUTS }, () => friOut),
      { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: BigInt(kernelSats) },
      ...Array.from({ length: SLOT_KERNEL_COUNT }, (_, i) => ({
        lockingBytecode: compileSlotsLockP2sh32(i),
        valueSatoshis: BigInt(kernelSats),
      })),
      { lockingBytecode: { compiler: c, script: "lock", data }, valueSatoshis: change },
    ],
  });
  if (!generated.success) {
    throw new Error(`fund verifier kernels: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    fri: Array.from({ length: FRI_KERNEL_INPUTS }, (_, i) => ({ tx_hash: txid, tx_pos: i, value: kernelSats })),
    extra: Array.from({ length: extraCount }, (_, i) => ({
      tx_hash: txid,
      tx_pos: FRI_KERNEL_INPUTS + i,
      value: kernelSats,
    })),
    changeValue: Number(change),
    changePos: count,
  };
}

/** Fund FRI-kernel P2SH32 carriers (one per proof shard) so the successor can spend them. */
export function compileFundFriKernels(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  count = FRI_KERNEL_INPUTS,
  kernelSats = 1_000,
): {
  raw: Uint8Array;
  txid: string;
  kernels: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  changeValue: number;
} {
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const fee = 800n;
  const change = BigInt(utxo.value) - BigInt(kernelSats) * BigInt(count) - fee;
  if (change < 546n) throw new Error("utxo too small to fund FRI kernels");
  const kernelOut = { lockingBytecode: compileFriQueryLockP2sh32(), valueSatoshis: BigInt(kernelSats) };
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
      ...Array.from({ length: count }, () => kernelOut),
      { lockingBytecode: { compiler: c, script: "lock", data }, valueSatoshis: change },
    ],
  });
  if (!generated.success) {
    throw new Error(`fund kernels: ${JSON.stringify(generated.errors).slice(0, 400)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  const txid = hashTransaction(raw);
  return {
    raw,
    txid,
    kernels: Array.from({ length: count }, (_, i) => ({ tx_hash: txid, tx_pos: i, value: kernelSats })),
    changeValue: Number(change),
  };
}

/** @deprecated use compileFundFriKernels */
export function compileFundFriKernel(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  kernelSats = 1_000,
): { raw: Uint8Array; txid: string; kernel: { tx_hash: string; tx_pos: number; value: number }; changeValue: number } {
  const funded = compileFundFriKernels(wallet, utxo, 1, kernelSats);
  return { raw: funded.raw, txid: funded.txid, kernel: funded.kernels[0]!, changeValue: funded.changeValue };
}

export async function broadcastCovenantGenesis(
  wallet: LabWallet,
  state: AnyAmountState,
  proof: Uint8Array,
  lockKind: LockKind = "p2sh32",
): Promise<MeasuredTx & { broadcast: string; prepTxid?: string; categoryHex: string }> {
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, wallet.address);
    if (utxos.length === 0) throw new Error("no Chipnet coins — fund the lab address");
    let picked = utxos.reduce((a, b) => (a.value >= b.value ? a : b));
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0) {
      const prep = compileSelfSendVout0(wallet, picked);
      prepTxid = await broadcastWithRetry(client, binToHex(prep.raw));
      picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value };
      await waitForTx(client, prep.txid);
    }
    const measured = compileCovenantSpend({
      wallet,
      utxo: picked,
      state,
      proof,
      lockKind,
    });
    const txid = await broadcastWithRetry(client, binToHex(measured.raw));
    return { ...measured, broadcast: txid, prepTxid, categoryHex: picked.tx_hash };
  } finally {
    client.close();
  }
}

export { compilePoolCovenant, STATE_BASE_SATS };
