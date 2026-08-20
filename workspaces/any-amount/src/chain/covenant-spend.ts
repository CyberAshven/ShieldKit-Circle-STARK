import {
  binToHex,
  encodeTransaction,
  generateTransaction,
  hashTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { encodePublicPaa1, encodeState, STATE_BASE_SATS, utxoValueFor, type AnyAmountState } from "../pool/state.ts";
import { isZero32 } from "../pool/bytes.ts";
import { LAB_PAYOUT_LOCKING } from "./payout.ts";
import { createLabWallet, p2pkhLockingOf, privateKeyOf, type LabWallet } from "./wallet.ts";
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
import {
  DUST_SATS,
  successorFeeCoinSats,
  successorFeeSats,
  STANDARD_HOP_TARGET_BYTES,
  type TxEnvelope,
} from "./envelope.ts";
import { cargoInputs, packCargoUnlockings, proofCargoLock, type CargoUtxo } from "./proof-cargo.ts";
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
import { compileFoldLockP2sh32, foldKernelCount, foldKernelUnlocking } from "./fold-kernel.ts";
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
  slotKernels?: number;
  envelope?: TxEnvelope;
}): MeasuredTx {
  const lockKind = args.lockKind ?? "p2sh32";
  const slotKernels =
    args.slotKernels ??
    (args.envelope === "consensus" ? SLOT_KERNEL_COUNT_CONSENSUS : SLOT_KERNEL_COUNT);
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const fee = 1_200n;
  const value = utxoValueFor(args.state);
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
        lockingBytecode: lockOf(lockKind, slotKernels),
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
 * Five-point successor: pool input 0 + FRI/fold/slot kernels.
 * Withdraws do **not** take a user P2PKH fee input (no relayer). Miner fee
 * comes from kernel-carrier sats. Deposits still need a funder for the net.
 */
export function compileCovenantSuccessor(args: {
  wallet?: LabWallet;
  feeUtxo?: { tx_hash: string; tx_pos: number; value: number };
  pool: {
    tx_hash: string;
    tx_pos: number;
    value: number | bigint;
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
  feeSats?: bigint;
  payoutLockingBytecode?: Uint8Array;
  extraPayouts?: Array<{ lockingBytecode: Uint8Array; sats: bigint }>;
  /** Last output (fee change). Default is a fresh P2PKH, not the funder. */
  changeLockingBytecode?: Uint8Array;
  /** Envelope C: spend the tape tip so a missing/wrong hop rejects the pay tx. */
  tapeUtxo?: { tx_hash: string; tx_pos: number; value: number };
  /** Pack leftover standard-envelope bytes with proof cargo (default 99 KB). 0 = skip. */
  packTo?: number;
  packHopIndex?: number;
  cargoUtxos?: CargoUtxo[];
}): MeasuredTx {
  const lockKind = args.lockKind ?? "p2sh32";
  const slotKernels =
    args.slotKernels ??
    (args.envelope === "consensus" ? SLOT_KERNEL_COUNT_CONSENSUS : SLOT_KERNEL_COUNT);
  const fee = args.feeSats ?? successorFeeSats(args.envelope ?? "standard");
  const value = utxoValueFor(args.newState);
  const poolIn = BigInt(args.pool.value);
  const net = value - poolIn;
  const depositNeed = net > 0n ? net : 0n;
  const userFee = Boolean(args.feeUtxo);
  const tape = Boolean(args.tapeUtxo);
  if (depositNeed > 0n && !args.feeUtxo) {
    throw new Error("deposit successor needs a funder utxo for the net");
  }
  if (userFee && !args.wallet) throw new Error("fee utxo needs a wallet to sign");
  if (tape && !args.wallet) throw new Error("tape utxo needs a wallet to sign");
  const signP2pkh = userFee || tape;
  const c = signP2pkh ? compiler() : undefined;
  const data = signP2pkh ? { keys: { privateKeys: { key: privateKeyOf(args.wallet!) } } } : undefined;
  const change =
    userFee && args.feeUtxo
      ? BigInt(args.feeUtxo.value) - fee - depositNeed
      : 0n;
  if (userFee && change < DUST_SATS) throw new Error("fee utxo too small for successor");
  const withdrawSats = net < 0n ? -net : 0n;
  const payoutLock = args.payoutLockingBytecode ?? LAB_PAYOUT_LOCKING;
  const extraPayouts = args.extraPayouts ?? [];
  if (extraPayouts.length > 0) {
    const paySum = extraPayouts.reduce((n, p) => n + p.sats, 0n);
    if (paySum !== withdrawSats) {
      throw new Error(`extraPayouts sum ${paySum} != pool net ${withdrawSats} (would steal or leak reserve)`);
    }
  }
  const wantPayout =
    Boolean(args.statement) &&
    args.statement!.publicAmountSats < 0n &&
    !isZero32(args.statement!.payoutLockingDigest);
  const payoutOutputs =
    extraPayouts.length > 0
      ? extraPayouts.map((p) => ({ lockingBytecode: p.lockingBytecode, valueSatoshis: p.sats }))
      : wantPayout
        ? [{ lockingBytecode: payoutLock, valueSatoshis: withdrawSats }]
        : [];
  const commitment = encodePublicPaa1(args.newState);
  const oldState = decodeState(args.pool.commitment);
  const decoded = decodeFriProof(args.proof);
  const packed = args.statement ? encodeAirPacked(args.statement, decoded) : decoded.layerRoots;
  const foldN = foldKernelCount(slotKernels);
  const unlocking =
    lockKind === "p2s"
      ? p2sUnlocking(undefined, packed)
      : p2sh32Unlocking(undefined, packed, { slotKernels });
  const shards = friShardUnlockings(args.proof, { allPairGroups: foldN > 1 });
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
    ...Array.from({ length: foldN }, (_, f) => ({ tx_hash: dummy, tx_pos: 11 + f, value: 1000 })),
    ...Array.from({ length: slotKernels }, (_, i) => ({ tx_hash: dummy, tx_pos: 11 + foldN + i, value: 1000 })),
  ];
  if (extras.length !== 1 + foldN + slotKernels) {
    throw new Error(`need ${1 + foldN + slotKernels} extra kernel UTXOs, got ${extras.length}`);
  }

  const packTo =
    args.packTo !== undefined
      ? args.packTo
      : args.envelope === "consensus"
        ? 0
        : STANDARD_HOP_TARGET_BYTES;
  const packHopIndex = args.packHopIndex ?? 0;
  const baseInputs = [
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
      ...Array.from({ length: foldN }, (_, f) => ({
        outpointIndex: extras[1 + f]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[1 + f]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: foldKernelUnlocking(1, f),
      })),
      ...Array.from({ length: slotKernels }, (_, i) => ({
        outpointIndex: extras[1 + foldN + i]!.tx_pos,
        outpointTransactionHash: hexToBin(extras[2 + i]!.tx_hash),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: slotsKernelUnlocking(i * SLOTS_PER_KERNEL),
      })),
      ...(userFee && args.feeUtxo && c && data
        ? [
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
          ]
        : []),
      ...(tape && args.tapeUtxo && c && data
        ? [
            {
              outpointIndex: args.tapeUtxo.tx_pos,
              outpointTransactionHash: hexToBin(args.tapeUtxo.tx_hash),
              sequenceNumber: 0xffffffff,
              unlockingBytecode: {
                compiler: c,
                script: "unlock",
                data,
                valueSatoshis: BigInt(args.tapeUtxo.value),
              },
            },
          ]
        : []),
  ];
  const outputs = [
      {
        lockingBytecode: lockOf(lockKind, slotKernels),
        valueSatoshis: value,
        token: {
          amount: 0n,
          category: args.pool.category,
          nft: { capability: "mutable" as const, commitment },
        },
      },
      ...payoutOutputs,
      ...(userFee
        ? [
            {
              lockingBytecode: args.changeLockingBytecode ?? p2pkhLockingOf(createLabWallet()),
              valueSatoshis: change,
            },
          ]
        : []),
  ];
  const bare = generateTransaction({ version: 2, locktime: 0, inputs: baseInputs, outputs });
  if (!bare.success) {
    throw new Error(`covenant successor: ${JSON.stringify(bare.errors).slice(0, 500)}`);
  }
  const baseBytes = encodeTransaction(bare.transaction).length;
  const cargo =
    packTo > 0
      ? packCargoUnlockings({
          baseBytes,
          proof: args.proof,
          hopIndex: packHopIndex,
          targetBytes: packTo,
        })
      : [];
  const generated = generateTransaction({
    version: 2,
    locktime: 0,
    inputs: [
      ...baseInputs,
      ...cargoInputs({ unlockings: cargo, utxos: args.cargoUtxos, hopIndex: packHopIndex }),
    ],
    outputs,
  });
  if (!generated.success) {
    throw new Error(`covenant successor packed: ${JSON.stringify(generated.errors).slice(0, 500)}`);
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
      value: utxoValueFor(state),
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

/** 10 FRI + bind-T + slot C=QZ carriers. Fat leftover is a fresh treasury, not the successor. */
export function compileFundVerifierKernels(
  wallet: LabWallet,
  utxo: { tx_hash: string; tx_pos: number; value: number },
  kernelSats = 1_000,
  slotKernels = SLOT_KERNEL_COUNT,
  feeCoinSats: bigint = successorFeeCoinSats("standard"),
  cargoCount = 0,
): {
  raw: Uint8Array;
  txid: string;
  fri: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  extra: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  cargo: Array<{ tx_hash: string; tx_pos: number; value: number }>;
  changeValue: number;
  changePos: number;
  treasuryValue?: number;
  treasuryPos?: number;
  treasuryAddress?: string;
} {
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(wallet) } } };
  const foldN = foldKernelCount(slotKernels);
  const extraCount = 1 + foldN + slotKernels;
  const count = FRI_KERNEL_INPUTS + extraCount;
  // 10 FRI + bind-T + N slots is ~50 B/out; 1000 sats was under 1 sat/byte at N=36 (code 66).
  const fee = 2_000n + BigInt(count) * 80n;
  const minerPad = feeCoinSats;
  const leftover =
    BigInt(utxo.value) -
    BigInt(kernelSats) * BigInt(count) -
    minerPad -
    fee -
    DUST_SATS * BigInt(cargoCount);
  if (leftover < DUST_SATS) throw new Error("utxo too small to fund verifier kernels");
  const treasuryWallet = createLabWallet();
  const fatFri = BigInt(kernelSats) + minerPad;
  const friLock = compileFriQueryLockP2sh32();
  const cargoLock = proofCargoLock();
  const tail = [
    ...Array.from({ length: cargoCount }, () => ({
      lockingBytecode: cargoLock,
      valueSatoshis: DUST_SATS,
    })),
    { lockingBytecode: p2pkhLockingOf(treasuryWallet), valueSatoshis: leftover },
  ];
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
      { lockingBytecode: friLock, valueSatoshis: fatFri },
      ...Array.from({ length: FRI_KERNEL_INPUTS - 1 }, () => ({
        lockingBytecode: friLock,
        valueSatoshis: BigInt(kernelSats),
      })),
      { lockingBytecode: compileCqzLockP2sh32(), valueSatoshis: BigInt(kernelSats) },
      ...Array.from({ length: foldN }, (_, f) => ({
        lockingBytecode: compileFoldLockP2sh32(1, f),
        valueSatoshis: BigInt(kernelSats),
      })),
      ...Array.from({ length: slotKernels }, (_, i) => ({
        lockingBytecode: compileSlotsLockP2sh32(i),
        valueSatoshis: BigInt(kernelSats),
      })),
      ...tail,
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
    fri: [
      { tx_hash: txid, tx_pos: 0, value: Number(fatFri) },
      ...Array.from({ length: FRI_KERNEL_INPUTS - 1 }, (_, i) => ({
        tx_hash: txid,
        tx_pos: i + 1,
        value: kernelSats,
      })),
    ],
    extra: Array.from({ length: extraCount }, (_, i) => ({
      tx_hash: txid,
      tx_pos: FRI_KERNEL_INPUTS + i,
      value: kernelSats,
    })),
    cargo: Array.from({ length: cargoCount }, (_, i) => ({
      tx_hash: txid,
      tx_pos: count + i,
      value: Number(DUST_SATS),
    })),
    changeValue: Number(leftover),
    changePos: count + cargoCount,
    treasuryValue: Number(leftover),
    treasuryPos: count + cargoCount,
    treasuryAddress: treasuryWallet.address,
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
      picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value, height: 0 };
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
