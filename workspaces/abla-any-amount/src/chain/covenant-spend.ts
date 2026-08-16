import {
  binToHex,
  encodeTransaction,
  generateTransaction,
  hashTransaction,
  hexToBin,
  walletTemplateP2pkhNonHd,
  walletTemplateToCompilerBCH,
} from "@bitauth/libauth";
import { encodeState, STATE_BASE_SATS, type AnyAmountState } from "../pool/state.ts";
import { sha256 } from "../pool/bytes.ts";
import { createLabWallet, privateKeyOf, type LabWallet } from "./wallet.ts";
import { broadcast, connectChipnet, listUnspent } from "./electrum.ts";
import {
  compilePoolCovenant,
  opReturn,
  p2sUnlocking,
  p2sh32Unlocking,
  poolLockP2s,
  poolLockP2sh32,
} from "./covenant-p2s.ts";

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
};

const PROOF_SLOT_TAG = new TextEncoder().encode("PAA1PROF");

export function proofSlot(proof: Uint8Array): Uint8Array {
  return Uint8Array.of(...PROOF_SLOT_TAG, ...sha256(proof));
}

function compiler() {
  return walletTemplateToCompilerBCH(walletTemplateP2pkhNonHd);
}

function lockOf(kind: LockKind): Uint8Array {
  return kind === "p2s" ? poolLockP2s() : poolLockP2sh32();
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
    proofSlotBytes: proofSlot(proof).length,
    lockKind,
  };
}

/**
 * Genesis: P2PKH funds a P2S / P2SH32 five-point cell.
 * NFT commitment is the 128-byte PAA1 state (Layla). Proof lives in the
 * OP_RETURN slot as `PAA1PROF || SHA-256(proof)` — full FRI is off-chain.
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
  const value = STATE_BASE_SATS + args.state.reserveSats;
  const change = BigInt(args.utxo.value) - value - fee;
  if (change < 546n) throw new Error("utxo too small for covenant spend");

  const commitment = encodeState(args.state);
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
      { lockingBytecode: opReturn(proofSlot(args.proof)), valueSatoshis: 0n },
    ],
  });
  if (!generated.success) {
    throw new Error(`covenant spend: ${JSON.stringify(generated.errors).slice(0, 500)}`);
  }
  const raw = encodeTransaction(generated.transaction);
  return measureOf(raw, generated.transaction.inputs[0]!.unlockingBytecode.length, args.proof, lockKind);
}

/**
 * Five-point successor: spend the pool cell as input 0 (P2S empty unlock or
 * P2SH32 redeem push) plus a P2PKH fee input. Output 0 keeps lock, category,
 * token amount 0, and a new 128-byte PAA1.
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
  lockKind?: LockKind;
}): MeasuredTx {
  const lockKind = args.lockKind ?? "p2sh32";
  const c = compiler();
  const data = { keys: { privateKeys: { key: privateKeyOf(args.wallet) } } };
  const fee = 1_500n;
  const value = STATE_BASE_SATS + args.newState.reserveSats;
  const change = BigInt(args.feeUtxo.value) - fee;
  if (change < 546n) throw new Error("fee utxo too small for successor");
  const commitment = encodeState(args.newState);
  const unlocking = lockKind === "p2s" ? p2sUnlocking() : p2sh32Unlocking();

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
        lockingBytecode: lockOf(lockKind),
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
      { lockingBytecode: opReturn(proofSlot(args.proof)), valueSatoshis: 0n },
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
    feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 100_000 },
    pool: {
      tx_hash: genesisP2sh32.txid,
      tx_pos: 0,
      value: Number(STATE_BASE_SATS + state.reserveSats),
      category: hexToBin("11".repeat(32)),
      commitment: encodeState(state),
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

export async function broadcastCovenantGenesis(
  wallet: LabWallet,
  state: AnyAmountState,
  proof: Uint8Array,
  lockKind: LockKind = "p2sh32",
): Promise<MeasuredTx & { broadcast: string; prepTxid?: string }> {
  const client = await connectChipnet();
  try {
    const utxos = await listUnspent(client, wallet.address);
    if (utxos.length === 0) throw new Error("no Chipnet coins — fund the lab address");
    let picked = utxos.reduce((a, b) => (a.value >= b.value ? a : b));
    let prepTxid: string | undefined;
    if (picked.tx_pos !== 0) {
      const prep = compileSelfSendVout0(wallet, picked);
      prepTxid = await broadcast(client, binToHex(prep.raw));
      picked = { tx_hash: prep.txid, tx_pos: 0, value: prep.value };
    }
    const measured = compileCovenantSpend({
      wallet,
      utxo: picked,
      state,
      proof,
      lockKind,
    });
    const txid = await broadcast(client, binToHex(measured.raw));
    return { ...measured, broadcast: txid, prepTxid };
  } finally {
    client.close();
  }
}

export { compilePoolCovenant, STATE_BASE_SATS };
