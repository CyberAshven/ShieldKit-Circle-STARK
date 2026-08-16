/**
 * Dedicated Circle-FRI fold kernel. First push of each grouped FRI unlocking
 * is (left||right)×7×queriesInShard. Kernel q reads shard (q % 10) and slices
 * pair group floor(q/10). One query per redeem (density).
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { COMMITTED_LAYERS, FRI_QUERIES } from "../backends/circle/params.ts";
import { AIR_OFF_IDX, SLOT_KERNEL_COUNT } from "./air-cqz.ts";
import { FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import { foldDefinesAsm, foldQueriesAsm } from "./fold-asm.ts";

export const FOLD_KERNEL_INPUTS = 1;
export const FOLD_KERNEL_INDEX = 12;
/** Measured: 2+ query folds exceed 2026 VM density in the successor kernel. */
export const FOLD_QUERY_COUNT_STANDARD = 1;
/** Standard 100 KB path: one fold input (density + remaining bytes). */
export const FOLD_KERNEL_COUNT_STANDARD = 1;
/** Consensus 1 MB path: one 1-query fold kernel per FRI query. */
export const FOLD_KERNEL_COUNT_CONSENSUS = FRI_QUERIES;

export function foldKernelCount(slotKernels: number): number {
  return slotKernels > SLOT_KERNEL_COUNT ? FOLD_KERNEL_COUNT_CONSENSUS : FOLD_KERNEL_COUNT_STANDARD;
}

export function foldQueryShardInput(queryIndex: number): number {
  return 1 + (queryIndex % FRI_KERNEL_INPUTS);
}

export function foldQueryPairIndex(queryIndex: number): number {
  return Math.floor(queryIndex / FRI_KERNEL_INPUTS);
}

const PAIR_BYTES = COMMITTED_LAYERS * 8;

/** Stack in: raw unlocking. Stack out: 56-byte pair blob at pairIndex. */
function queryPairsAsm(pairIndex = 0): string {
  return `
<1> OP_SPLIT
OP_OVER
<0x4c>
OP_NUMEQUAL
OP_IF
  OP_NIP
  <1> OP_SPLIT
  OP_SWAP
  <0x00>
  OP_CAT
  OP_BIN2NUM
  OP_SPLIT
  OP_DROP
OP_ELSE
  OP_OVER
  <0x4d>
  OP_NUMEQUAL
  OP_IF
    OP_NIP
    <2> OP_SPLIT
    OP_SWAP
    <0x00>
    OP_CAT
    OP_BIN2NUM
    OP_SPLIT
    OP_DROP
  OP_ELSE
    OP_SWAP
    OP_BIN2NUM
    OP_SPLIT
    OP_DROP
  OP_ENDIF
OP_ENDIF
<${pairIndex * PAIR_BYTES}>
OP_SPLIT
OP_NIP
<${PAIR_BYTES}>
OP_SPLIT
OP_DROP
`;
}

function extractQueryPairsAsm(inputIndex: number, pairIndex = 0): string {
  return `
<${inputIndex}> OP_INPUTBYTECODE
${queryPairsAsm(pairIndex)}
`;
}

export function foldKernelAsm(nFold = 1, queryIndex = 0): string {
  const sourceInput = foldQueryShardInput(queryIndex);
  const pairIndex = foldQueryPairIndex(queryIndex);
  const pulls = Array.from({ length: nFold }, (_, q) => {
    const qi = queryIndex + q;
    return `${extractQueryPairsAsm(foldQueryShardInput(qi), foldQueryPairIndex(qi))}\nOP_CAT`;
  }).join("\n");
  return `
${foldDefinesAsm()}
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
OP_0
${pulls}
OP_OVER
<${AIR_OFF_IDX + queryIndex * 2}> OP_SPLIT OP_NIP
<${nFold * 2}> OP_SPLIT OP_DROP
${foldQueriesAsm(nFold)}
OP_1
`;
}

export function compileInput1PairsLock(): Uint8Array {
  const bin = cashAssemblyToBin(`
<1> OP_INPUTBYTECODE
${queryPairsAsm(0)}
OP_SIZE
<${PAIR_BYTES}>
OP_NUMEQUAL
OP_NIP
`);
  if (typeof bin === "string") throw new Error(`input1-pairs: ${bin}`);
  return bin;
}

export function compileFirstQueryPairsLock(): Uint8Array {
  const bin = cashAssemblyToBin(`
${queryPairsAsm(0)}
OP_SIZE
<${PAIR_BYTES}>
OP_NUMEQUAL
OP_NIP
`);
  if (typeof bin === "string") throw new Error(`first-pairs: ${bin}`);
  return bin;
}

const FOLD_REDEEM_PAD = 0;

export function compileFoldKernel(nFold = 1, queryIndex = 0): Uint8Array {
  const bin = cashAssemblyToBin(foldKernelAsm(nFold, queryIndex));
  if (typeof bin === "string") throw new Error(`fold-kernel: ${bin}`);
  if (bin.length >= FOLD_REDEEM_PAD) return bin;
  const pairs = Math.ceil((FOLD_REDEEM_PAD - bin.length) / 2);
  const pad = new Uint8Array(pairs * 2);
  for (let i = 0; i < pairs; i += 1) {
    pad[i * 2] = 0x00;
    pad[i * 2 + 1] = 0x75;
  }
  const out = new Uint8Array(pad.length + bin.length);
  out.set(pad, 0);
  out.set(bin, pad.length);
  return out;
}

export function compileFoldLockP2sh32(nFold = 1, queryIndex = 0): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileFoldKernel(nFold, queryIndex)));
}

function pushRedeem(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

export function foldKernelUnlocking(nFold = 1, queryIndex = 0): Uint8Array {
  return pushRedeem(compileFoldKernel(nFold, queryIndex));
}
