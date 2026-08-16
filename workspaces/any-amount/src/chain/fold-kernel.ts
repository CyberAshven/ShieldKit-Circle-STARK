/**
 * Dedicated Circle-FRI fold kernel. First push of each grouped FRI unlocking
 * is (left||right)×7 for that shard's first query. Fold reads inputs 1..nFold.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { COMMITTED_LAYERS } from "../backends/circle/params.ts";
import { AIR_OFF_IDX, SLOT_KERNEL_COUNT } from "./air-cqz.ts";
import { foldDefinesAsm, foldQueriesAsm } from "./fold-asm.ts";

export const FOLD_KERNEL_INPUTS = 1;
export const FOLD_KERNEL_INDEX = 12;
/** Measured: 2+ query folds exceed 2026 VM density in the successor kernel. */
export const FOLD_QUERY_COUNT_STANDARD = 1;

/** Stack in: raw unlocking. Stack out: first 56-byte query pair blob. */
function firstQueryPairsAsm(): string {
  return `
<1> OP_SPLIT
OP_DUP
<0x4c>
OP_NUMEQUAL
OP_IF
  OP_DROP
  <1> OP_SPLIT
  OP_SWAP
  OP_BIN2NUM
  OP_SPLIT
  OP_DROP
OP_ELSE
  OP_DUP
  <0x4d>
  OP_NUMEQUAL
  OP_IF
    OP_DROP
    <2> OP_SPLIT
    OP_SWAP
    OP_BIN2NUM
    OP_SPLIT
    OP_DROP
  OP_ELSE
    OP_SWAP
    OP_SPLIT
    OP_DROP
  OP_ENDIF
OP_ENDIF
<${COMMITTED_LAYERS * 8}>
OP_SPLIT
OP_DROP
`;
}

function extractQueryPairsAsm(inputIndex: number): string {
  return `
<${inputIndex}> OP_INPUTBYTECODE
${firstQueryPairsAsm()}
`;
}

export function foldKernelAsm(nFold = SLOT_KERNEL_COUNT): string {
  const pulls = Array.from({ length: nFold }, (_, q) => `${extractQueryPairsAsm(1 + q)}\nOP_CAT`).join("\n");
  return `
${foldDefinesAsm()}
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
OP_0
${pulls}
OP_OVER
<${AIR_OFF_IDX}> OP_SPLIT OP_NIP
<${nFold * 2}> OP_SPLIT OP_DROP
${foldQueriesAsm(nFold)}
OP_1
`;
}

export function compileInput1PairsLock(): Uint8Array {
  const bin = cashAssemblyToBin(`
<1> OP_INPUTBYTECODE
${firstQueryPairsAsm()}
OP_SIZE
<${COMMITTED_LAYERS * 8}>
OP_NUMEQUAL
OP_NIP
`);
  if (typeof bin === "string") throw new Error(`input1-pairs: ${bin}`);
  return bin;
}

export function compileFirstQueryPairsLock(): Uint8Array {
  const bin = cashAssemblyToBin(`
${firstQueryPairsAsm()}
OP_SIZE
<${COMMITTED_LAYERS * 8}>
OP_NUMEQUAL
OP_NIP
`);
  if (typeof bin === "string") throw new Error(`first-pairs: ${bin}`);
  return bin;
}

const FOLD_REDEEM_PAD = 0;

export function compileFoldKernel(nFold = SLOT_KERNEL_COUNT): Uint8Array {
  const bin = cashAssemblyToBin(foldKernelAsm(nFold));
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

export function compileFoldLockP2sh32(nFold = SLOT_KERNEL_COUNT): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileFoldKernel(nFold)));
}

function pushRedeem(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

export function foldKernelUnlocking(nFold = SLOT_KERNEL_COUNT): Uint8Array {
  return pushRedeem(compileFoldKernel(nFold));
}
