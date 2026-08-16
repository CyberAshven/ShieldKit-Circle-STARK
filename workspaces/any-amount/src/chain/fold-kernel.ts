/**
 * Dedicated Circle-FRI fold kernel. Merkle kernels stay small; this input
 * re-reads their first 7 (left,right) pushes (query-grouped shard 0 = FS slot)
 * and runs foldPair through every committed layer.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { COMMITTED_LAYERS } from "../backends/circle/params.ts";
import { AIR_OFF_IDX, SLOT_KERNEL_COUNT } from "./air-cqz.ts";
import { foldDefinesAsm, foldQueriesAsm } from "./fold-asm.ts";

export const FOLD_KERNEL_INPUTS = 1;
/** Input index of the fold kernel (after 10 FRI + bind-T). */
export const FOLD_KERNEL_INDEX = 12;

function parseOneOpeningAsm(): string {
  return `
<1> OP_SPLIT OP_NIP
<4> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT OP_NIP
<4> OP_SPLIT
OP_FROMALTSTACK
OP_SWAP
OP_CAT
OP_TOALTSTACK
<1> OP_SPLIT
OP_DUP
<0x4d>
OP_NUMEQUAL
OP_IF
  OP_DROP
  <2> OP_SPLIT
  OP_SWAP
  OP_BIN2NUM
  OP_SPLIT OP_NIP
OP_ELSE
  OP_DUP
  <0x4c>
  OP_NUMEQUAL
  OP_IF
    OP_DROP
    <1> OP_SPLIT
    OP_SWAP
    OP_BIN2NUM
    OP_SPLIT OP_NIP
  OP_ELSE
    OP_SWAP
    OP_SPLIT OP_NIP
  OP_ENDIF
OP_ENDIF
<1> OP_SPLIT OP_NIP
OP_FROMALTSTACK
`;
}

function defineParseFn(): string {
  const body = cashAssemblyToBin(parseOneOpeningAsm());
  if (typeof body === "string") throw new Error(`parse-open: ${body}`);
  return `<0x${Buffer.from(body).toString("hex")}>\n<3>\nOP_DEFINE`;
}

function extractQueryPairsAsm(inputIndex: number): string {
  return `
<${inputIndex}> OP_INPUTBYTECODE
OP_0
<${COMMITTED_LAYERS}>
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_SWAP
    <3> OP_INVOKE
    OP_ROT
    OP_SWAP
    OP_CAT
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_NIP
`;
}

export function foldKernelAsm(nFold = SLOT_KERNEL_COUNT): string {
  const pulls = Array.from({ length: nFold }, (_, q) => `${extractQueryPairsAsm(1 + q)}\nOP_CAT`).join("\n");
  return `
${foldDefinesAsm()}
${defineParseFn()}
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
OP_0
${pulls}
OP_OVER
<${AIR_OFF_IDX}> OP_SPLIT OP_NIP
<${nFold * 2}> OP_SPLIT OP_DROP
${foldQueriesAsm()}
OP_1
`;
}

export function compileFoldKernel(nFold = SLOT_KERNEL_COUNT): Uint8Array {
  const bin = cashAssemblyToBin(foldKernelAsm(nFold));
  if (typeof bin === "string") throw new Error(`fold-kernel: ${bin}`);
  return bin;
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
