/**
 * Dedicated miner booleanity kernel (consensus B, after the six folds).
 * Reconstructs occupancy-query T from two unlocking shards and EQUALVERIFYs
 * Σ α^c T_c(T_c−1) against packed nTable (booleanity C mixed into occupancy).
 * Unlocking is LDE openings — not rho/owner/amount8.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { circleDomain } from "../backends/circle/fri.ts";
import { defaultInternalHash, type InternalHash } from "../backends/circle/internal-hash.ts";
import { FRI_QUERIES, TRACE_LEN, FRI_N } from "../backends/circle/params.ts";
import type { Note } from "../pool/notes.ts";
import type { PoolStatement } from "../pool/statement.ts";
import {
  AIR_OFF_HASHBIT,
  AIR_OFF_IDX,
  AIR_OFF_NTABLE,
  AIR_PACKED_SIZE,
  SLOT_KERNEL_COUNT,
} from "./air-cqz.ts";
import { FIRST_PUSH_BODY } from "./fri-kernel.ts";
import { M31_ADD, M31_MUL, M31_P, M31_SUB } from "./m31-asm.ts";
import {
  BOOL_KERNEL_COUNT,
  BOOL_QUERIES,
  BOOL_SHARD_BYTES,
  BOOL_SHARD_QUERIES,
  SHA_BIT_GROUP_COLS,
  encodeOccupancyBoolShards,
  shaBitLdeLeaves,
} from "./sha-bit-air.ts";

export { BOOL_KERNEL_COUNT, BOOL_SHARD_QUERIES };

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function defineFn(asm: string, index: number, name: string): string {
  const body = cashAssemblyToBin(asm);
  if (typeof body === "string") throw new Error(`${name}: ${body}`);
  return `${hexPush(body)}\n<${index}>\nOP_DEFINE`;
}

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  if (data.length <= 0xffff) {
    return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
  }
  throw new Error("push too large");
}

function pushRedeem(data: Uint8Array): Uint8Array {
  return pushData(data);
}

/**
 * acc pow alpha blob → acc' pow' alpha blob'
 * C = bit(bit−1); acc' = acc + pow·C; pow' = pow·alpha.
 */
const BOOL_COL_ASM = `
<4> OP_SPLIT
OP_SWAP
OP_BIN2NUM
OP_DUP
OP_1SUB
OP_MUL
<${M31_P}> OP_MOD
OP_3 OP_PICK
${M31_MUL}
OP_4 OP_PICK
${M31_ADD}
OP_3 OP_PICK
OP_3 OP_PICK
${M31_MUL}
OP_5 OP_ROLL
OP_DROP
OP_4 OP_ROLL
OP_DROP
OP_2SWAP
`;

function oneQueryAsm(q: number, localQ: number): string {
  const tOff = localQ === 0 ? "" : `<${localQ * SHA_BIT_GROUP_COLS * 4}> OP_SPLIT OP_NIP\n`;
  const nOff = q === 0 ? "" : `<${q * 4}> OP_SPLIT OP_NIP\n`;
  return `
OP_OVER
${tOff}<${SHA_BIT_GROUP_COLS * 4}> OP_SPLIT OP_DROP
<0>
<1>
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
OP_3 OP_ROLL
${Array.from({ length: SHA_BIT_GROUP_COLS }, () => "<1> OP_INVOKE").join("\n")}
OP_DROP
OP_NIP
OP_DROP
OP_OVER
${nOff}<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_NUMEQUALVERIFY
`;
}

/**
 * Consensus B: two check kernels after the six folds (inputs 18 and 19).
 * Each spends its own 18-query T shard so density stays under 800×unlocking.
 */
export const BOOL_CHECK_INPUT = 18;
export const BOOL_DATA_INPUT = 19;

export function booleanityKernelAsm(queryOffset = 0): string {
  return `
${defineFn(BOOL_COL_ASM, 1, "boolcol")}
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
<${AIR_PACKED_SIZE}>
OP_SPLIT
OP_DROP
OP_DUP
<${AIR_OFF_HASHBIT}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
<3> OP_SPLIT
<0x7f> OP_AND
OP_CAT
OP_BIN2NUM
<${M31_P}> OP_MOD
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_NTABLE}> OP_SPLIT OP_NIP
<${FRI_QUERIES * 4}> OP_SPLIT OP_DROP
OP_NIP
${Array.from({ length: BOOL_SHARD_QUERIES }, (_, local) => oneQueryAsm(queryOffset + local, local)).join("\n")}
OP_2DROP
OP_FROMALTSTACK
OP_DROP
OP_1
`;
}

export const BOOLEANITY_KERNEL_ASM = booleanityKernelAsm(0);
export const BOOLEANITY_DATA_KERNEL_ASM = booleanityKernelAsm(BOOL_SHARD_QUERIES);

export function booleanityKernelCount(slotKernels: number, enabled?: boolean): number {
  const on = enabled ?? slotKernels > SLOT_KERNEL_COUNT;
  return on && slotKernels > SLOT_KERNEL_COUNT ? BOOL_KERNEL_COUNT : 0;
}

function compileOrThrow(asm: string, name: string): Uint8Array {
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`${name}: ${bin}`);
  return bin;
}

export function compileBooleanityKernel(queryOffset = 0): Uint8Array {
  return compileOrThrow(booleanityKernelAsm(queryOffset), `booleanity-kernel-${queryOffset}`);
}

export function compileBooleanityDataKernel(): Uint8Array {
  return compileBooleanityKernel(BOOL_SHARD_QUERIES);
}

export function compileBooleanityLockP2sh32(queryOffset = 0): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileBooleanityKernel(queryOffset)));
}

export function compileBooleanityDataLockP2sh32(): Uint8Array {
  return compileBooleanityLockP2sh32(BOOL_SHARD_QUERIES);
}

export function compileBooleanityLocks(): Uint8Array[] {
  return Array.from({ length: BOOL_KERNEL_COUNT }, (_, s) =>
    compileBooleanityLockP2sh32(s * BOOL_SHARD_QUERIES),
  );
}

export function booleanityCheckUnlocking(shard: Uint8Array): Uint8Array {
  if (shard.length !== BOOL_SHARD_BYTES) throw new Error("bool check shard");
  const redeem = pushRedeem(compileBooleanityKernel());
  const push = pushData(shard);
  const out = new Uint8Array(push.length + redeem.length);
  out.set(push, 0);
  out.set(redeem, push.length);
  return out;
}

export function booleanityDataUnlocking(shard: Uint8Array): Uint8Array {
  if (shard.length !== BOOL_SHARD_BYTES) throw new Error("bool data shard");
  const redeem = pushRedeem(compileBooleanityDataKernel());
  const push = pushData(shard);
  const out = new Uint8Array(push.length + redeem.length);
  out.set(push, 0);
  out.set(redeem, push.length);
  return out;
}

export function occupancyBoolShardsFromNote(args: {
  note: Note;
  statement: PoolStatement;
  packed: Uint8Array;
  hash?: InternalHash;
}): Uint8Array[] {
  const hash = args.hash ?? defaultInternalHash();
  const qIdx: number[] = [];
  for (let s = 0; s < FRI_QUERIES; s += 1) {
    const o = AIR_OFF_IDX + s * 2;
    qIdx.push((args.packed[o]! << 8) | args.packed[o + 1]!);
  }
  const hashWit = {
    amountSats: args.note.amountSats,
    rho: args.note.rho,
    owner: args.note.ownerSecret,
    poolInstanceId: args.statement.oldState.poolInstanceId,
    action: args.statement.action,
  };
  const small = circleDomain(TRACE_LEN);
  const big = circleDomain(FRI_N);
  const friCols = shaBitLdeLeaves(hashWit, small, big).columnsLde;
  return encodeOccupancyBoolShards(friCols, qIdx);
}

export function occupancyBoolUnlockings(
  args: {
    note: Note;
    statement: PoolStatement;
    packed: Uint8Array;
    hash?: InternalHash;
  },
  slice?: { start?: number; count?: number },
): Uint8Array[] {
  const shards = occupancyBoolShardsFromNote(args);
  const start = slice?.start ?? 0;
  const count = slice?.count ?? shards.length;
  return shards.slice(start, start + count).map((shard, i) => {
    const s = start + i;
    const redeem = pushRedeem(compileBooleanityKernel(s * BOOL_SHARD_QUERIES));
    const push = pushData(shard);
    const out = new Uint8Array(push.length + redeem.length);
    out.set(push, 0);
    out.set(redeem, push.length);
    return out;
  });
}
