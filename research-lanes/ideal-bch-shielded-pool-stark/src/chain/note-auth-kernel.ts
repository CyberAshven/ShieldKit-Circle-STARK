/**
 * On-chain note Merkle + nullifier-root chain, bound to packed auth digest.
 * Unlocking carries leaf, nf, amountCommit, createdLeaf — not rho/owner/amount8.
 * Packed AIR_OFF_NET is SHA256(leaf‖nf‖amountCommit‖createdLeaf). Miner OP_SHA256 + EQUALVERIFY.
 * Preimage check stays in verifyFri. Dummy leftover-fill cargo is not this kernel.
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { concatBytes, ZERO32 } from "../pool/bytes.ts";
import { type Note } from "../pool/notes.ts";
import {
  extractCellAsm,
  extractRaw32Asm,
  HASH_CELL_COMMIT,
  SLOT_KERNEL_COUNT,
  AIR_OFF_NET,
  AIR_OFF_HASHBIT,
  AIR_PACKED_SIZE,
} from "./air-cqz.ts";
import { FIRST_PUSH_BODY, COMPACT_PATH_STRIDE } from "./fri-kernel.ts";
import {
  SHA_LDE_COMPACT,
  SHA_LDE_PATH_DEPTH,
  SHA_LDE_PREFIX,
  SHA_LDE_SHARD_BYTES,
  SHA_LDE_SHARD_COUNT,
  SHA_LDE_VALUE_BYTES,
} from "./sha-lde.ts";
import { FRI_QUERIES } from "../backends/circle/params.ts";

import { noteAuthPublicOpens, type NoteAuthOpens } from "./note-auth-bind.ts";
export { noteAuthBindHash, noteAuthPublicOpens, noteAuthBindFromStatement } from "./note-auth-bind.ts";
import {
  EXTRACT_NF_ROOT,
  EXTRACT_NOTE_ROOT,
  NOTE_MERKLE_WALK,
  encodeWalkSteps,
} from "./note-merkle.ts";
import { decodeFriProof } from "../backends/circle/fri.ts";
import type { PoolStatement } from "../pool/statement.ts";

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

const ZERO32_PUSH = hexPush(ZERO32);
/** Consensus 18-input skeleton: pool + 7 FRI + cqz + grind + algebraicC + note-auth + 6 fold. */
export const NOTE_AUTH_FOLD_INPUT0 = 12;

function foldPeelFnAsm(): string {
  const body = cashAssemblyToBin(`
${FIRST_PUSH_BODY}
<${SHA_LDE_SHARD_BYTES}>
OP_SPLIT
OP_DROP
`);
  if (typeof body === "string") throw new Error(`fold-peel: ${body}`);
  return `${hexPush(body)}\n<0>\nOP_DEFINE`;
}

function foldChunkAsm(inputIndex: number): string {
  return `
<${inputIndex}> OP_INPUTBYTECODE
<0> OP_INVOKE
`;
}

/** Compact merkle walk. Stack in: table compact value root. Isolated `_walk-sha` KAT. */
function shaWalkFnAsm(): string {
  const step = `
<${COMPACT_PATH_STRIDE}> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT
OP_SWAP
OP_BIN2NUM
OP_TOALTSTACK
OP_BIN2NUM
OP_2 OP_PICK
OP_SWAP
<32> OP_MUL
OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_SWAP
OP_FROMALTSTACK
OP_NOTIF
  OP_SWAP
OP_ENDIF
OP_CAT
OP_SHA256
OP_FROMALTSTACK
`;
  const body = cashAssemblyToBin(`
OP_TOALTSTACK
OP_SHA256
OP_SWAP
${Array.from({ length: SHA_LDE_PATH_DEPTH }, () => step).join("\n")}
OP_DROP
OP_NIP
OP_FROMALTSTACK
OP_EQUALVERIFY
`);
  if (typeof body === "string") throw new Error(`sha-walk: ${body}`);
  return `${hexPush(body)}\n<1>\nOP_DEFINE`;
}

const SHA_LDE_VALUES_LEN = FRI_QUERIES * SHA_LDE_VALUE_BYTES;
const SHA_LDE_COMPACT_LEN = FRI_QUERIES * SHA_LDE_COMPACT;

/**
 * Miner-run SHA-LDE: 36 occupancy-query openings, compact merkle vs hashBitRoot,
 * prefix vs unlocking A/L/N. TRACE w is not in unlocking.
 * Stack in/out: S C L N A Cr.
 */
export const HASH_BIT_CHECK_ASM = `
${foldPeelFnAsm()}
${shaWalkFnAsm()}
OP_TXINPUTCOUNT
<18>
OP_GREATERTHANOREQUAL
OP_IF
OP_TOALTSTACK
${foldChunkAsm(NOTE_AUTH_FOLD_INPUT0)}
${Array.from({ length: SHA_LDE_SHARD_COUNT - 1 }, (_, i) => `${foldChunkAsm(NOTE_AUTH_FOLD_INPUT0 + 1 + i)}\nOP_CAT`).join("\n")}
<2> OP_SPLIT
OP_NIP
<${SHA_LDE_VALUES_LEN}>
OP_SPLIT
<${SHA_LDE_COMPACT_LEN}>
OP_SPLIT
OP_2 OP_PICK
<${SHA_LDE_PREFIX}>
OP_SPLIT
OP_DROP
<4> OP_SPLIT
OP_SWAP
OP_5 OP_PICK
<4> OP_SPLIT
OP_DROP
OP_EQUALVERIFY
<4> OP_SPLIT
OP_SWAP
OP_7 OP_PICK
<4> OP_SPLIT
OP_DROP
OP_EQUALVERIFY
OP_5 OP_PICK
<4> OP_SPLIT
OP_DROP
OP_DUP
${ZERO32_PUSH}
<4> OP_SPLIT
OP_DROP
OP_EQUAL
OP_IF
  OP_2DROP
OP_ELSE
  OP_EQUALVERIFY
OP_ENDIF
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
<${AIR_PACKED_SIZE}>
OP_SPLIT
OP_DROP
<${AIR_OFF_HASHBIT}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_SIZE
<32>
OP_NUMEQUALVERIFY
OP_DUP
OP_0NOTEQUAL
OP_VERIFY
${Array.from({ length: FRI_QUERIES }, (_, k) => `
OP_1 OP_PICK
OP_3 OP_PICK
${k === 0 ? "" : `<${k * SHA_LDE_COMPACT}>\nOP_SPLIT\nOP_NIP\n`}<${SHA_LDE_COMPACT}> OP_SPLIT OP_DROP
OP_5 OP_PICK
${k === 0 ? "" : `<${k * SHA_LDE_VALUE_BYTES}>\nOP_SPLIT\nOP_NIP\n`}<${SHA_LDE_VALUE_BYTES}> OP_SPLIT OP_DROP
OP_3 OP_PICK
<1> OP_INVOKE
`).join("\n")}
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_ENDIF
`;

/**
 * Unlocking (bottom→top): spentSteps createdSteps leaf nf amountCommit createdLeaf.
 * Not amount8/rho/owner.
 *
 * Stack at start (top last): S C L N A Cr.
 * Packed input-0 prefix is PUSHDATA2 (1+2). Bind = packed[AIR_OFF_NET:][0:32].
 */
export const NOTE_AUTH_KERNEL_ASM = `
${HASH_BIT_CHECK_ASM}
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
OP_DUP
<${AIR_OFF_NET}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_TOALTSTACK
${extractCellAsm(3)}
OP_TOALTSTACK
OP_3 OP_PICK
OP_3 OP_PICK
OP_3 OP_PICK
OP_3 OP_PICK
OP_CAT
OP_CAT
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
OP_EQUALVERIFY
OP_TOALTSTACK
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
${extractRaw32Asm(HASH_CELL_COMMIT)}
OP_3 OP_PICK
OP_EQUALVERIFY
OP_DROP
OP_FROMALTSTACK
OP_DUP
<1>
OP_NUMEQUAL
OP_IF
  OP_DROP
  OP_3 OP_PICK
  OP_EQUALVERIFY
  OP_DROP
  ${ZERO32_PUSH}
  OP_EQUALVERIFY
  OP_ROT
  OP_DROP
  OP_OVER
  ${ZERO32_PUSH}
  OP_SWAP
  ${NOTE_MERKLE_WALK}
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NOTE_ROOT}
  OP_EQUALVERIFY
  OP_SWAP
  ${NOTE_MERKLE_WALK}
  <0> OP_OUTPUTTOKENCOMMITMENT
  ${EXTRACT_NOTE_ROOT}
  OP_EQUALVERIFY
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  <0> OP_OUTPUTTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  OP_EQUALVERIFY
OP_ELSE
  OP_DROP
  OP_SWAP
  OP_DROP
  OP_TOALTSTACK
  OP_ROT
  OP_TOALTSTACK
  OP_TOALTSTACK
  OP_SWAP
  ${NOTE_MERKLE_WALK}
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NOTE_ROOT}
  OP_EQUALVERIFY
  OP_FROMALTSTACK
  <0> OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  OP_SWAP
  OP_CAT
  OP_SHA256
  <0> OP_OUTPUTTOKENCOMMITMENT
  ${EXTRACT_NF_ROOT}
  OP_EQUALVERIFY
  OP_FROMALTSTACK
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_FROMALTSTACK
    OP_OVER
    ${ZERO32_PUSH}
    OP_SWAP
    ${NOTE_MERKLE_WALK}
    <0> OP_UTXOTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    OP_EQUALVERIFY
    OP_SWAP
    ${NOTE_MERKLE_WALK}
    <0> OP_OUTPUTTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    OP_EQUALVERIFY
  OP_ELSE
    OP_DROP
    OP_FROMALTSTACK
    OP_DROP
    <0> OP_UTXOTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    <0> OP_OUTPUTTOKENCOMMITMENT
    ${EXTRACT_NOTE_ROOT}
    OP_EQUALVERIFY
  OP_ENDIF
OP_ENDIF
OP_1
`;

export function compileNoteAuthKernel(): Uint8Array {
  const bin = cashAssemblyToBin(NOTE_AUTH_KERNEL_ASM);
  if (typeof bin === "string") throw new Error(`note-auth-kernel: ${bin}`);
  return bin;
}

export function compileNoteAuthLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileNoteAuthKernel()));
}

export function includeNoteAuth(slotKernels: number, force = false): boolean {
  return force || slotKernels > SLOT_KERNEL_COUNT;
}

export function prefixExtraKernelCount(slotKernels: number, includePool = true, forceNoteAuth = false): number {
  if (!includePool) return forceNoteAuth ? 2 : 1;
  return includeNoteAuth(slotKernels, forceNoteAuth) ? 4 : 3;
}

export function noteAuthKernelUnlocking(args: {
  note: Note;
  spentIndex: number;
  spentPath: Uint8Array[];
  createdIndex: number;
  createdPath: Uint8Array[];
  change?: Note;
  poolInstanceId: Uint8Array;
  action: "DEPOSIT" | "WITHDRAW";
  opens?: NoteAuthOpens;
}): Uint8Array {
  const spentSteps = encodeWalkSteps(args.spentIndex, args.spentPath);
  const createdSteps = encodeWalkSteps(args.createdIndex, args.createdPath);
  const opens =
    args.opens ??
    noteAuthPublicOpens({
      note: args.note,
      change: args.change,
      action: args.action,
      poolInstanceId: args.poolInstanceId,
    });
  const payload = concatBytes(
    pushData(spentSteps),
    pushData(createdSteps),
    pushData(opens.leaf),
    pushData(opens.nf),
    pushData(opens.amountCommit),
    pushData(opens.createdLeaf),
  );
  const redeem = pushData(compileNoteAuthKernel());
  return concatBytes(payload, redeem);
}

export function noteAuthUnlockingFromProof(args: {
  note: Note;
  change?: Note;
  proof: Uint8Array;
  statement: PoolStatement;
}): Uint8Array {
  const decoded = decodeFriProof(args.proof);
  const auth = decoded.auth;
  const deposit = args.statement.action === "DEPOSIT";
  return noteAuthKernelUnlocking({
    note: args.note,
    change: args.change,
    spentIndex: deposit ? auth.createdIndex : auth.index,
    spentPath: deposit ? auth.createdPath : auth.path,
    createdIndex: auth.createdIndex,
    createdPath: auth.createdPath,
    poolInstanceId: args.statement.oldState.poolInstanceId,
    action: args.statement.action,
  });
}

