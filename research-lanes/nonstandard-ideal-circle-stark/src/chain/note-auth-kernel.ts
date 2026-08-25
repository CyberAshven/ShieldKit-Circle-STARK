/**
 * On-chain note Merkle + nullifier-root chain, bound to packed auth digest.
 * Unlocking carries leaf, nf, amountCommit, createdLeaf — not rho/owner/amount8.
 * Fold leftover stays pair-bind. AmountCommit bit-LDE compact-walks run here
 * (own density): leaf = A[0:4]‖L[0:4]‖N[0:4]‖T, T from the six fold shards.
 * Miner EQUALVERIFYs those walks against hashBitRoot, matching verifyFri.
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
} from "./air-cqz.ts";
import { COMPACT_PATH_STRIDE, FIRST_PUSH_BODY } from "./fri-kernel.ts";
import {
  encodeShaLdeBlob,
  SHA_LDE_COMPACT,
  SHA_LDE_PATH_DEPTH,
  SHA_LDE_PREFIX,
  SHA_LDE_VALUE_BYTES,
} from "./sha-lde.ts";
import {
  SHA_BIT_COMPACT,
  SHA_BIT_FELT_BYTES,
  SHA_BIT_FOLDS,
  SHA_BIT_PATH_DEPTH,
  SHA_BIT_QUERIES,
  SHA_BIT_SHARD_BYTES,
} from "./sha-bit-air.ts";
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

const SHA_LDE_VALUES_LEN = FRI_QUERIES * SHA_LDE_VALUE_BYTES;
const SHA_LDE_COMPACT_LEN = FRI_QUERIES * SHA_LDE_COMPACT;

/** IN: table compact value root. OUT: empty (EQUALVERIFY root). */
function merkleWalkFnAsm(depth: number): string {
  const step = `
<${COMPACT_PATH_STRIDE}> OP_SPLIT
OP_TOALTSTACK
<1> OP_SPLIT
OP_SWAP
<0x00> OP_CAT OP_BIN2NUM
OP_TOALTSTACK
<0x00> OP_CAT OP_BIN2NUM
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
${Array.from({ length: depth }, () => step).join("\n")}
OP_DROP
OP_SWAP
OP_DROP
OP_FROMALTSTACK
OP_EQUALVERIFY
`);
  if (typeof body === "string") throw new Error(`sha-walk: ${body}`);
  return `${hexPush(body)}\n<1>\nOP_DEFINE`;
}

function shaWalkFnAsm(): string {
  return merkleWalkFnAsm(SHA_LDE_PATH_DEPTH);
}

/** IN: path value root. Path is (bit‖sib32)×depth. */
function merkleWalkPathFnAsm(depth: number): string {
  const step = `
<1> OP_SPLIT
OP_SWAP
<0x00> OP_CAT OP_BIN2NUM
OP_TOALTSTACK
<32> OP_SPLIT
OP_SWAP
OP_ROT
OP_FROMALTSTACK
OP_NOTIF
  OP_SWAP
OP_ENDIF
OP_CAT
OP_SHA256
OP_SWAP
`;
  const body = cashAssemblyToBin(`
OP_TOALTSTACK
OP_SHA256
OP_SWAP
${Array.from({ length: depth }, () => step).join("\n")}
OP_DROP
OP_FROMALTSTACK
OP_EQUALVERIFY
`);
  if (typeof body === "string") throw new Error(`sha-bit-path-walk: ${body}`);
  return `${hexPush(body)}\n<1>\nOP_DEFINE`;
}

function shaBitWalkFnAsm(): string {
  return merkleWalkPathFnAsm(SHA_BIT_PATH_DEPTH);
}

const FOLD_SHA_INPUT0 = 12;

function foldShaShardAsm(inputIndex: number): string {
  return `
<${inputIndex}> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
OP_SIZE
<${SHA_BIT_SHARD_BYTES}>
OP_SUB
OP_SPLIT
OP_NIP
`;
}

/** Stack: values compact table. Alt: root. Walk consumes nothing of those three. */
function shaWalkOneAsm(k: number): string {
  const cOff = k === 0 ? "" : `<${k * SHA_LDE_COMPACT}> OP_SPLIT OP_NIP\n`;
  const vOff = k === 0 ? "" : `<${k * SHA_LDE_VALUE_BYTES}> OP_SPLIT OP_NIP\n`;
  return `
OP_DUP
OP_2 OP_PICK
${cOff}<${SHA_LDE_COMPACT}> OP_SPLIT OP_DROP
OP_4 OP_PICK
${vOff}<${SHA_LDE_VALUE_BYTES}> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<1> OP_INVOKE
`;
}

/**
 * Stack after parse: S C L N A Cr values compact table.
 * Push A[0:4]||L[0:4]||N[0:4] (matches JS shaPublicPrefix).
 */
function shaPrefixWantAsm(): string {
  return `
OP_4 OP_PICK
<4> OP_SPLIT OP_DROP
OP_7 OP_PICK
<4> OP_SPLIT OP_DROP
OP_CAT
OP_6 OP_PICK
<4> OP_SPLIT OP_DROP
OP_CAT
`;
}

/** Stack: S C L N A Cr. Push A[0:4]||L[0:4]||N[0:4]. */
function shaBitPrefixWantAsm(): string {
  return `
OP_1 OP_PICK
<4> OP_SPLIT OP_DROP
OP_4 OP_PICK
<4> OP_SPLIT OP_DROP
OP_CAT
OP_3 OP_PICK
<4> OP_SPLIT OP_DROP
OP_CAT
`;
}

/**
 * Stack: want paths s0..s5 (s5 top). Alt: root.
 * T is s0[k]‖…‖s5[k]. After T, extra=1: pick 8 is want, pick 7 is paths.
 * INVOKE is path leaf root.
 */
function shaBitWalkOneAsm(k: number): string {
  const sliceBytes = SHA_BIT_FELT_BYTES / SHA_BIT_FOLDS;
  const slice = (pick: number) => `
<${pick}> OP_PICK
${k === 0 ? "" : `<${k * sliceBytes}> OP_SPLIT OP_NIP\n`}
<${sliceBytes}> OP_SPLIT OP_DROP
`;
  const cOff = k === 0 ? "" : `<${k * SHA_BIT_COMPACT}> OP_SPLIT OP_NIP\n`;
  return `
${slice(5)}
${slice(5)}
OP_CAT
${slice(4)}
OP_CAT
${slice(3)}
OP_CAT
${slice(2)}
OP_CAT
${slice(1)}
OP_CAT
OP_8 OP_PICK
OP_SWAP
OP_CAT
OP_7 OP_PICK
${cOff}<${SHA_BIT_COMPACT}> OP_SPLIT OP_DROP
OP_SWAP
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<1> OP_INVOKE
`;
}

/** EQUALVERIFY opening k's 12-byte prefix against want (top). Values stay. */
function shaPrefixOneAsm(k: number): string {
  const vOff = k === 0 ? "" : `<${k * SHA_LDE_VALUE_BYTES}> OP_SPLIT OP_NIP\n`;
  return `
OP_3 OP_PICK
${vOff}<${SHA_LDE_PREFIX}> OP_SPLIT OP_DROP
OP_OVER
OP_EQUALVERIFY
`;
}

/**
 * 18-input successors: grind first push is SHA bit-AIR full merkle paths.
 * AmountCommit 96-col LDE openings live in the 6 fold unlockings. This kernel
 * concatenates T, prefixes A/L/N, and path-walks hashBitRoot.
 * Isolated 2-input note-auth skips this (TXINPUTCOUNT < 18).
 */
export const HASH_BIT_CHECK_ASM = `
${shaBitWalkFnAsm()}
OP_TXINPUTCOUNT
<18>
OP_GREATERTHANOREQUAL
OP_IF
${shaBitPrefixWantAsm()}
<9> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
<0> OP_INPUTBYTECODE
${FIRST_PUSH_BODY}
<${AIR_OFF_HASHBIT}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_SIZE <32> OP_NUMEQUALVERIFY
OP_TOALTSTACK
${Array.from({ length: SHA_BIT_FOLDS }, (_, f) => foldShaShardAsm(FOLD_SHA_INPUT0 + f)).join("\n")}
${Array.from({ length: SHA_BIT_QUERIES }, (_, k) => shaBitWalkOneAsm(k)).join("\n")}
OP_2DROP
OP_2DROP
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_DROP
OP_ENDIF
`;

/**
 * Unlocking (bottom→top): spentSteps createdSteps leaf nf amountCommit createdLeaf [shaBlob].
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
OP_2OVER
OP_2OVER
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
  poolInstanceId?: Uint8Array;
  action?: "DEPOSIT" | "WITHDRAW";
  opens?: NoteAuthOpens;
  shaLdeBlob?: Uint8Array;
}): Uint8Array {
  const spentSteps = encodeWalkSteps(args.spentIndex, args.spentPath);
  const createdSteps = encodeWalkSteps(args.createdIndex, args.createdPath);
  const action = args.action ?? (args.change || args.createdPath.length ? "WITHDRAW" : "DEPOSIT");
  const opens =
    args.opens ??
    noteAuthPublicOpens({
      note: args.note,
      change: args.change,
      action: action === "DEPOSIT" && !args.change ? "DEPOSIT" : action,
      poolInstanceId: args.poolInstanceId ?? new Uint8Array(32),
    });
  const payload = concatBytes(
    pushData(spentSteps),
    pushData(createdSteps),
    pushData(opens.leaf),
    pushData(opens.nf),
    pushData(opens.amountCommit),
    pushData(opens.createdLeaf),
    ...(args.shaLdeBlob && args.shaLdeBlob.length > 0 ? [pushData(args.shaLdeBlob)] : []),
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
  const shaLdeBlob = decoded.shaBit
    ? undefined
    : decoded.hashBitLde
      ? encodeShaLdeBlob(decoded.hashBitLde)
      : undefined;
  return noteAuthKernelUnlocking({
    note: args.note,
    change: args.change,
    spentIndex: deposit ? auth.createdIndex : auth.index,
    spentPath: deposit ? auth.createdPath : auth.path,
    createdIndex: auth.createdIndex,
    createdPath: auth.createdPath,
    poolInstanceId: args.statement.oldState.poolInstanceId,
    action: args.statement.action,
    shaLdeBlob,
  });
}
