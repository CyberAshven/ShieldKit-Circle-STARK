import { binToHex, cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { compileFriQueryLockP2sh32, FRI_KERNEL_INPUTS } from "./fri-kernel.ts";
import { encodeLayerRootsPrefix } from "./fri-openings.ts";
import { AIR_PACKED_SIZE, compileCqzLockP2sh32 } from "./air-cqz.ts";
import {
  EXTRACT_INSTANCE,
  EXTRACT_NF_ROOT,
  EXTRACT_NOTE_ROOT,
  EXTRACT_RESERVE_NUM,
  EXTRACT_SEQ_NUM,
  NOTE_MERKLE_WALK,
  SPENT_NOTE_PREIMAGE,
  ZERO32_ASM,
  encodeWalkSteps,
} from "./note-merkle.ts";
import { STATE_BASE_SATS } from "../pool/state.ts";

/**
 * Pool lock = covenant, not P2PKH.
 * P2S: locking bytecode is this program.
 * P2SH32: hash256(program) in the lock (ShieldKit P1 shell).
 *
 * OP_SIZE leaves the commitment on the stack — OP_DROP it or the successor
 * fails with "Extra items left on stack" (seen on Chipnet against 0adce2ca…).
 *
 * Output-0's 128-byte PAA1 is bound: instance id, noteRoot (equal or
 * incremental append), nullifierRoot (equal or SHA-256(old||nf)).
 * Unlocking: <layerRoot>×7 <walkLeaf> <walkSteps> <nf> <amount> <rho> <owner>
 * <amountCommit> <spentLeaf> <spentSteps> [<redeem>].
 * Kernels read those 7 roots from input-0 unlocking; they are not spender-pushed
 * on the kernel itself. The lock drops them after BIND so the stack is clean.
 */
export const FIVE_POINT_PAA1 = `
OP_0 OP_OUTPUTBYTECODE
OP_INPUTINDEX OP_UTXOBYTECODE
OP_EQUALVERIFY
OP_0 OP_OUTPUTTOKENCATEGORY
OP_INPUTINDEX OP_UTXOTOKENCATEGORY
OP_EQUALVERIFY
OP_0 OP_OUTPUTTOKENAMOUNT
OP_INPUTINDEX OP_UTXOTOKENAMOUNT
OP_NUMEQUALVERIFY
OP_0 OP_OUTPUTTOKENCOMMITMENT
OP_SIZE <128> OP_EQUALVERIFY
OP_DROP
OP_0 OP_OUTPUTTOKENCOMMITMENT
<4> OP_SPLIT OP_DROP
<0x50414131> OP_EQUALVERIFY
`;

function requireFriInputsAsm(): string {
  const lockHex = binToHex(compileFriQueryLockP2sh32());
  const cqzHex = binToHex(compileCqzLockP2sh32());
  const lines = [
    "OP_TXINPUTCOUNT",
    `<${2 + FRI_KERNEL_INPUTS}>`,
    "OP_GREATERTHANOREQUAL",
    "OP_VERIFY",
  ];
  for (let i = 1; i <= FRI_KERNEL_INPUTS; i += 1) {
    lines.push(`<${i}>`, "OP_UTXOBYTECODE", `<0x${lockHex}>`, "OP_EQUALVERIFY");
  }
  lines.push(`<${1 + FRI_KERNEL_INPUTS}>`, "OP_UTXOBYTECODE", `<0x${cqzHex}>`, "OP_EQUALVERIFY");
  return lines.join("\n");
}

/** Inputs 1..FRI_KERNEL_INPUTS must be the batch FRI kernel. Extra fee inputs may follow. */
export const REQUIRE_FRI_INPUTS = requireFriInputsAsm();

/** Bind new PAA1 fields to old cell + unlocking membership/nullifier preimage. */
export const BIND_PAA1 = `
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_TOALTSTACK
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
OP_SIZE <128> OP_EQUALVERIFY
OP_DROP
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_INSTANCE}
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_INSTANCE}
OP_EQUALVERIFY
OP_TOALTSTACK
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_NOTE_ROOT}
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_NOTE_ROOT}
OP_2DUP
OP_EQUAL
OP_IF
  OP_DROP
  OP_TOALTSTACK
  ${NOTE_MERKLE_WALK}
  OP_FROMALTSTACK
  OP_EQUALVERIFY
OP_ELSE
  OP_TOALTSTACK
  OP_TOALTSTACK
  OP_2DUP
  ${NOTE_MERKLE_WALK}
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_ROT
  OP_EQUALVERIFY
  OP_TOALTSTACK
  OP_NIP
  ${ZERO32_ASM}
  OP_SWAP
  ${NOTE_MERKLE_WALK}
  OP_FROMALTSTACK
  OP_EQUALVERIFY
OP_ENDIF
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_NF_ROOT}
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_NF_ROOT}
OP_2DUP
OP_EQUAL
OP_IF
  OP_2DROP
  ${ZERO32_ASM}
  OP_EQUALVERIFY
OP_ELSE
  OP_TOALTSTACK
  OP_SWAP
  OP_CAT
  OP_SHA256
  OP_FROMALTSTACK
  OP_EQUALVERIFY
OP_ENDIF
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_TOALTSTACK
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_SEQ_NUM}
<1> OP_ADD
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_SEQ_NUM}
OP_NUMEQUALVERIFY
OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
${EXTRACT_RESERVE_NUM}
OP_DUP
<${Number(STATE_BASE_SATS)}> OP_ADD
OP_INPUTINDEX OP_UTXOVALUE
OP_NUMEQUALVERIFY
OP_0 OP_OUTPUTTOKENCOMMITMENT
${EXTRACT_RESERVE_NUM}
OP_DUP
<${Number(STATE_BASE_SATS)}> OP_ADD
OP_0 OP_OUTPUTVALUE
OP_NUMEQUALVERIFY
OP_2DUP
OP_GREATERTHAN
OP_IF
  OP_SUB
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_VERIFY
  OP_FROMALTSTACK
  OP_NUMEQUALVERIFY
OP_ELSE
  OP_SWAP
  OP_SUB
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_VERIFY
  OP_FROMALTSTACK
  OP_NUMEQUALVERIFY
OP_ENDIF
OP_FROMALTSTACK
OP_DUP
${ZERO32_ASM}
OP_EQUAL
OP_IF
  OP_DROP
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_DROP
  OP_FROMALTSTACK OP_DROP
OP_ELSE
  OP_FROMALTSTACK
  OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_INSTANCE}
  OP_SWAP
  OP_FROMALTSTACK
  OP_SWAP
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT
  ${EXTRACT_NOTE_ROOT}
  ${SPENT_NOTE_PREIMAGE}
OP_ENDIF
OP_1
`;

/** Packed AIR blob sits under the witness; drop it after BIND so only OP_1 remains. */
export const DROP_LAYER_ROOTS = `
OP_TOALTSTACK
OP_DROP
OP_FROMALTSTACK
`;

export function compilePoolCovenant(): Uint8Array {
  const bin = cashAssemblyToBin(
    `${FIVE_POINT_PAA1}\n${REQUIRE_FRI_INPUTS}\n${BIND_PAA1}\n${DROP_LAYER_ROOTS}`,
  );
  if (typeof bin === "string") throw new Error(`covenant compile: ${bin}`);
  return bin;
}

export function poolLockP2s(): Uint8Array {
  return compilePoolCovenant();
}

export function poolLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compilePoolCovenant()));
}

/** Bitcoin script push of `data` (redeem / unlocking payload). */
export function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  if (data.length <= 0xffff) {
    return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
  }
  throw new Error("push too large");
}

export type PoolUnlockWitness = {
  walkLeaf: Uint8Array;
  walkPath: Uint8Array[];
  walkIndex: number;
  nullifier: Uint8Array;
  amountSats: bigint;
  rho: Uint8Array;
  owner: Uint8Array;
  amountCommit: Uint8Array;
  spentLeaf: Uint8Array;
  spentPath: Uint8Array[];
  spentIndex: number;
};

function pushScriptNumber(n: bigint): Uint8Array {
  if (n === 0n) return Uint8Array.of(0x00);
  if (n >= 1n && n <= 16n) return Uint8Array.of(0x50 + Number(n));
  if (n < 0n || n > 0x7fffffffn) throw new Error(`script number ${n}`);
  const bytes: number[] = [];
  let v = n;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  return pushData(Uint8Array.from(bytes));
}

export function poolWitnessPushes(w: PoolUnlockWitness): Uint8Array {
  const steps = encodeWalkSteps(w.walkIndex, w.walkPath);
  const spentSteps = encodeWalkSteps(w.spentIndex, w.spentPath);
  const parts = [
    pushData(w.walkLeaf),
    pushData(steps),
    pushData(w.nullifier),
    pushScriptNumber(w.amountSats),
    pushData(w.rho),
    pushData(w.owner),
    pushData(w.amountCommit),
    pushData(w.spentLeaf),
    pushData(spentSteps),
  ];
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function p2sh32Unlocking(w?: PoolUnlockWitness, layerRoots?: Uint8Array[] | Uint8Array): Uint8Array {
  const redeem = pushData(compilePoolCovenant());
  const prefix =
    layerRoots instanceof Uint8Array && layerRoots.length === AIR_PACKED_SIZE
      ? pushData(layerRoots)
      : encodeLayerRootsPrefix(Array.isArray(layerRoots) ? layerRoots : []);
  if (!w) {
    const out = new Uint8Array(prefix.length + redeem.length);
    out.set(prefix, 0);
    out.set(redeem, prefix.length);
    return out;
  }
  const wit = poolWitnessPushes(w);
  const out = new Uint8Array(prefix.length + wit.length + redeem.length);
  out.set(prefix, 0);
  out.set(wit, prefix.length);
  out.set(redeem, prefix.length + wit.length);
  return out;
}

export function p2sUnlocking(w?: PoolUnlockWitness, layerRoots?: Uint8Array[] | Uint8Array): Uint8Array {
  const prefix =
    layerRoots instanceof Uint8Array && layerRoots.length === AIR_PACKED_SIZE
      ? pushData(layerRoots)
      : encodeLayerRootsPrefix(Array.isArray(layerRoots) ? layerRoots : []);
  if (!w) return prefix;
  const wit = poolWitnessPushes(w);
  const out = new Uint8Array(prefix.length + wit.length);
  out.set(prefix, 0);
  out.set(wit, prefix.length);
  return out;
}

export function walkWitnessFromAuth(
  auth: {
    leaf: Uint8Array;
    index: number;
    path: Uint8Array[];
    nullifier: Uint8Array;
    createdLeaf: Uint8Array;
    createdIndex: number;
    createdPath: Uint8Array[];
    amountSats: bigint;
    publicDeltaSats: bigint;
    amountCommit: Uint8Array;
    rho: Uint8Array;
    owner: Uint8Array;
  },
  oldNoteRoot: Uint8Array,
  newNoteRoot: Uint8Array,
): PoolUnlockWitness {
  const same =
    oldNoteRoot.length === newNoteRoot.length && oldNoteRoot.every((b, i) => b === newNoteRoot[i]);
  const amountSats = auth.publicDeltaSats;
  return {
    walkLeaf: same ? auth.leaf : auth.createdLeaf,
    walkPath: same ? auth.path : auth.createdPath,
    walkIndex: same ? auth.index : auth.createdIndex,
    nullifier: auth.nullifier,
    amountSats,
    rho: auth.rho,
    owner: auth.owner,
    amountCommit: auth.amountCommit,
    spentLeaf: auth.leaf,
    spentPath: auth.path,
    spentIndex: auth.index,
  };
}
