import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { FRI_LOG_N } from "../backends/circle/params.ts";
import { AIR_OFF_QTABLE } from "./air-cqz.ts";

/** Fixed kernel-input count in the pool lock (must be known at genesis). */
export const FRI_KERNEL_INPUTS = 10;

/**
 * One paired-Merkle opening.
 * Stack: left right steps layerIndex
 * layerIndex 0..6 → layerRoots[i].
 * layerIndex 16..22 → layerRoots[i-16] (extra honest Q queries).
 * Actual layer 0 (0 or 16): opened felt must equal some packed qTable entry.
 * Steps length must be (FRI_LOG_N-1-layer)*33 so an 8-leaf dummy cannot walk.
 */
export const FRI_LAYER_UNBOUND = 16;

export const FRI_ONE_OPENING = `
OP_TOALTSTACK
OP_DUP
<${FRI_LAYER_UNBOUND}>
OP_GREATERTHANOREQUAL
OP_IF
  <${FRI_LAYER_UNBOUND}>
  OP_SUB
OP_ENDIF
OP_DUP
OP_0
OP_EQUAL
OP_TOALTSTACK
OP_DUP
<${FRI_LOG_N - 1}>
OP_SWAP
OP_SUB
<33>
OP_MUL
OP_2 OP_PICK
OP_SIZE
OP_NIP
OP_NUMEQUALVERIFY
OP_DUP
OP_TOALTSTACK
<32> OP_MUL
<0> OP_INPUTBYTECODE
<1> OP_SPLIT
OP_NIP
<2> OP_SPLIT
OP_NIP
OP_SWAP
OP_SPLIT
OP_NIP
<32> OP_SPLIT
OP_DROP
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DUP
OP_SHA256
OP_SWAP
OP_SHA256
OP_SWAP
OP_CAT
OP_SHA256
OP_FROMALTSTACK
OP_BEGIN
  OP_SIZE
  OP_0 OP_GREATERTHAN
  OP_IF
    <33> OP_SPLIT
    OP_TOALTSTACK
    <1> OP_SPLIT
    OP_ROT
    OP_SWAP
    OP_ROT
    OP_IF
      OP_SWAP
    OP_ENDIF
    OP_CAT
    OP_SHA256
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_FROMALTSTACK
OP_EQUALVERIFY
OP_FROMALTSTACK
OP_DROP
OP_FROMALTSTACK
OP_IF
  OP_FROMALTSTACK
  <4>
  OP_MUL
  <${AIR_OFF_QTABLE}>
  OP_ADD
  <0> OP_INPUTBYTECODE
  <1> OP_SPLIT OP_NIP
  <2> OP_SPLIT OP_NIP
  OP_SWAP
  OP_SPLIT OP_NIP
  <4> OP_SPLIT OP_DROP
  <0x00> OP_CAT
  OP_BIN2NUM
  OP_TOALTSTACK
  <0x00> OP_CAT
  OP_BIN2NUM
  OP_SWAP
  <0x00> OP_CAT
  OP_BIN2NUM
  OP_FROMALTSTACK
  OP_DUP
  OP_3 OP_PICK
  OP_NUMEQUAL
  OP_SWAP
  OP_2 OP_PICK
  OP_NUMEQUAL
  OP_BOOLOR
  OP_VERIFY
  OP_2DROP
  OP_1
OP_ELSE
  OP_FROMALTSTACK
  OP_DROP
  OP_2DROP
  OP_0
OP_ENDIF
`;

/**
 * Batch kernel: stack is (left right steps layerIndex)×N then N.
 * At least one opening must be actual layer 0 (index 0 or 16) so a spend
 * that only uses 17–22 cannot skip the Q bind.
 */
export const FRI_QUERY_KERNEL = `
OP_0
OP_SWAP
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_TOALTSTACK
    ${FRI_ONE_OPENING}
    OP_FROMALTSTACK
    OP_BOOLOR
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_VERIFY
    OP_DEPTH
    OP_IF
      OP_DROP
    OP_ENDIF
    OP_1
  OP_ENDIF
OP_UNTIL
OP_1
`;

export const FRI_MERKLE_ONLY_KERNEL = FRI_QUERY_KERNEL;

export function compileFriQueryKernel(): Uint8Array {
  const bin = cashAssemblyToBin(FRI_QUERY_KERNEL);
  if (typeof bin === "string") throw new Error(`fri kernel: ${bin}`);
  return bin;
}

export function compileFriQueryLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileFriQueryKernel()));
}

export function compileFriMerkleOnlyKernel(): Uint8Array {
  return compileFriQueryKernel();
}

export function compileFriMerkleOnlyLockP2sh32(): Uint8Array {
  return compileFriQueryLockP2sh32();
}
