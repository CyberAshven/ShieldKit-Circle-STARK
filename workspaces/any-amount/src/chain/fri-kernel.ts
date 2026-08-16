import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";

/** Fixed kernel-input count in the pool lock (must be known at genesis). */
export const FRI_KERNEL_INPUTS = 10;

/**
 * One paired-Merkle opening.
 * Stack: left right steps layerIndex
 * Expected root is layerRoots[layerIndex] from input 0 unlocking
 * (this statement's proof), not a spender-pushed kernel root.
 */
export const FRI_ONE_OPENING = `
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
`;

/**
 * Batch kernel: stack is (left right steps layerIndex)×N then N.
 */
export const FRI_QUERY_KERNEL = `
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    ${FRI_ONE_OPENING}
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_1
`;

export function compileFriQueryKernel(): Uint8Array {
  const bin = cashAssemblyToBin(FRI_QUERY_KERNEL);
  if (typeof bin === "string") throw new Error(`fri kernel: ${bin}`);
  return bin;
}

export function compileFriQueryLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileFriQueryKernel()));
}
