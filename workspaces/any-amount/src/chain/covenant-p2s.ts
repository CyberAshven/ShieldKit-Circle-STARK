import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";

/**
 * Pool lock = covenant, not P2PKH.
 * P2S: locking bytecode is this program.
 * P2SH32: hash256(program) in the lock (ShieldKit P1 shell).
 *
 * OP_SIZE leaves the commitment on the stack — OP_DROP it or the successor
 * fails with "Extra items left on stack" (seen on Chipnet against 0adce2ca…).
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
<0x50414131> OP_EQUAL
`;

export function compilePoolCovenant(): Uint8Array {
  const bin = cashAssemblyToBin(FIVE_POINT_PAA1);
  if (typeof bin === "string") throw new Error(`covenant compile: ${bin}`);
  return bin;
}

export function poolLockP2s(): Uint8Array {
  return compilePoolCovenant();
}

export function poolLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compilePoolCovenant()));
}

/** Bitcoin script push of `data` (redeem / OP_RETURN payload). */
export function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  if (data.length <= 0xffff) {
    return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
  }
  throw new Error("push too large");
}

export function p2sh32Unlocking(): Uint8Array {
  return pushData(compilePoolCovenant());
}

export function p2sUnlocking(): Uint8Array {
  return new Uint8Array(0);
}

export function opReturn(payload: Uint8Array): Uint8Array {
  return Uint8Array.of(0x6a, ...pushData(payload));
}
