/**
 * Tape tip lock chain for envelope C. Kept in its own module so both
 * `chained.ts` and `covenant-spend.ts` can use it without a cycle.
 */
import {
  binToHex,
  cashAssemblyToBin,
  encodeLockingBytecodeP2sh32,
  hash256,
} from "@bitauth/libauth";

/**
 * Tape tip lock chain — binds every hop to one digest.
 *
 * Without this the tape is held together only by the wallet's signature: hops
 * chain via plain P2PKH, `tapeCommit` is written to an OP_RETURN no script reads,
 * and BCH cannot introspect an ancestor. See C-BINDING.md.
 *
 * The locks form a counted chain so the digest cannot be swapped and hops cannot
 * be skipped:
 *
 *   L(d, i) for i < N  requires output 1 to be exactly L(d, i+1)
 *   L(d, N)            terminal - the pay hop spends this one
 *
 * A single self-propagating lock would not do: every tip would be identical, so
 * the pay hop could spend the funder's initial tip and skip the whole tape. It
 * also cannot recognise the pay hop by checking for the pool lock, because the
 * pool covenant asserts the tip lock - that is circular. Counting breaks both.
 *
 * Built from the end: index N first, then downwards.
 */
export function tapeTipRedeemChain(digest: Uint8Array, tapeN: number): Uint8Array[] {
  const redeems: Uint8Array[] = new Array(tapeN + 1);
  const compile = (asm: string): Uint8Array => {
    const bin = cashAssemblyToBin(asm);
    if (typeof bin === "string") throw new Error(`tape tip redeem: ${bin}`);
    return bin;
  };
  // Terminal. The digest is inside the redeem, so it is inside the P2SH32 hash.
  redeems[tapeN] = compile(`<0x${binToHex(digest)}> OP_DROP OP_1`);
  for (let i = tapeN - 1; i >= 0; i -= 1) {
    const next = binToHex(encodeLockingBytecodeP2sh32(hash256(redeems[i + 1]!)));
    redeems[i] = compile(
      `<0x${binToHex(digest)}> OP_DROP <1> OP_OUTPUTBYTECODE <0x${next}> OP_EQUALVERIFY OP_1`,
    );
  }
  return redeems;
}

export function tapeTipLockChain(digest: Uint8Array, tapeN: number): Uint8Array[] {
  return tapeTipRedeemChain(digest, tapeN).map((r) => encodeLockingBytecodeP2sh32(hash256(r)));
}

/** P2SH32 spend of a tape tip: just the redeem push. */
export function tapeTipUnlocking(redeem: Uint8Array): Uint8Array {
  return pushDataLocal(redeem);
}

function pushDataLocal(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}
