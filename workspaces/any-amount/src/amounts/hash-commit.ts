/**
 * Production note-amount commit: tagged SHA-256.
 * Hides v given a uniform 32-byte blind. No discrete-log / EC assumption.
 * Pedersen (C = vG + rH) stays in pedersen.ts as a comparison plugin only.
 */
import { concatBytes, sha256, writeI64LE, ZERO32 } from "../pool/bytes.ts";

export const HASH_AMOUNT_TAG = new TextEncoder().encode("PAA1-HASH-AMT-v1");
export const HASH_NET_TAG = new TextEncoder().encode("PAA1-HASH-NET-v1");

/** SHA-256(tag || amount_i64le || blind32). */
export function commitAmount(value: bigint, blind: Uint8Array): Uint8Array {
  if (value < 0n) throw new Error("negative amount");
  if (blind.length !== 32) throw new Error("amount blind width");
  return sha256(concatBytes(HASH_AMOUNT_TAG, writeI64LE(value), blind));
}

/** Commit the public deposit/withdraw net so encodeStatement does not carry the raw i64. */
export function commitPublicNet(publicAmountSats: bigint, payoutLockingDigest: Uint8Array): Uint8Array {
  const payout = payoutLockingDigest.length === 32 ? payoutLockingDigest : ZERO32;
  return sha256(concatBytes(HASH_NET_TAG, writeI64LE(publicAmountSats), payout));
}
