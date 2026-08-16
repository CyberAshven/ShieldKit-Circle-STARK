/**
 * One-time pad for the published note preimage (rho, owner, amounts).
 * viewingKey is 80 uniform bytes, never written into encodeFriProof.
 * Masked fields are statistically independent of the witness (OTP).
 */
import { concatBytes, readU64BE, sha256, writeU64BE } from "../../pool/bytes.ts";
import type { FriAuth } from "./air.ts";

export const VIEWING_TAG = new TextEncoder().encode("PAA1-VIEW-v1");
export const VIEWING_PAD_LEN = 80;

export function freshViewingKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(VIEWING_PAD_LEN));
}

export function viewingCommit(key: Uint8Array): Uint8Array {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  return sha256(concatBytes(VIEWING_TAG, key));
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) out[i] = a[i]! ^ b[i]!;
  return out;
}

export function maskAuth(auth: FriAuth, key: Uint8Array): FriAuth {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  return {
    ...auth,
    rho: xorBytes(auth.rho, key.subarray(0, 32)),
    owner: xorBytes(auth.owner, key.subarray(32, 64)),
    amountSats: readU64BE(xorBytes(writeU64BE(auth.amountSats), key.subarray(64, 72)), 0),
    publicDeltaSats: readU64BE(xorBytes(writeU64BE(auth.publicDeltaSats), key.subarray(72, 80)), 0),
  };
}

export function unmaskAuth(auth: FriAuth, key: Uint8Array): FriAuth {
  return maskAuth(auth, key);
}

/**
 * Degree-0 mask felt for FRI openings / packed Q.
 * Derived from the public viewing-commit so verifyFri and encodeAirPacked
 * can recompute it without the viewing key. Openings are Q+c, not raw Q.
 * Anyone who recomputes Q from packed Newton T can recover c — say so in STATUS.
 */
export function openingMaskFelt(commit: Uint8Array): bigint {
  if (commit.length !== 32) throw new Error("viewing commit width");
  const h = sha256(concatBytes(VIEWING_TAG, commit, new TextEncoder().encode("fri-open-mask")));
  let n = 0n;
  for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(h[i]!);
  return n % 2147483647n;
}
