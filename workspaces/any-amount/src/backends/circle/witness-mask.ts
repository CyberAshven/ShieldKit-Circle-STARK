/**
 * One-time pad for the published note preimage (rho, owner, amounts).
 * viewingKey is 80 uniform bytes, never written into encodeFriProof.
 * Masked fields are statistically independent of the witness (OTP).
 */
import { concatBytes, readU64BE, writeU64BE } from "../../pool/bytes.ts";
import type { FriAuth } from "./air.ts";
import { defaultInternalHash, type InternalHash } from "./internal-hash.ts";

export const VIEWING_TAG = new TextEncoder().encode("PAA1-VIEW-v1");
export const FRI_OPEN_MASK_TAG = new TextEncoder().encode("fri-open-mask");
export const VIEWING_PAD_LEN = 80;

export function freshViewingKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(VIEWING_PAD_LEN));
}

export function viewingCommit(key: Uint8Array, hash: InternalHash = defaultInternalHash()): Uint8Array {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  return hash.digest(concatBytes(VIEWING_TAG, key));
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
 * Derived from the packed viewing-commit (not stored as a felt). Openings are
 * Q+c. Packed Newton T interpolates on-chain cells offset by c so T-eval is
 * not unmasked Q. On-chain lock recomputes c with OP_SHA256 of the same tags.
 */
export function openingMaskFelt(commit: Uint8Array, hash: InternalHash = defaultInternalHash()): bigint {
  if (commit.length !== 32) throw new Error("viewing commit width");
  const h = hash.digest(concatBytes(VIEWING_TAG, commit, FRI_OPEN_MASK_TAG));
  // 4-byte LE, high bit cleared so OP_BIN2NUM stays unsigned; then mod M31.
  const n =
    BigInt(h[0]!) |
    (BigInt(h[1]!) << 8n) |
    (BigInt(h[2]!) << 16n) |
    (BigInt(h[3]! & 0x7f) << 24n);
  return n % 2147483647n;
}
