/**
 * AmountCommit SHA-256 bit-AIR (compression 0, 96 columns) fused into occupancy.
 * TRACE bits are 0/1; LDE interpolants are M31. Booleanity C = T(T−1) vanishes
 * on TRACE, Q = C/Z is the occupancy FRI target (public algebraicC is already 0).
 * 36 query openings of 16 columns sit in each of 6 fold unlockings (same queries,
 * not extra inputs). Note-auth concatenates them into 384-byte leaves and walks
 * hashBitRoot. Round-function next-row gates stay JS until cargo allows T(ωx).
 */
import { vanishingOnTrace } from "../backends/circle/air.ts";
import type { CirclePoint } from "../backends/circle/group.ts";
import { interpolateCircle, evalCirclePoly } from "../backends/circle/interpolate.ts";
import { MerkleTree } from "../backends/circle/merkle.ts";
import { add, encodeLe, inv, mul, sub, type M31El } from "../backends/circle/m31.ts";
import { TRACE_LEN } from "../backends/circle/params.ts";
import type { InternalHash } from "../backends/circle/internal-hash.ts";
import { concatBytes } from "../pool/bytes.ts";
import {
  BITS_PER_GROUP,
  buildHashBitTrace,
  noteAuthPublicsFromWitness,
  type NoteAuthWitness,
} from "./note-auth-air.ts";
import { shaPublicPrefix } from "./sha-lde.ts";

export const SHA_BIT_GROUP_COLS = BITS_PER_GROUP;
export const SHA_BIT_FOLDS = 6;
export const SHA_BIT_COLS_PER_FOLD = SHA_BIT_GROUP_COLS / SHA_BIT_FOLDS;
/** 32×3+20=116 bits, occupancy stays 36. 256-leaf LDE, depth 8. Paths are full siblings. */
export const SHA_BIT_QUERIES = 32;
export const SHA_BIT_N = TRACE_LEN * 4;
export const SHA_BIT_PREFIX = 12;
export const SHA_BIT_FELT_BYTES = SHA_BIT_GROUP_COLS * 4;
export const SHA_BIT_LEAF_BYTES = SHA_BIT_PREFIX + SHA_BIT_FELT_BYTES;
export const SHA_BIT_SHARD_BYTES = SHA_BIT_QUERIES * SHA_BIT_COLS_PER_FOLD * 4;
export const SHA_BIT_PATH_DEPTH = 8;
const PATH_STEP = 33;
export const SHA_BIT_COMPACT = SHA_BIT_PATH_DEPTH * PATH_STEP;
export const SHA_BIT_COMPACT_LEN = SHA_BIT_QUERIES * SHA_BIT_COMPACT;

function fullPath(parentIndex: number, parentPath: Uint8Array[]): Uint8Array {
  const n = parentPath.length;
  const out = new Uint8Array(n * PATH_STEP);
  let i = parentIndex;
  for (let s = 0; s < n; s += 1) {
    out[s * PATH_STEP] = i & 1;
    out.set(parentPath[s]!, s * PATH_STEP + 1);
    i >>= 1;
  }
  return out;
}

export function amountCommitColumns(w: NoteAuthWitness): M31El[][] {
  return buildHashBitTrace(w).columns.slice(0, SHA_BIT_GROUP_COLS);
}

export function columnLde(col: M31El[], small: CirclePoint[], big: CirclePoint[]): M31El[] {
  const interp = interpolateCircle(small, col);
  return big.map((p) => evalCirclePoly(interp, p));
}

export function encodeShaBitLeaf(prefix: Uint8Array, felts: M31El[]): Uint8Array {
  if (prefix.length !== SHA_BIT_PREFIX) throw new Error("sha-bit prefix");
  if (felts.length !== SHA_BIT_GROUP_COLS) throw new Error("sha-bit leaf");
  const out = new Uint8Array(SHA_BIT_LEAF_BYTES);
  out.set(prefix, 0);
  for (let i = 0; i < felts.length; i += 1) out.set(encodeLe(felts[i]!), SHA_BIT_PREFIX + i * 4);
  return out;
}

export function parseFeltBytes(bytes: Uint8Array): M31El[] {
  if (bytes.length !== SHA_BIT_FELT_BYTES) throw new Error("sha-bit felts");
  const out: M31El[] = [];
  for (let i = 0; i < SHA_BIT_GROUP_COLS; i += 1) {
    const o = i * 4;
    out.push(BigInt(bytes[o]!) | (BigInt(bytes[o + 1]!) << 8n) | (BigInt(bytes[o + 2]!) << 16n) | (BigInt(bytes[o + 3]!) << 24n));
  }
  return out;
}

export function decodeShaBitFelts(leaf: Uint8Array): M31El[] {
  if (leaf.length !== SHA_BIT_LEAF_BYTES) throw new Error("sha-bit leaf bytes");
  return parseFeltBytes(leaf.subarray(SHA_BIT_PREFIX));
}

export function shaBitLdeLeaves(w: NoteAuthWitness, small: CirclePoint[], big: CirclePoint[]): {
  columnsLde: M31El[][];
  leaves: Uint8Array[];
  prefix: Uint8Array;
} {
  const cols = amountCommitColumns(w);
  const columnsLde = cols.map((c) => columnLde(c, small, big));
  const prefix = shaPublicPrefix(noteAuthPublicsFromWitness(w));
  const leaves = Array.from({ length: big.length }, (_, i) =>
    encodeShaBitLeaf(prefix, columnsLde.map((c) => c[i]!)),
  );
  return { columnsLde, leaves, prefix };
}

export function booleanityBatchQLde(
  columnsLde: M31El[][],
  small: CirclePoint[],
  big: CirclePoint[],
  alpha: M31El,
): M31El[] {
  const zLde = vanishingOnTrace(big, small);
  const q = Array.from({ length: big.length }, () => 0n);
  let pow = 1n;
  for (let c = 0; c < columnsLde.length; c += 1) {
    const t = columnsLde[c]!;
    for (let i = 0; i < big.length; i += 1) {
      const bit = t[i]!;
      const constr = mul(bit, sub(bit, 1n));
      const z = zLde[i]!;
      const qi = z === 0n ? 0n : mul(constr, inv(z));
      q[i] = add(q[i]!, mul(pow, qi));
    }
    pow = mul(pow, alpha);
  }
  return q;
}

export function booleanityAlpha(hash: InternalHash, bitRoot: Uint8Array): M31El {
  const h = hash.digest(concatBytes(bitRoot, new TextEncoder().encode("sha-bool-α")));
  return (
    (BigInt(h[0]!) | (BigInt(h[1]!) << 8n) | (BigInt(h[2]!) << 16n) | (BigInt(h[3]! & 0x7f) << 24n)) % 2147483647n
  );
}

export function booleanityCAt(
  felts: M31El[],
  alpha: M31El,
): M31El {
  let acc = 0n;
  let pow = 1n;
  for (const bit of felts) {
    acc = add(acc, mul(pow, mul(bit, sub(bit, 1n))));
    pow = mul(pow, alpha);
  }
  return acc;
}

export type ShaBitProof = {
  root: Uint8Array;
  table: Uint8Array;
  compact: Uint8Array;
  shards: Uint8Array[];
  leaves: Uint8Array[];
};

export function openShaBit(
  leaves: Uint8Array[],
  queryIndex: number[],
  columnsLde: M31El[][],
  hash: InternalHash,
): ShaBitProof {
  if (leaves.length !== SHA_BIT_N) throw new Error("sha-bit leaves");
  if (queryIndex.length !== SHA_BIT_QUERIES) throw new Error("sha-bit queries");
  const tree = new MerkleTree(leaves, hash);
  const compact = concatBytes(
    ...queryIndex.map((index) => fullPath(index, tree.path(index))),
  );
  const shards = Array.from({ length: SHA_BIT_FOLDS }, (_, f) => {
    const out = new Uint8Array(SHA_BIT_SHARD_BYTES);
    for (let q = 0; q < SHA_BIT_QUERIES; q += 1) {
      const idx = queryIndex[q]!;
      for (let c = 0; c < SHA_BIT_COLS_PER_FOLD; c += 1) {
        const col = f * SHA_BIT_COLS_PER_FOLD + c;
        out.set(encodeLe(columnsLde[col]![idx]!), (q * SHA_BIT_COLS_PER_FOLD + c) * 4);
      }
    }
    return out;
  });
  return { root: tree.root, table: new Uint8Array(0), compact, shards, leaves };
}

export function walkShaBitLeaf(
  value: Uint8Array,
  compact: Uint8Array,
  table: Uint8Array,
  root: Uint8Array,
  hash: InternalHash,
): boolean {
  if (compact.length !== SHA_BIT_COMPACT) return false;
  let acc = hash.digest(value);
  for (let s = 0; s < SHA_BIT_PATH_DEPTH; s += 1) {
    const o = s * PATH_STEP;
    const bit = compact[o]!;
    const sib = compact.subarray(o + 1, o + PATH_STEP);
    acc = bit === 0 ? hash.digest(concatBytes(acc, sib)) : hash.digest(concatBytes(sib, acc));
  }
  return acc.length === 32 && root.length === 32 && acc.every((b, i) => b === root[i]);
}

export function reconstructFeltsFromShards(shards: Uint8Array[], query: number): Uint8Array {
  const felts = new Uint8Array(SHA_BIT_FELT_BYTES);
  for (let f = 0; f < SHA_BIT_FOLDS; f += 1) {
    const shard = shards[f]!;
    const o = query * SHA_BIT_COLS_PER_FOLD * 4;
    felts.set(shard.subarray(o, o + SHA_BIT_COLS_PER_FOLD * 4), f * SHA_BIT_COLS_PER_FOLD * 4);
  }
  return felts;
}

export function encodeShaBitBlob(proof: ShaBitProof): Uint8Array {
  return proof.compact;
}

export function decodeShaBitBlob(blob: Uint8Array): { compact: Uint8Array; table: Uint8Array } {
  const cLen = SHA_BIT_COMPACT_LEN;
  return { compact: blob.subarray(0, cLen), table: blob.subarray(cLen) };
}
