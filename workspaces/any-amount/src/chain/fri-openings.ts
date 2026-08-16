import { encodeLe, M31 } from "../backends/circle/m31.ts";
import { decodeFriProof, type FriProof } from "../backends/circle/fri.ts";
import { MerkleTree } from "../backends/circle/merkle.ts";
import { COMMITTED_LAYERS, FRI_N } from "../backends/circle/params.ts";
import { compileFriQueryKernel, FRI_KERNEL_INPUTS, FRI_LAYER_UNBOUND } from "./fri-kernel.ts";
import { encodeSteps, parentIndexOf } from "./vm-steps.ts";
import { AIR_PACKED_SIZE, AIR_OFF_ROOTS } from "./air-cqz.ts";

export { FRI_KERNEL_INPUTS };
export const UNLOCKING_LIMIT = 10_000;

function pushData(data: Uint8Array): Uint8Array {
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  if (data.length <= 0xffff) {
    return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
  }
  throw new Error("push too large");
}

function pushScriptNumber(n: number): Uint8Array {
  if (n === 0) return Uint8Array.of(0x00);
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n);
  if (n < 0 || n > 127) throw new Error(`script number ${n}`);
  return Uint8Array.of(1, n);
}
const SHARD_BUDGET = 9_000;

export type FriOpening = {
  left: Uint8Array;
  right: Uint8Array;
  parentPath: Uint8Array[];
  parentIndex: number;
  root: Uint8Array;
  layerIndex: number;
  /** Fiat–Shamir domain index for this query (same on all 7 layers). */
  queryIndex: number;
};

/** One PUSHDATA2 of the 1200-byte AIR packed blob (roots at offset 0). */
export function encodeLayerRootsPrefix(layerRoots: Uint8Array[]): Uint8Array {
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  const roots = layerRoots.slice(0, COMMITTED_LAYERS);
  while (roots.length < COMMITTED_LAYERS) roots.push(new Uint8Array(32));
  for (let i = 0; i < COMMITTED_LAYERS; i += 1) packed.set(roots[i]!, AIR_OFF_ROOTS + i * 32);
  return pushData(packed);
}

export function collectFriOpenings(proof: Uint8Array | FriProof): FriOpening[] {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const out: FriOpening[] = [];
  let boundQ = false;
  for (const q of p.queries) {
    for (let r = 0; r < q.layers.length; r += 1) {
      const layer = q.layers[r]!;
      const n = FRI_N >> r;
      const i = q.index % n;
      const lo = i < n / 2;
      let layerIndex = r;
      if (r === 0) {
        if (boundQ) layerIndex = FRI_LAYER_UNBOUND;
        else boundQ = true;
      }
      out.push({
        left: encodeLe(lo ? layer.value : layer.partner),
        right: encodeLe(lo ? layer.partner : layer.value),
        parentPath: layer.path,
        parentIndex: parentIndexOf(i, n),
        root: p.layerRoots[r]!,
        layerIndex,
        queryIndex: q.index,
      });
    }
  }
  return out;
}

function openingPushBytes(o: FriOpening): number {
  const steps = encodeSteps(o.parentIndex, o.parentPath);
  return pushData(o.left).length + pushData(o.right).length + pushData(steps).length + 1;
}

/** Split openings into exactly FRI_KERNEL_INPUTS shards, each under 10 KB unlocking. */
export function shardFriOpenings(openings: FriOpening[]): FriOpening[][] {
  if (openings.length === 0) throw new Error("no FRI openings");
  const n = FRI_KERNEL_INPUTS;
  const shards: FriOpening[][] = Array.from({ length: n }, () => []);
  const grouped = openings.length >= COMMITTED_LAYERS && openings.length % COMMITTED_LAYERS === 0;
  if (grouped) {
    const nQ = openings.length / COMMITTED_LAYERS;
    for (let q = 0; q < nQ; q += 1) {
      shards[q % n]!.push(...openings.slice(q * COMMITTED_LAYERS, (q + 1) * COMMITTED_LAYERS));
    }
  } else {
    for (let i = 0; i < openings.length; i += 1) shards[i % n]!.push(openings[i]!);
  }
  for (let s = 0; s < n; s += 1) {
    if (shards[s]!.length === 0) shards[s] = [openings[openings.length - 1]!];
    const packed = shardUnlockingBytes(shards[s]!);
    if (packed > UNLOCKING_LIMIT) {
      throw new Error(`FRI shard ${s} unlocking ${packed} > ${UNLOCKING_LIMIT}`);
    }
    let raw = 0;
    for (const o of shards[s]!) raw += openingPushBytes(o);
    if (raw > SHARD_BUDGET + 200) {
      throw new Error(`FRI shard ${s} payload ${raw} over budget`);
    }
  }
  return shards;
}

export function encodeFriBatchUnlocking(openings: FriOpening[]): Uint8Array {
  if (openings.length === 0) throw new Error("empty FRI shard");
  const parts: Uint8Array[] = [];
  for (const o of openings) {
    parts.push(
      pushData(o.left),
      pushData(o.right),
      pushData(encodeSteps(o.parentIndex, o.parentPath)),
      pushScriptNumber(o.layerIndex),
    );
  }
  parts.push(pushScriptNumber(openings.length));
  parts.push(pushData(compileFriQueryKernel()));
  const n = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function shardUnlockingBytes(openings: FriOpening[]): number {
  return encodeFriBatchUnlocking(openings).length;
}

export function friShardUnlockings(proof: Uint8Array | FriProof): Uint8Array[] {
  return shardFriOpenings(collectFriOpenings(proof)).map(encodeFriBatchUnlocking);
}

/**
 * 8-leaf dummy Q-tree openings. Merkle-valid against the dummy root, not this
 * statement's layerRoots. Used to prove kernels cannot spend a dummy tree
 * while the pool unlocking still carries the honest proof roots.
 */
export function dummyFriOpenings(count = FRI_KERNEL_INPUTS): FriOpening[] {
  const values = Array.from({ length: 8 }, (_, i) => BigInt(i + 1));
  const tree = new MerkleTree(values);
  const out: FriOpening[] = [];
  for (let k = 0; k < count; k += 1) {
    const i = (k % 4) * 2;
    out.push({
      left: encodeLe(values[i]!),
      right: encodeLe(values[i + 1]!),
      parentPath: tree.path(i).slice(1),
      parentIndex: Math.floor(i / 2),
      root: tree.root,
      layerIndex: k % COMMITTED_LAYERS,
      queryIndex: 0,
    });
  }
  return out;
}

export function dummyFriShardUnlockings(): Uint8Array[] {
  return shardFriOpenings(dummyFriOpenings()).map(encodeFriBatchUnlocking);
}

/** Same dummy 8-leaf tree, but every opening uses layerIndex 16+k so a skip-bind kernel would walk without a Q check. */
export function dummyFriOpeningsUnbound(count = FRI_KERNEL_INPUTS): FriOpening[] {
  return dummyFriOpenings(count).map((o) => ({
    ...o,
    layerIndex: FRI_LAYER_UNBOUND + (o.layerIndex % COMMITTED_LAYERS),
  }));
}

export function dummyFriShardUnlockingsUnbound(): Uint8Array[] {
  return shardFriOpenings(dummyFriOpeningsUnbound()).map(encodeFriBatchUnlocking);
}

/** Dummy 8-leaf openings that never use actual layer 0 (only 17–22). */
export function dummyFriOpeningsNoL0(count = FRI_KERNEL_INPUTS): FriOpening[] {
  return dummyFriOpenings(count).map((o, k) => ({
    ...o,
    layerIndex: FRI_LAYER_UNBOUND + 1 + (k % (COMMITTED_LAYERS - 1)),
  }));
}

export function dummyFriShardUnlockingsNoL0(): Uint8Array[] {
  return shardFriOpenings(dummyFriOpeningsNoL0()).map(encodeFriBatchUnlocking);
}

/** FRI_N-wide dummy tree (honest path depth) so isolated walk tests can pass the depth gate. */
export function dummyFriOpeningsWide(count = 1): FriOpening[] {
  const values = Array.from({ length: FRI_N }, (_, i) => BigInt((i % Number(M31 - 1n)) + 1));
  const tree = new MerkleTree(values);
  const out: FriOpening[] = [];
  for (let k = 0; k < count; k += 1) {
    const i = (k % (FRI_N / 2)) * 2;
    out.push({
      left: encodeLe(values[i]!),
      right: encodeLe(values[i + 1]!),
      parentPath: tree.path(i).slice(1),
      parentIndex: Math.floor(i / 2),
      root: tree.root,
      layerIndex: 0,
      queryIndex: 0,
    });
  }
  return out;
}

export function proofShardReport(proof: Uint8Array | FriProof): {
  openings: number;
  shards: number;
  unlockingMax: number;
  unlockingSum: number;
  shardsFit10k: boolean;
  txEst: number;
  txFit100k: boolean;
} {
  const shards = friShardUnlockings(proof);
  const unlockingMax = Math.max(...shards.map((s) => s.length));
  const unlockingSum = shards.reduce((n, s) => n + s.length, 0);
  const txEst = unlockingSum + 1_200 + shards.length * 150;
  return {
    openings: collectFriOpenings(proof).length,
    shards: shards.length,
    unlockingMax,
    unlockingSum,
    shardsFit10k: unlockingMax <= UNLOCKING_LIMIT,
    txEst,
    txFit100k: txEst <= 100_000,
  };
}
