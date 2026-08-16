import { concatBytes, sha256, ZERO32 } from "./bytes.ts";

export const MERKLE_DEPTH = 8;

export type Note = {
  amountSats: bigint;
  rho: Uint8Array;
  ownerSecret: Uint8Array;
};

export function commitNote(note: Note): Uint8Array {
  const amt = new Uint8Array(8);
  let n = note.amountSats;
  for (let i = 7; i >= 0; i -= 1) {
    amt[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return sha256(concatBytes(amt, note.rho, note.ownerSecret));
}

export function nullifierOf(note: Note, poolInstanceId: Uint8Array): Uint8Array {
  return sha256(concatBytes(poolInstanceId, note.ownerSecret, note.rho));
}

/** Change notes must not reuse rho — same rho ⇒ same nullifier ⇒ second spend dies. */
export function freshRho(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function pairHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(left, right));
}

export class IncrementalMerkle {
  readonly depth: number;
  leaves: Uint8Array[] = [];
  readonly zeros: Uint8Array[];

  constructor(depth = MERKLE_DEPTH) {
    this.depth = depth;
    this.zeros = [new Uint8Array(ZERO32)];
    for (let i = 0; i < depth; i += 1) {
      const z = this.zeros[i]!;
      this.zeros.push(pairHash(z, z));
    }
  }

  get root(): Uint8Array {
    if (this.leaves.length === 0) return this.zeros[this.depth]!;
    let layer = [...this.leaves];
    for (let d = 0; d < this.depth; d += 1) {
      const z = this.zeros[d]!;
      if (layer.length % 2 === 1) layer = [...layer, z];
      const next: Uint8Array[] = [];
      for (let i = 0; i < layer.length; i += 2) {
        next.push(pairHash(layer[i]!, layer[i + 1]!));
      }
      layer = next;
    }
    return layer[0]!;
  }

  append(leaf: Uint8Array): { index: number; path: Uint8Array[]; root: Uint8Array } {
    const index = this.leaves.length;
    if (index >= 2 ** this.depth) throw new Error("tree full");
    const path = this.authPath(index);
    this.leaves.push(leaf);
    return { index, path, root: this.root };
  }

  authPath(index: number): Uint8Array[] {
    const path: Uint8Array[] = [];
    let i = index;
    let layer = [...this.leaves];
    for (let d = 0; d < this.depth; d += 1) {
      const z = this.zeros[d]!;
      if (layer.length % 2 === 1) layer = [...layer, z];
      path.push(layer[i ^ 1] ?? z);
      const next: Uint8Array[] = [];
      for (let j = 0; j < Math.max(layer.length, 2); j += 2) {
        next.push(pairHash(layer[j] ?? z, layer[j + 1] ?? z));
      }
      layer = next;
      i >>= 1;
    }
    return path;
  }

  static verify(leaf: Uint8Array, index: number, path: Uint8Array[], root: Uint8Array): boolean {
    let acc = leaf;
    let i = index;
    for (const sib of path) {
      acc = i % 2 === 0 ? pairHash(acc, sib) : pairHash(sib, acc);
      i >>= 1;
    }
    return acc.length === root.length && acc.every((b, k) => b === root[k]);
  }
}

export class NullifierSet {
  items: Uint8Array[] = [];

  get root(): Uint8Array {
    let acc = new Uint8Array(ZERO32);
    for (const n of this.items) acc = sha256(concatBytes(acc, n));
    return acc;
  }

  add(nullifier: Uint8Array): Uint8Array {
    const key = Buffer.from(nullifier).toString("hex");
    if (this.items.some((x) => Buffer.from(x).toString("hex") === key)) {
      throw new Error("nullifier already used");
    }
    this.items.push(nullifier);
    return this.root;
  }
}
