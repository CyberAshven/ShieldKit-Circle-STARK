import { sha256, concatBytes, bytesToHex } from "../../pool/bytes.ts";
import { encodeLe, type M31El } from "./m31.ts";

export function merkleParent(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(left, right));
}

export function leafHash(value: M31El): Uint8Array {
  return sha256(encodeLe(value));
}

export class MerkleTree {
  readonly layers: Uint8Array[][];

  constructor(values: M31El[]) {
    if (values.length === 0 || (values.length & (values.length - 1)) !== 0) {
      throw new Error("merkle width must be a power of two");
    }
    const leaves = values.map(leafHash);
    this.layers = [leaves];
    let cur = leaves;
    while (cur.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < cur.length; i += 2) {
        next.push(merkleParent(cur[i]!, cur[i + 1]!));
      }
      this.layers.push(next);
      cur = next;
    }
  }

  get root(): Uint8Array {
    return this.layers[this.layers.length - 1]![0]!;
  }

  path(index: number): Uint8Array[] {
    const out: Uint8Array[] = [];
    let i = index;
    for (let d = 0; d < this.layers.length - 1; d += 1) {
      const layer = this.layers[d]!;
      out.push(layer[i ^ 1]!);
      i >>= 1;
    }
    return out;
  }

  static verify(value: M31El, index: number, path: Uint8Array[], root: Uint8Array): boolean {
    let acc = leafHash(value);
    let i = index;
    for (const sib of path) {
      acc = i % 2 === 0 ? merkleParent(acc, sib) : merkleParent(sib, acc);
      i >>= 1;
    }
    return bytesToHex(acc) === bytesToHex(root);
  }
}
