import { bytesToHex, concatBytes, readU16BE, sha256, writeU16BE } from "../../pool/bytes.ts";
import { encodeStatement, type PoolStatement } from "../../pool/statement.ts";
import { foldPair } from "./fold.ts";
import { addPoints, CIRCLE_GEN, scalarMul, type CirclePoint } from "./group.ts";
import { add, el, encodeLe, M31, type M31El } from "./m31.ts";
import { MerkleTree } from "./merkle.ts";

/** Bench Circle FRI. Hash-based = PQ. Not 128-bit sound (n=32, 8 queries). */
export const FRI_LOG_N = 5;
export const FRI_N = 32;
export const FRI_QUERIES = 8;
export const FRI_VERSION = 1;

export type FriQueryLayer = {
  value: M31El;
  partner: M31El;
  path: Uint8Array[];
  partnerPath: Uint8Array[];
};

export type FriQuery = {
  index: number;
  layers: FriQueryLayer[];
};

export type FriProof = {
  version: number;
  layerRoots: Uint8Array[];
  final: M31El[];
  queries: FriQuery[];
};

function subgroupGen(): CirclePoint {
  return scalarMul(CIRCLE_GEN, 2n ** 26n);
}

export function circleDomain(): CirclePoint[] {
  const g = subgroupGen();
  const out: CirclePoint[] = [];
  for (let i = 0; i < FRI_N; i += 1) out.push(scalarMul(g, BigInt(i)));
  return out;
}

function hashToM31(...parts: Uint8Array[]): M31El {
  const h = sha256(concatBytes(...parts));
  let n = 0n;
  for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(h[i]!);
  return n % M31;
}

/** Pair the two halves of the current layer (classical FRI even/odd). */
function partnerIndex(i: number, n: number): number {
  return (i + n / 2) % n;
}

/** Whole statement → 16 M31 coeffs via SHA-256(stmt || i). Membership, nullifier, reserve all bind. */
export function statementCoeffs(bytes: Uint8Array): M31El[] {
  const coeffs: M31El[] = [];
  for (let i = 0; i < 16; i += 1) {
    const h = sha256(concatBytes(bytes, Uint8Array.of(i)));
    let c = 0n;
    for (let k = 0; k < 8; k += 1) c = (c << 8n) | BigInt(h[k]!);
    coeffs.push(c % M31);
  }
  return coeffs;
}

export function evalOnCircle(coeffs: M31El[], p: CirclePoint): M31El {
  let acc = 0n;
  let pow = 1n;
  for (const c of coeffs) {
    acc = add(acc, (c * pow) % M31);
    pow = (pow * p.x) % M31;
  }
  return el(acc);
}

export function statementToEvals(statement: PoolStatement, domain: CirclePoint[]): M31El[] {
  const coeffs = statementCoeffs(encodeStatement(statement));
  return domain.map((p) => evalOnCircle(coeffs, p));
}

function foldLayer(
  domain: CirclePoint[],
  evals: M31El[],
  lambda: M31El,
): { domain: CirclePoint[]; evals: M31El[] } {
  const nextN = evals.length / 2;
  const nextE: M31El[] = [];
  const nextD: CirclePoint[] = [];
  for (let i = 0; i < nextN; i += 1) {
    const j = partnerIndex(i, evals.length);
    const folded = foldPair(domain[i]!, evals[i]!, evals[j]!, lambda);
    nextE.push(folded.value);
    nextD.push(folded.domain);
  }
  return { domain: nextD, evals: nextE };
}

function queryIndices(digest: Uint8Array, roots: Uint8Array[]): number[] {
  const seed = sha256(concatBytes(digest, ...roots, new TextEncoder().encode("queries")));
  const idx: number[] = [];
  for (let q = 0; q < FRI_QUERIES; q += 1) idx.push(seed[q]! % FRI_N);
  return idx;
}

export function proveFri(statement: PoolStatement): FriProof {
  const digest = sha256(encodeStatement(statement));
  let domain = circleDomain();
  let evals = statementToEvals(statement, domain);
  const trees: MerkleTree[] = [];
  const layers: M31El[][] = [];
  const domains: CirclePoint[][] = [];

  for (let r = 0; r < FRI_LOG_N - 1; r += 1) {
    const tree = new MerkleTree(evals);
    trees.push(tree);
    layers.push(evals);
    domains.push(domain);
    const lambda = hashToM31(digest, Uint8Array.of(r), tree.root, new TextEncoder().encode("lambda"));
    const next = foldLayer(domain, evals, lambda);
    evals = next.evals;
    domain = next.domain;
  }

  const layerRoots = trees.map((t) => t.root);
  const queries = queryIndices(digest, layerRoots).map((start) => {
    const qLayers: FriQueryLayer[] = [];
    let index = start;
    for (let r = 0; r < trees.length; r += 1) {
      const n = layers[r]!.length;
      const i = index % n;
      const j = partnerIndex(i, n);
      qLayers.push({
        value: layers[r]![i]!,
        partner: layers[r]![j]!,
        path: trees[r]!.path(i),
        partnerPath: trees[r]!.path(j),
      });
      index = i % (n / 2);
    }
    return { index: start, layers: qLayers };
  });

  return { version: FRI_VERSION, layerRoots, final: evals, queries };
}

export function verifyFri(
  statement: PoolStatement,
  proof: FriProof,
): { ok: true } | { ok: false; reason: string } {
  if (proof.version !== FRI_VERSION) return { ok: false, reason: "version" };
  if (proof.layerRoots.length !== FRI_LOG_N - 1) return { ok: false, reason: "layers" };
  if (proof.queries.length !== FRI_QUERIES) return { ok: false, reason: "query count" };

  const digest = sha256(encodeStatement(statement));
  const expectedIdx = queryIndices(digest, proof.layerRoots);
  const honest = statementToEvals(statement, circleDomain());

  for (let q = 0; q < proof.queries.length; q += 1) {
    const query = proof.queries[q]!;
    if (query.index !== expectedIdx[q]) return { ok: false, reason: `query ${q} index` };
    if (query.layers[0]!.value !== honest[query.index]) {
      return { ok: false, reason: "layer0 != statement polynomial" };
    }

    let domain = circleDomain();
    let index = query.index;
    for (let r = 0; r < query.layers.length; r += 1) {
      const n = FRI_N >> r;
      const i = index % n;
      const j = partnerIndex(i, n);
      const layer = query.layers[r]!;
      if (!MerkleTree.verify(layer.value, i, layer.path, proof.layerRoots[r]!)) {
        return { ok: false, reason: `merkle value L${r}` };
      }
      if (!MerkleTree.verify(layer.partner, j, layer.partnerPath, proof.layerRoots[r]!)) {
        return { ok: false, reason: `merkle partner L${r}` };
      }
      const lambda = hashToM31(
        digest,
        Uint8Array.of(r),
        proof.layerRoots[r]!,
        new TextEncoder().encode("lambda"),
      );
      const lo = Math.min(i, j);
      const valLo = i === lo ? layer.value : layer.partner;
      const valHi = i === lo ? layer.partner : layer.value;
      const folded = foldPair(domain[lo]!, valLo, valHi, lambda);
      if (r + 1 === query.layers.length) {
        const fi = i % (n / 2);
        if (fi >= proof.final.length || proof.final[fi] !== folded.value) {
          return { ok: false, reason: "final fold" };
        }
      } else {
        const nxt = query.layers[r + 1]!;
        if (nxt.value !== folded.value && nxt.partner !== folded.value) {
          return { ok: false, reason: `fold mismatch L${r}` };
        }
      }
      const nextDomain: CirclePoint[] = [];
      for (let k = 0; k < n / 2; k += 1) {
        nextDomain.push(foldPair(domain[k]!, 0n, 0n, 0n).domain);
      }
      domain = nextDomain;
      index = i % (n / 2);
    }
  }
  return { ok: true };
}

export function encodeFriProof(p: FriProof): Uint8Array {
  const parts: Uint8Array[] = [
    Uint8Array.of(p.version, p.layerRoots.length, p.final.length, p.queries.length),
  ];
  for (const r of p.layerRoots) parts.push(r);
  for (const f of p.final) parts.push(encodeLe(f));
  for (const q of p.queries) {
    parts.push(writeU16BE(q.index));
    parts.push(Uint8Array.of(q.layers.length));
    for (const layer of q.layers) {
      parts.push(encodeLe(layer.value), encodeLe(layer.partner));
      parts.push(Uint8Array.of(layer.path.length));
      for (const node of layer.path) parts.push(node);
      parts.push(Uint8Array.of(layer.partnerPath.length));
      for (const node of layer.partnerPath) parts.push(node);
    }
  }
  return concatBytes(...parts);
}

export function decodeFriProof(bytes: Uint8Array): FriProof {
  let o = 0;
  const version = bytes[o++]!;
  const nRoots = bytes[o++]!;
  const nFinal = bytes[o++]!;
  const nQ = bytes[o++]!;
  const layerRoots: Uint8Array[] = [];
  for (let i = 0; i < nRoots; i += 1) {
    layerRoots.push(bytes.slice(o, o + 32));
    o += 32;
  }
  const readEl = (): M31El => {
    let v = 0n;
    for (let k = 3; k >= 0; k -= 1) v = (v << 8n) | BigInt(bytes[o + k]!);
    o += 4;
    return v;
  };
  const final: M31El[] = [];
  for (let i = 0; i < nFinal; i += 1) final.push(readEl());
  const queries: FriQuery[] = [];
  for (let q = 0; q < nQ; q += 1) {
    const index = readU16BE(bytes, o);
    o += 2;
    const nL = bytes[o++]!;
    const layers: FriQueryLayer[] = [];
    for (let r = 0; r < nL; r += 1) {
      const value = readEl();
      const partner = readEl();
      const nP = bytes[o++]!;
      const path: Uint8Array[] = [];
      for (let i = 0; i < nP; i += 1) {
        path.push(bytes.slice(o, o + 32));
        o += 32;
      }
      const nPP = bytes[o++]!;
      const partnerPath: Uint8Array[] = [];
      for (let i = 0; i < nPP; i += 1) {
        partnerPath.push(bytes.slice(o, o + 32));
        o += 32;
      }
      layers.push({ value, partner, path, partnerPath });
    }
    queries.push({ index, layers });
  }
  return { version, layerRoots, final, queries };
}

export function proofByteLength(p: FriProof): number {
  return encodeFriProof(p).length;
}

export { addPoints, bytesToHex };
