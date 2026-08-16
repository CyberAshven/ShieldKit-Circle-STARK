import {
  bytesToHex,
  concatBytes,
  eq32,
  readU16BE,
  readU32BE,
  readU64BE,
  sha256,
  writeU16BE,
  writeU32BE,
  writeU64BE,
} from "../../pool/bytes.ts";
import { commitNote } from "../../pool/notes.ts";
import {
  freshViewingKey,
  maskAuth,
  unmaskAuth,
  viewingCommit,
  openingMaskFelt,
  VIEWING_PAD_LEN,
} from "./witness-mask.ts";
import { encodeStatement, type PoolStatement } from "../../pool/statement.ts";
import { foldPair } from "./fold.ts";
import { addPoints, CIRCLE_GEN, scalarMul, type CirclePoint } from "./group.ts";
import { add, encodeLe, M31, mul, sub, type M31El } from "./m31.ts";
import { MerkleTree } from "./merkle.ts";
import {
  COMMITTED_LAYERS,
  FRI_FINAL,
  FRI_LOG_N,
  FRI_N,
  FRI_QUERIES,
  FRI_VERSION,
  GRIND_BITS,
  TRACE_LEN,
  assertSoundParams,
} from "./params.ts";
import {
  airQuotientLde,
  algebraicC,
  assertSatisfied,
  buildTrace,
  checkAuthRelation,
  checkPublicAuthRelation,
  checkPublicConservation,
  openedNote,
  publicCells,
  publicEvals,
  quotientAtDomain,
  type FriAuth,
  type FriWitness,
} from "./air.ts";
import { evalCirclePoly, interpolateCircle } from "./interpolate.ts";

assertSoundParams();

export type FriQueryLayer = {
  value: M31El;
  partner: M31El;
  path: Uint8Array[];
  partnerPath: Uint8Array[];
};

export type FriQuery = {
  index: number;
  layers: FriQueryLayer[];
  traceValue: M31El;
  tracePath: Uint8Array[];
};

export type FriProof = {
  version: number;
  grindNonce: number;
  layerRoots: Uint8Array[];
  traceRoot: Uint8Array;
  final: M31El[];
  queries: FriQuery[];
  auth: FriAuth;
  /** In-memory only. Never written by encodeFriProof. */
  viewingKey?: Uint8Array;
  viewingCommit?: Uint8Array;
  authMasked?: boolean;
};

export type VerifyFriOpts = { viewingKey?: Uint8Array };

function log2n(n: number): number {
  return Math.round(Math.log2(n));
}

function subgroupGen(n: number): CirclePoint {
  const log = log2n(n);
  return scalarMul(CIRCLE_GEN, 2n ** BigInt(31 - log));
}

const domainCache = new Map<number, CirclePoint[]>();

export function circleDomain(n: number = FRI_N): CirclePoint[] {
  const hit = domainCache.get(n);
  if (hit) return hit;
  const g = subgroupGen(n);
  const out: CirclePoint[] = [scalarMul(g, 0n)];
  let acc = g;
  out.push(acc);
  for (let i = 2; i < n; i += 1) {
    acc = addPoints(acc, g);
    out.push(acc);
  }
  domainCache.set(n, out);
  return out;
}

function hashToM31(...parts: Uint8Array[]): M31El {
  const h = sha256(concatBytes(...parts));
  let n = 0n;
  for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(h[i]!);
  return n % M31;
}

function partnerIndex(i: number, n: number): number {
  return (i + n / 2) % n;
}

/** Lay out (i, i+n/2) as merkle siblings so each query sends one shared path. */
function pairOrder(evals: M31El[]): M31El[] {
  const n = evals.length;
  const out: M31El[] = [];
  for (let i = 0; i < n / 2; i += 1) {
    out.push(evals[i]!, evals[i + n / 2]!);
  }
  return out;
}

function pairMerkleIndex(i: number, n: number): number {
  return i < n / 2 ? 2 * i : 2 * (i - n / 2) + 1;
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

function queryIndices(seed: Uint8Array, n: number, count: number): number[] {
  const idx: number[] = [];
  let h = seed;
  while (idx.length < count) {
    h = sha256(concatBytes(h, new TextEncoder().encode("q"), Uint8Array.of(idx.length)));
    const v = (h[0]! << 8) | h[1]!;
    idx.push(v % n);
  }
  return idx;
}

function grindOk(digest: Uint8Array, nonce: number): boolean {
  const h = sha256(concatBytes(digest, writeU32BE(nonce), new TextEncoder().encode("grind")));
  let bits = 0;
  for (const b of h) {
    for (let i = 7; i >= 0; i -= 1) {
      if (((b >> i) & 1) !== 0) return bits >= GRIND_BITS;
      bits += 1;
      if (bits >= GRIND_BITS) return true;
    }
  }
  return bits >= GRIND_BITS;
}

function findGrind(digest: Uint8Array): number {
  for (let nonce = 0; nonce < 1 << 24; nonce += 1) {
    if (grindOk(digest, nonce)) return nonce;
  }
  throw new Error("grind failed");
}

export function statementToEvals(statement: PoolStatement, domain: CirclePoint[]): M31El[] {
  return publicEvals(statement, circleDomain(TRACE_LEN), domain);
}

export function proveFri(statement: PoolStatement, witness: FriWitness = {}): FriProof {
  const trace = buildTrace(statement, witness);
  assertSatisfied(trace);
  const digest = sha256(encodeStatement(statement));
  const small = circleDomain(TRACE_LEN);
  const big = circleDomain(FRI_N);
  const viewingKey = freshViewingKey();
  const vCommit = viewingCommit(viewingKey);
  const { qLde } = airQuotientLde(statement, small, big);
  const openMask = openingMaskFelt(vCommit);
  const tLde = qLde.map((q) => add(q, openMask));
  const traceTree = new MerkleTree(tLde);

  let domain = big;
  let evals = tLde.slice();
  const trees: MerkleTree[] = [];
  const layers: M31El[][] = [];
  const domains: CirclePoint[][] = [];

  const stopAt = FRI_FINAL;
  while (evals.length > stopAt) {
    const tree = new MerkleTree(pairOrder(evals));
    trees.push(tree);
    layers.push(evals);
    domains.push(domain);
    const lambda = hashToM31(digest, Uint8Array.of(trees.length - 1), tree.root, new TextEncoder().encode("lambda"));
    const next = foldLayer(domain, evals, lambda);
    evals = next.evals;
    domain = next.domain;
  }

  const layerRoots = trees.map((t) => t.root);
  const grindSeed = sha256(concatBytes(digest, traceTree.root, ...layerRoots));
  const grindNonce = findGrind(grindSeed);
  const qIdx = queryIndices(
    sha256(concatBytes(grindSeed, writeU32BE(grindNonce), new TextEncoder().encode("queries"))),
    FRI_N,
    FRI_QUERIES,
  );

  const queries = qIdx.map((start) => {
    const qLayers: FriQueryLayer[] = [];
    let index = start;
    for (let r = 0; r < trees.length; r += 1) {
      const n = layers[r]!.length;
      const i = index % n;
      const j = partnerIndex(i, n);
      qLayers.push({
        value: layers[r]![i]!,
        partner: layers[r]![j]!,
        path: trees[r]!.path(pairMerkleIndex(i, n)).slice(1),
        partnerPath: [],
      });
      index = i % (n / 2);
    }
    return {
      index: start,
      layers: qLayers,
      traceValue: tLde[start]!,
      tracePath: traceTree.path(start),
    };
  });

  return {
    version: FRI_VERSION,
    grindNonce,
    layerRoots,
    traceRoot: traceTree.root,
    final: evals,
    queries,
    auth: trace.auth,
    viewingKey,
    viewingCommit: vCommit,
    authMasked: false,
  };
}

/** FRI of a caller-supplied quotient LDE (mutation / cheat tests). Still carries auth. */
export function proveFromTLde(statement: PoolStatement, tLde: M31El[], auth: FriAuth): FriProof {
  const digest = sha256(encodeStatement(statement));
  const viewingKey = freshViewingKey();
  const vCommit = viewingCommit(viewingKey);
  const openMask = openingMaskFelt(vCommit);
  const masked = tLde.map((q) => add(q, openMask));
  const big = circleDomain(FRI_N);
  const traceTree = new MerkleTree(masked);
  let domain = big;
  let evals = masked.slice();
  const trees: MerkleTree[] = [];
  const layers: M31El[][] = [];
  while (evals.length > FRI_FINAL) {
    const tree = new MerkleTree(pairOrder(evals));
    trees.push(tree);
    layers.push(evals);
    const lambda = hashToM31(digest, Uint8Array.of(trees.length - 1), tree.root, new TextEncoder().encode("lambda"));
    const next = foldLayer(domain, evals, lambda);
    evals = next.evals;
    domain = next.domain;
  }
  const layerRoots = trees.map((t) => t.root);
  const grindSeed = sha256(concatBytes(digest, traceTree.root, ...layerRoots));
  const grindNonce = findGrind(grindSeed);
  const qIdx = queryIndices(
    sha256(concatBytes(grindSeed, writeU32BE(grindNonce), new TextEncoder().encode("queries"))),
    FRI_N,
    FRI_QUERIES,
  );
  const queries = qIdx.map((start) => {
    const qLayers: FriQueryLayer[] = [];
    let index = start;
    for (let r = 0; r < trees.length; r += 1) {
      const n = layers[r]!.length;
      const i = index % n;
      const j = partnerIndex(i, n);
      qLayers.push({
        value: layers[r]![i]!,
        partner: layers[r]![j]!,
        path: trees[r]!.path(pairMerkleIndex(i, n)).slice(1),
        partnerPath: [],
      });
      index = i % (n / 2);
    }
    return {
      index: start,
      layers: qLayers,
      traceValue: masked[start]!,
      tracePath: traceTree.path(start),
    };
  });
  return {
    version: FRI_VERSION,
    grindNonce,
    layerRoots,
    traceRoot: traceTree.root,
    final: evals,
    queries,
    auth,
    viewingKey,
    viewingCommit: vCommit,
    authMasked: false,
  };
}

export function mutateTraceAndProve(statement: PoolStatement, bumpIndex: number, witness: FriWitness): FriProof {
  const small = circleDomain(TRACE_LEN);
  const big = circleDomain(FRI_N);
  const trace = buildTrace(statement, witness);
  assertSatisfied(trace);
  const { qLde } = airQuotientLde(statement, small, big);
  const bumped = qLde.map((x, i) => (i === bumpIndex % qLde.length ? add(x, 1n) : add(x, 1n)));
  return proveFromTLde(statement, bumped, trace.auth);
}

function authPreimageOpen(auth: FriAuth): boolean {
  try {
    return eq32(auth.leaf, commitNote(openedNote(auth)));
  } catch {
    return false;
  }
}

function resolveAuthForVerify(
  statement: PoolStatement,
  proof: FriProof,
  witness: FriWitness,
  opts: VerifyFriOpts,
): { ok: true } | { ok: false; reason: string } {
  const key = opts.viewingKey ?? (proof.authMasked ? undefined : proof.viewingKey);
  if (key) {
    if (key.length !== VIEWING_PAD_LEN) return { ok: false, reason: "viewing key" };
    const commit = proof.viewingCommit ?? viewingCommit(key);
    if (!eq32(viewingCommit(key), commit)) return { ok: false, reason: "viewing key" };
    const opened = proof.authMasked ? unmaskAuth(proof.auth, key) : proof.auth;
    return checkAuthRelation(statement, opened, witness);
  }
  if (authPreimageOpen(proof.auth)) {
    return checkAuthRelation(statement, proof.auth, witness);
  }
  return checkPublicAuthRelation(statement, proof.auth);
}

/**
 * Opening-only verifier. FRI target is algebraicC / Z (conservation, sequence,
 * action). Membership is a sibling nativeWalk, not a residual flag.
 * Published encodings mask the note preimage; pass `viewingKey` to open it.
 */
export function verifyFri(
  statement: PoolStatement,
  proof: FriProof,
  witness: FriWitness = {},
  opts: VerifyFriOpts = {},
): { ok: true } | { ok: false; reason: string } {
  if (proof.version !== FRI_VERSION) return { ok: false, reason: "version" };
  if (proof.queries.length !== FRI_QUERIES) return { ok: false, reason: "query count" };
  if (proof.final.length !== FRI_FINAL) return { ok: false, reason: "final width" };
  if (!proof.auth) return { ok: false, reason: "missing auth" };

  const cons = checkPublicConservation(statement);
  if (!cons.ok) return cons;
  const auth = resolveAuthForVerify(statement, proof, witness, opts);
  if (!auth.ok) return auth;

  const cVec = algebraicC(publicCells(statement), statement);
  if (cVec.some((r) => r !== 0n)) return { ok: false, reason: "algebraicC" };
  const { nLde, zLde } = airQuotientLde(statement, circleDomain(TRACE_LEN), circleDomain(FRI_N));

  const digest = sha256(encodeStatement(statement));
  const grindSeed = sha256(concatBytes(digest, proof.traceRoot, ...proof.layerRoots));
  if (!grindOk(grindSeed, proof.grindNonce)) return { ok: false, reason: "grind" };
  const expectedIdx = queryIndices(
    sha256(concatBytes(grindSeed, writeU32BE(proof.grindNonce), new TextEncoder().encode("queries"))),
    FRI_N,
    FRI_QUERIES,
  );

  for (let q = 0; q < proof.queries.length; q += 1) {
    const query = proof.queries[q]!;
    if (query.index !== expectedIdx[q]) return { ok: false, reason: `query ${q} index` };
    if (!MerkleTree.verify(query.traceValue, query.index, query.tracePath, proof.traceRoot)) {
      return { ok: false, reason: "trace merkle" };
    }
    const nAt = nLde[query.index]!;
    const zAt = zLde[query.index]!;
    const openMask = proof.viewingCommit ? openingMaskFelt(proof.viewingCommit) : 0n;
    if (mul(sub(query.traceValue, openMask), zAt) !== nAt) {
      return { ok: false, reason: "N != Q*Z" };
    }
    if (query.layers[0]!.value !== query.traceValue) {
      return { ok: false, reason: "FRI layer0 != Q(z)" };
    }

    let domain = circleDomain(FRI_N);
    let index = query.index;
    for (let r = 0; r < query.layers.length; r += 1) {
      const n = FRI_N >> r;
      const i = index % n;
      const j = partnerIndex(i, n);
      const layer = query.layers[r]!;
      if (!MerkleTree.verifyPaired(layer.value, layer.partner, i, n, layer.path, proof.layerRoots[r]!)) {
        return { ok: false, reason: `merkle T L${r}` };
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

function encodeAuth(a: FriAuth, commit: Uint8Array): Uint8Array {
  return concatBytes(
    writeU16BE(a.index),
    Uint8Array.of(a.path.length),
    a.leaf,
    a.root,
    a.nullifier,
    a.amountCommit,
    writeU16BE(a.createdIndex),
    Uint8Array.of(a.createdPath.length),
    a.createdLeaf,
    commit.length === 32 ? commit : new Uint8Array(32),
    a.rho,
    a.owner,
    writeU64BE(a.amountSats),
    writeU64BE(a.publicDeltaSats),
    ...a.path,
    ...a.createdPath,
  );
}

function decodeAuth(bytes: Uint8Array, start: number): { auth: FriAuth; viewingCommit: Uint8Array; next: number } {
  let o = start;
  const index = readU16BE(bytes, o);
  o += 2;
  const nP = bytes[o++]!;
  const leaf = bytes.slice(o, o + 32);
  o += 32;
  const root = bytes.slice(o, o + 32);
  o += 32;
  const nullifier = bytes.slice(o, o + 32);
  o += 32;
  const amountCommit = bytes.slice(o, o + 32);
  o += 32;
  const createdIndex = readU16BE(bytes, o);
  o += 2;
  const nC = bytes[o++]!;
  const createdLeaf = bytes.slice(o, o + 32);
  o += 32;
  const commit = bytes.slice(o, o + 32);
  o += 32;
  const rho = bytes.slice(o, o + 32);
  o += 32;
  const owner = bytes.slice(o, o + 32);
  o += 32;
  const amountSats = readU64BE(bytes, o);
  o += 8;
  const publicDeltaSats = readU64BE(bytes, o);
  o += 8;
  const path: Uint8Array[] = [];
  for (let i = 0; i < nP; i += 1) {
    path.push(bytes.slice(o, o + 32));
    o += 32;
  }
  const createdPath: Uint8Array[] = [];
  for (let i = 0; i < nC; i += 1) {
    createdPath.push(bytes.slice(o, o + 32));
    o += 32;
  }
  return {
    auth: { leaf, index, path, root, nullifier, rho, owner, amountSats, publicDeltaSats, amountCommit, createdLeaf, createdIndex, createdPath },
    viewingCommit: commit,
    next: o,
  };
}

export function encodeFriProof(p: FriProof): Uint8Array {
  const key = p.viewingKey && p.viewingKey.length === VIEWING_PAD_LEN ? p.viewingKey : freshViewingKey();
  const commit = viewingCommit(key);
  const published = p.authMasked ? p.auth : maskAuth(p.auth, key);
  const parts: Uint8Array[] = [
    Uint8Array.of(p.version, p.layerRoots.length, p.final.length, p.queries.length),
    writeU32BE(p.grindNonce),
    p.traceRoot,
    encodeAuth(published, commit),
  ];
  for (const r of p.layerRoots) parts.push(r);
  for (const f of p.final) parts.push(encodeLe(f));
  for (const q of p.queries) {
    parts.push(writeU16BE(q.index));
    parts.push(encodeLe(q.traceValue));
    parts.push(Uint8Array.of(q.tracePath.length));
    for (const node of q.tracePath) parts.push(node);
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
  const grindNonce = readU32BE(bytes, o);
  o += 4;
  const traceRoot = bytes.slice(o, o + 32);
  o += 32;
  const decodedAuth = decodeAuth(bytes, o);
  const auth = decodedAuth.auth;
  const commit = decodedAuth.viewingCommit;
  o = decodedAuth.next;
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
    const traceValue = readEl();
    const nTP = bytes[o++]!;
    const tracePath: Uint8Array[] = [];
    for (let i = 0; i < nTP; i += 1) {
      tracePath.push(bytes.slice(o, o + 32));
      o += 32;
    }
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
    queries.push({ index, layers, traceValue, tracePath });
  }
  return {
    version,
    grindNonce,
    layerRoots,
    traceRoot,
    final,
    queries,
    auth,
    viewingCommit: commit,
    authMasked: true,
  };
}

export function unmaskFriProof(proof: FriProof, key: Uint8Array): FriProof {
  if (key.length !== VIEWING_PAD_LEN) throw new Error("viewing key width");
  if (proof.viewingCommit && !eq32(viewingCommit(key), proof.viewingCommit)) {
    throw new Error("viewing key");
  }
  return {
    ...proof,
    auth: proof.authMasked ? unmaskAuth(proof.auth, key) : proof.auth,
    viewingKey: key,
    authMasked: false,
  };
}

export function proofByteLength(p: FriProof): number {
  return encodeFriProof(p).length;
}

export { add, bytesToHex, COMMITTED_LAYERS, FRI_LOG_N, FRI_N, FRI_QUERIES, TRACE_LEN };
export { freshViewingKey, unmaskAuth, viewingCommit, openingMaskFelt, VIEWING_PAD_LEN } from "./witness-mask.ts";
export type { FriWitness, FriAuth };
export { airQuotientLde, algebraicC, buildTrace, nativeWalk, publicCells, publicEvals, quotientAtDomain, wDeposit, wWithdraw } from "./air.ts";
export { interpolateCircle, evalCirclePoly } from "./interpolate.ts";
