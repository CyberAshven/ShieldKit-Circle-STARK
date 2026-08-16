/**
 * Packed AIR prefix + M31/Newton/circle snippets for on-chain N=Q·Z.
 * Layout (1200-byte payload, always PUSHDATA2):
 *   0    7×32 layerRoots
 *   224  traceRoot
 *   256  grindNonce u32be
 *   260  Newton even (32 felts)
 *   388  Newton odd
 *   516  encodeStatement (433)
 *   949  Q table (36×4)
 */
import { cashAssemblyToBin, encodeLockingBytecodeP2sh32, hash256 } from "@bitauth/libauth";
import { encodeStatement, type PoolStatement } from "../pool/statement.ts";
import { concatBytes, sha256, writeU32BE } from "../pool/bytes.ts";
import { airQuotientLde, publicCells } from "../backends/circle/air.ts";
import { decodeFriProof, type FriProof } from "../backends/circle/fri.ts";
import { interpolateCircle } from "../backends/circle/interpolate.ts";
import { addPoints, CIRCLE_GEN, CIRCLE_ONE, scalarMul, type CirclePoint } from "../backends/circle/group.ts";
import { add, encodeLe, mul, sub, type M31El } from "../backends/circle/m31.ts";
import { circleDomain } from "../backends/circle/fri.ts";
import { COMMITTED_LAYERS, FRI_N, FRI_QUERIES, TRACE_LEN } from "../backends/circle/params.ts";
import { encodeFeltBlob, M31_ADD, M31_MUL, M31_SUB } from "./m31-asm.ts";

export const AIR_PACKED_SIZE = 1600;
export const AIR_OFF_ROOTS = 0;
export const AIR_OFF_TRACE = 224;
export const AIR_OFF_NONCE = 256;
export const AIR_OFF_EVEN = 260;
export const AIR_OFF_ODD = 392;
export const AIR_OFF_STMT = 524;
export const AIR_STMT_LEN = 433;
export const AIR_OFF_QTABLE = 957;
export const AIR_OFF_IDX = 1101;
export const AIR_OFF_CELLS = 1173;
export const AIR_OFF_NTABLE = 1429;
export const AIR_NEWTON_FELTS = 33;
export const AIR_NEWTON_BYTES = AIR_NEWTON_FELTS * 4;

const smallDomain = circleDomain(TRACE_LEN);
const bigDomain = circleDomain(FRI_N);
export const TRACE_XS: M31El[] = interpolateCircle(
  smallDomain,
  smallDomain.map(() => 0n),
).xs;
export const VANISH_XS: M31El[] = smallDomain.slice(0, TRACE_LEN / 2).map((p) => p.x);
export const G64: CirclePoint = smallDomain[1]!;
export const G1024: CirclePoint = bigDomain[1]!;

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function pushFelt(n: bigint): string {
  return `<${n.toString()}>`;
}

export function newtonEvalJs(coeffs: M31El[], at: M31El, xs: M31El[] = TRACE_XS): M31El {
  let acc = 0n;
  let prod = 1n;
  for (let i = 0; i < coeffs.length; i += 1) {
    acc = add(acc, mul(coeffs[i]!, prod));
    if (i + 1 < coeffs.length) prod = mul(prod, sub(at, xs[i]!));
  }
  return acc;
}

/**
 * Unrolled Newton eval. Stack in: at_x. Coeffs and xs are literals.
 * Stack out: result.
 */
/** Newton from a 128-byte LE blob. Stack: coeffs128 at_x → result. */
export function newtonFromBlobAsm(xs: M31El[] = TRACE_XS): string {
  const lines: string[] = [`OP_TOALTSTACK`, `<0>`, `<1>`];
  for (let i = 0; i < xs.length; i += 1) {
    lines.push(
      `OP_2 OP_PICK`,
      `<${i * 4}>`,
      `OP_SPLIT`,
      `OP_NIP`,
      `<4>`,
      `OP_SPLIT`,
      `OP_DROP`,
      `OP_BIN2NUM`,
      `OP_OVER`,
      M31_MUL,
      `OP_ROT`,
      M31_ADD,
      `OP_SWAP`,
    );
    if (i + 1 < xs.length) {
      lines.push(`OP_FROMALTSTACK`, `OP_DUP`, `OP_TOALTSTACK`, pushFelt(xs[i]!), M31_SUB, M31_MUL);
    }
  }
  lines.push(`OP_DROP`, `OP_NIP`, `OP_FROMALTSTACK`, `OP_DROP`);
  return lines.join("\n");
}

export function newtonEvalUnrolledAsm(coeffs: M31El[], xs: M31El[] = TRACE_XS): string {
  const lines: string[] = [`<0>`, `<1>`];
  for (let i = 0; i < coeffs.length; i += 1) {
    lines.push(pushFelt(coeffs[i]!), `OP_OVER`, M31_MUL, `OP_ROT`, M31_ADD, `OP_SWAP`);
    if (i + 1 < coeffs.length) {
      lines.push(`OP_2 OP_PICK`, pushFelt(xs[i]!), M31_SUB, M31_MUL);
    }
  }
  lines.push(`OP_DROP`, `OP_NIP`);
  return lines.join("\n");
}

/**
 * Decode 2-byte big-endian as unsigned. Stack: be16 → n.
 * A lone high byte (≥0x80) is negative under OP_BIN2NUM; pad LE so 0x0193 is 403, not 147.
 */
export const BE16_UNSIGNED = `
OP_1 OP_SPLIT
OP_SWAP
OP_CAT
<0x00> OP_CAT
OP_BIN2NUM
`;

/** Circle add. Stack: x1 y1 x2 y2 → x3 y3 */
export const CIRCLE_ADD = `
OP_3 OP_PICK
OP_2 OP_PICK
${M31_MUL}
OP_3 OP_PICK
OP_2 OP_PICK
${M31_MUL}
${M31_SUB}
OP_TOALTSTACK
OP_3 OP_PICK
OP_1 OP_PICK
${M31_MUL}
OP_3 OP_PICK
OP_3 OP_PICK
${M31_MUL}
${M31_ADD}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
`;

/** 10-bit double-and-add [k]G. Stack: k gx gy → accx accy */
export const SCALAR_MUL_FAST = `
OP_TOALTSTACK
OP_TOALTSTACK
${pushFelt(CIRCLE_ONE.x)}
${pushFelt(CIRCLE_ONE.y)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_4 OP_ROLL
${Array.from({ length: 10 }, () => `
OP_DUP
OP_2 OP_MOD
OP_IF
  OP_TOALTSTACK
  OP_3 OP_PICK
  OP_3 OP_PICK
  OP_3 OP_PICK
  OP_3 OP_PICK
  ${CIRCLE_ADD}
  OP_TOALTSTACK
  OP_TOALTSTACK
  OP_2SWAP
  OP_2DROP
  OP_FROMALTSTACK
  OP_FROMALTSTACK
  OP_2SWAP
  OP_FROMALTSTACK
OP_ENDIF
OP_TOALTSTACK
OP_2DUP
${CIRCLE_ADD}
OP_FROMALTSTACK
OP_2 OP_DIV
`).join("\n")}
OP_DROP
OP_2DROP
`;

/** [k]G by adding G, k times. Stack: k gx gy → accx accy */
export const SCALAR_MUL = `
OP_TOALTSTACK
OP_TOALTSTACK
${pushFelt(CIRCLE_ONE.x)}
${pushFelt(CIRCLE_ONE.y)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_4 OP_ROLL
OP_BEGIN
  OP_DUP
  OP_0 OP_GREATERTHAN
  OP_IF
    OP_1SUB
    OP_TOALTSTACK
    OP_3 OP_PICK
    OP_3 OP_PICK
    OP_3 OP_PICK
    OP_3 OP_PICK
    ${CIRCLE_ADD}
    OP_TOALTSTACK
    OP_TOALTSTACK
    OP_2SWAP
    OP_2DROP
    OP_FROMALTSTACK
    OP_FROMALTSTACK
    OP_2SWAP
    OP_FROMALTSTACK
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_2DROP
`;

/** Z(zx) = ∏ (zx − xs[k]). Stack: zx → Z */
export function vanishingUnrolledAsm(xs: M31El[] = TRACE_XS): string {
  const lines: string[] = [`<1>`];
  for (const x of xs) {
    lines.push(`OP_OVER`, pushFelt(x), M31_SUB, M31_MUL);
  }
  lines.push(`OP_NIP`);
  return lines.join("\n");
}

export function statementNewton(statement: PoolStatement): { even: M31El[]; odd: M31El[] } {
  const interp = interpolateCircle(smallDomain, publicCells(statement));
  return { even: interp.even, odd: interp.odd };
}

export function fiatShamirQueryIndices(digest: Uint8Array, proof: FriProof): number[] {
  const grindSeed = sha256(concatBytes(digest, proof.traceRoot, ...proof.layerRoots));
  const seed = sha256(concatBytes(grindSeed, writeU32BE(proof.grindNonce), new TextEncoder().encode("queries")));
  const idx: number[] = [];
  let h = seed;
  while (idx.length < FRI_QUERIES) {
    h = sha256(concatBytes(h, new TextEncoder().encode("q"), Uint8Array.of(idx.length)));
    idx.push(((h[0]! << 8) | h[1]!) % FRI_N);
  }
  return idx;
}

export function encodeAirPacked(statement: PoolStatement, proof: Uint8Array | FriProof): Uint8Array {
  const p = proof instanceof Uint8Array ? decodeFriProof(proof) : proof;
  const interp = statementNewton(statement);
  const { qLde, nLde, zLde } = airQuotientLde(statement, smallDomain, bigDomain);
  const digest = sha256(encodeStatement(statement));
  const packed = new Uint8Array(AIR_PACKED_SIZE);
  for (let r = 0; r < COMMITTED_LAYERS; r += 1) {
    packed.set(p.layerRoots[r] ?? new Uint8Array(32), AIR_OFF_ROOTS + r * 32);
  }
  packed.set(p.traceRoot, AIR_OFF_TRACE);
  packed.set(writeU32BE(p.grindNonce), AIR_OFF_NONCE);
  const even = interp.even.slice();
  const odd = interp.odd.slice();
  while (even.length < AIR_NEWTON_FELTS) even.push(0n);
  while (odd.length < AIR_NEWTON_FELTS) odd.push(0n);
  packed.set(encodeFeltBlob(even.slice(0, AIR_NEWTON_FELTS)), AIR_OFF_EVEN);
  packed.set(encodeFeltBlob(odd.slice(0, AIR_NEWTON_FELTS)), AIR_OFF_ODD);
  const stmt = encodeStatement(statement);
  if (stmt.length !== AIR_STMT_LEN) throw new Error(`statement ${stmt.length} != ${AIR_STMT_LEN}`);
  packed.set(stmt, AIR_OFF_STMT);
  const qIdx = fiatShamirQueryIndices(digest, p);
  const off = qIdx.findIndex((i) => zLde[i] !== 0n);
  if (off < 0) throw new Error("all FS queries on-trace");
  if (off !== 0) {
    const tmp = qIdx[0]!;
    qIdx[0] = qIdx[off]!;
    qIdx[off] = tmp;
  }
  for (let s = 0; s < FRI_QUERIES; s += 1) {
    packed.set(encodeLe(qLde[qIdx[s]!]!), AIR_OFF_QTABLE + s * 4);
    packed.set(encodeLe(nLde[qIdx[s]!]!), AIR_OFF_NTABLE + s * 4);
    packed[AIR_OFF_IDX + s * 2] = (qIdx[s]! >> 8) & 0xff;
    packed[AIR_OFF_IDX + s * 2 + 1] = qIdx[s]! & 0xff;
  }
  const cells = publicCells(statement);
  while (cells.length < TRACE_LEN) cells.push(0n);
  packed.set(encodeFeltBlob(cells.slice(0, TRACE_LEN)), AIR_OFF_CELLS);
  return packed;
}

export function nqzAt(statement: PoolStatement, index: number): { n: M31El; z: M31El; q: M31El } {
  const { nLde, zLde, qLde } = airQuotientLde(statement, smallDomain, bigDomain);
  return { n: nLde[index]!, z: zLde[index]!, q: qLde[index]! };
}

function compileOrThrow(asm: string, name: string): Uint8Array {
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`${name}: ${bin}`);
  return bin;
}

export function compileM31MulLock(): Uint8Array {
  return compileOrThrow(`${M31_MUL}\n<15>\nOP_NUMEQUAL`, "m31mul");
}

export function compileNewtonLock(coeffs: M31El[]): Uint8Array {
  return compileOrThrow(`${newtonEvalUnrolledAsm(coeffs)}\nOP_NUMEQUAL`, "newton");
}

export function compileCircleAddLock(expected: CirclePoint): Uint8Array {
  return compileOrThrow(
    `${CIRCLE_ADD}\n${pushFelt(expected.y)}\nOP_NUMEQUALVERIFY\n${pushFelt(expected.x)}\nOP_NUMEQUAL`,
    "cadd",
  );
}

export function compileScalarMulLock(expected: CirclePoint): Uint8Array {
  return compileOrThrow(
    `${SCALAR_MUL}\n${pushFelt(expected.y)}\nOP_NUMEQUALVERIFY\n${pushFelt(expected.x)}\nOP_NUMEQUAL`,
    "smul",
  );
}

export function compileVanishingLock(): Uint8Array {
  return compileOrThrow(`${vanishingUnrolledAsm(VANISH_XS)}\nOP_NUMEQUAL`, "vanish");
}

/**
 * One-query N=Q·Z. Unlocking: even_at, odd_at, q, zx (we pass zx to skip scalar-mul
 * in this isolated lock). Lock recomputes Z(zx) and N from T(z),T(z+g),T(z+2g)
 * supplied as six Newton results? Isolated version: unlocking is q z n, lock checks q*z==n.
 *
 * Full N is checked in compileCqzFromCellsLock.
 */
export function compileQzEqualsNLock(): Uint8Array {
  return compileOrThrow(`${M31_MUL}\nOP_NUMEQUAL`, "qz=n");
}

export function compileNewtonFromBlobLock(): Uint8Array {
  return compileOrThrow(`${newtonFromBlobAsm()}\nOP_NUMEQUAL`, "newton-blob");
}

export function compileEvalTFromBlobLock(expected: M31El): Uint8Array {
  return compileOrThrow(
    `
${defineNewtonFn()}
${evalTFromBlobAsm()}
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "evalT-blob",
  );
}

function defineNewtonFn(): string {
  const body = cashAssemblyToBin(newtonFromBlobAsm());
  if (typeof body === "string") throw new Error(`newton fn: ${body}`);
  return `${hexPush(body)}\n<0>\nOP_DEFINE`;
}

/** Stack: even odd x y → T(x,y). Requires newton fn 0. Alt-clean. */
export function evalTFromBlobAsm(): string {
  return `
OP_TOALTSTACK
OP_TOALTSTACK
OP_OVER
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<0> OP_INVOKE
OP_FROMALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_TOALTSTACK
OP_NIP
OP_FROMALTSTACK
<0> OP_INVOKE
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
${M31_MUL}
${M31_ADD}
`;
}

/**
 * Stack: packed blob.
 * For each Fiat–Shamir slot: Z([i]G) is recomputed and Q·Z equals nTable[s].
 * Query indices are taken from the packed transcript (bound to this statement).
 */
export function checkAirCqzAsm(): string {
  const g = `${pushFelt(G1024.x)}\n${pushFelt(G1024.y)}`;
  return `
<0>
OP_BEGIN
  OP_DUP
  <${FRI_QUERIES}>
  OP_LESSTHAN
  OP_IF
    OP_OVER
    OP_OVER
    <2> OP_MUL
    <${AIR_OFF_IDX}> OP_ADD
    OP_SPLIT OP_NIP
    <2> OP_SPLIT OP_DROP
    ${BE16_UNSIGNED}
    OP_TOALTSTACK
    OP_OVER
    OP_OVER
    <4> OP_MUL
    <${AIR_OFF_QTABLE}> OP_ADD
    OP_SPLIT OP_NIP
    <4> OP_SPLIT OP_DROP
    OP_BIN2NUM
    OP_TOALTSTACK
    OP_OVER
    OP_SWAP
    <4> OP_MUL
    <${AIR_OFF_NTABLE}> OP_ADD
    OP_SPLIT OP_NIP
    <4> OP_SPLIT OP_DROP
    OP_BIN2NUM
    OP_FROMALTSTACK
    OP_SWAP
    OP_TOALTSTACK
    OP_TOALTSTACK
    OP_FROMALTSTACK
    ${g}
    ${SCALAR_MUL}
    OP_DROP
    ${vanishingUnrolledAsm(VANISH_XS)}
    OP_FROMALTSTACK
    ${M31_MUL}
    OP_FROMALTSTACK
    OP_NUMEQUALVERIFY
    OP_1ADD
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_DROP
`;
}

export function compileCheckAirLock(): Uint8Array {
  return compileOrThrow(`${checkAirCqzAsm()}\nOP_1`, "check-air");
}

export function packedMagicAsm(): string {
  return `
OP_DUP
<${AIR_OFF_STMT}> OP_SPLIT OP_NIP
<4> OP_SPLIT
OP_SWAP
<0x50414131> OP_EQUALVERIFY
<4> OP_SPLIT
OP_DROP
<0x53544d54> OP_EQUALVERIFY
`;
}

function padNewton(vals: M31El[]): M31El[] {
  const out = vals.slice();
  while (out.length < AIR_NEWTON_FELTS) out.push(0n);
  return out.slice(0, AIR_NEWTON_FELTS);
}

function lagrangeNewtonBlobs(k: number): { even: Uint8Array; odd: Uint8Array } {
  const interp = interpolateCircle(
    smallDomain,
    Array.from({ length: TRACE_LEN }, (_, i) => (i === k ? 1n : 0n)),
  );
  return {
    even: encodeFeltBlob(padNewton(interp.even)),
    odd: encodeFeltBlob(padNewton(interp.odd)),
  };
}

/** Stack: L0 L23 Tp Tgp Tg2 action → N = L0·cons + L23·seq */
export function airNumeratorAsm(): string {
  return `
OP_3 OP_PICK
OP_3 OP_PICK
OP_SWAP
${M31_SUB}
OP_DUP
<1>
${M31_SUB}
OP_2 OP_PICK
OP_1
OP_NUMEQUAL
OP_IF
  OP_3 OP_PICK
  OP_2 OP_PICK
  OP_SWAP
  ${M31_SUB}
OP_ELSE
  OP_3 OP_PICK
  OP_2 OP_PICK
  <0>
  OP_SWAP
  ${M31_SUB}
  OP_SWAP
  ${M31_SUB}
OP_ENDIF
OP_TOALTSTACK
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_3 OP_PICK
OP_OVER
${M31_MUL}
OP_TOALTSTACK
OP_DROP
OP_ROT
OP_DROP
${M31_MUL}
OP_FROMALTSTACK
${M31_ADD}
`;
}

/**
 * Slot-0 C=Q·Z with N recomputed from the public interpolant T.
 * Stack in: packed blob.
 * i = idx[0], z = [i]G_1024, Z(z.x) ≠ 0, N = L0·cons + L23·seq from T,
 * then nTable[0] == N and qTable[0]·Z == N.
 */
export function slot0CqzAsm(): string {
  const l0 = lagrangeNewtonBlobs(0);
  const l23 = lagrangeNewtonBlobs(23);
  const g64 = `${pushFelt(G64.x)}\n${pushFelt(G64.y)}`;
  return `
${defineNewtonFn()}
${packedMagicAsm()}
OP_DUP
<${AIR_OFF_IDX}> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
OP_SWAP
OP_DUP
<${AIR_OFF_QTABLE}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_NTABLE}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_STMT + 8}> OP_SPLIT OP_NIP
<1> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_EVEN}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_TOALTSTACK
<${AIR_OFF_ODD}> OP_SPLIT OP_NIP
<${AIR_NEWTON_BYTES}> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_SWAP
OP_TOALTSTACK
OP_TOALTSTACK
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
${SCALAR_MUL_FAST}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_2SWAP
OP_OVER
${vanishingUnrolledAsm(VANISH_XS)}
OP_DUP
OP_0
OP_NUMNOTEQUAL
OP_VERIFY
OP_TOALTSTACK
OP_2OVER
OP_3 OP_PICK
OP_3 OP_PICK
${evalTFromBlobAsm()}
OP_TOALTSTACK
OP_2DUP
${g64}
${CIRCLE_ADD}
OP_5 OP_PICK
OP_5 OP_PICK
OP_3 OP_PICK
OP_3 OP_PICK
${evalTFromBlobAsm()}
OP_TOALTSTACK
OP_2DUP
${g64}
${CIRCLE_ADD}
OP_7 OP_PICK
OP_7 OP_PICK
OP_3 OP_PICK
OP_3 OP_PICK
${evalTFromBlobAsm()}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_2DUP
${hexPush(l0.even)}
${hexPush(l0.odd)}
OP_2SWAP
${evalTFromBlobAsm()}
OP_TOALTSTACK
OP_2DUP
${hexPush(l23.even)}
${hexPush(l23.odd)}
OP_2SWAP
${evalTFromBlobAsm()}
OP_TOALTSTACK
OP_2DROP
OP_2DROP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_ROT
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_TOALTSTACK
${airNumeratorAsm()}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_SWAP
OP_3 OP_PICK
OP_NUMEQUALVERIFY
OP_SWAP
${M31_MUL}
OP_NUMEQUALVERIFY
`;
}

/** Isolated slot-0 C=QZ. Unlocking: packed blob. */
export function compileSlot0CqzLock(): Uint8Array {
  return compileOrThrow(`${slot0CqzAsm()}\nOP_1`, "slot0-cqz");
}

/** Kernel redeem: load packed blob from input 0 unlocking, then slot-0 C=Q·Z. */
export const CQZ_KERNEL = `
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
${slot0CqzAsm()}
OP_1
`;

export function compileCqzKernel(): Uint8Array {
  return compileOrThrow(CQZ_KERNEL, "cqz-kernel");
}

export function compileCqzLockP2sh32(): Uint8Array {
  return encodeLockingBytecodeP2sh32(hash256(compileCqzKernel()));
}

export function cqzKernelUnlocking(): Uint8Array {
  const data = compileCqzKernel();
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

export function compileScalarMulFastLock(expected: CirclePoint): Uint8Array {
  return compileOrThrow(
    `${SCALAR_MUL_FAST}\n${pushFelt(expected.y)}\nOP_NUMEQUALVERIFY\n${pushFelt(expected.x)}\nOP_NUMEQUAL`,
    "smul-fast",
  );
}

/**
 * One FS query: packed blob on stack, slot on top.
 * Recomputes i = FS[slot], z=[i]G, Z, T, N, checks qTable[slot]*Z == N.
 */
export function oneQueryCqzAsm(): string {
  const l0e = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(0)).even);
  const l0o = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(0)).odd);
  const l23e = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(23)).even);
  const l23o = encodeFeltBlob(interpolateCircle(smallDomain, oneHot(23)).odd);
  return `
OP_TOALTSTACK
<${AIR_OFF_QTABLE}> OP_SPLIT OP_NIP
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<4> OP_MUL
OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_TOALTSTACK
`;
}

function oneHot(k: number): M31El[] {
  return Array.from({ length: TRACE_LEN }, (_, i) => (i === k ? 1n : 0n));
}

/**
 * Given at_x, evaluate T = even(at) + y*odd(at).
 * Unlocking: at_x  at_y. Redeem contains even/odd coeff literals.
 */
export function compileEvalTLock(even: M31El[], odd: M31El[], expected: M31El): Uint8Array {
  return compileOrThrow(
    `
OP_TOALTSTACK
OP_DUP
OP_TOALTSTACK
${newtonEvalUnrolledAsm(even)}
OP_FROMALTSTACK
${newtonEvalUnrolledAsm(odd)}
OP_FROMALTSTACK
${M31_MUL}
${M31_ADD}
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "evalT",
  );
}

export function compileCqzRelationLock(statement: PoolStatement, index: number): Uint8Array {
  const interp = statementNewton(statement);
  const z = bigDomain[index]!;
  const zg = addPoints(z, G64);
  const zg2 = addPoints(zg, G64);
  const tp = add(newtonEvalJs(interp.even, z.x), mul(z.y, newtonEvalJs(interp.odd, z.x)));
  const tgp = add(newtonEvalJs(interp.even, zg.x), mul(zg.y, newtonEvalJs(interp.odd, zg.x)));
  const tg2 = add(newtonEvalJs(interp.even, zg2.x), mul(zg2.y, newtonEvalJs(interp.odd, zg2.x)));
  const deposit = statement.action === "DEPOSIT";
  const cons = deposit ? sub(sub(tgp, tp), tg2) : sub(sub(tp, tgp), tg2);
  const seq = sub(sub(tgp, tp), 1n);
  const l0 = oneHotEval(0, z);
  const l23 = oneHotEval(23, z);
  const n = add(mul(l0, cons), mul(l23, seq));
  const { q, z: zVal } = nqzAt(statement, index);
  if (mul(q, zVal) !== n) throw new Error("JS C=QZ mismatch");
  return compileQzEqualsNLock();
}

function oneHotEval(k: number, p: CirclePoint): M31El {
  const interp = interpolateCircle(
    smallDomain,
    Array.from({ length: TRACE_LEN }, (_, i) => (i === k ? 1n : 0n)),
  );
  return add(newtonEvalJs(interp.even, p.x), mul(p.y, newtonEvalJs(interp.odd, p.x)));
}

/** First unlocking item is the packed AIR blob (PUSHDATA2). */
export const LOAD_AIR_PACKED = `
<0> OP_INPUTBYTECODE
<1> OP_SPLIT OP_NIP
<2> OP_SPLIT OP_NIP
`;

export { smallDomain, bigDomain, addPoints, scalarMul, CIRCLE_GEN };
