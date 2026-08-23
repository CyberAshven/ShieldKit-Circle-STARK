/**
 * On-chain Circle FRI fold (2024/278 foldPair) for the 2026 VM.
 * Function indices used by the production FRI kernel:
 *   0 CIRCLE_ADD   1 SCALAR_MUL   2 FOLD_PAIR   3 LAMBDA
 */
import { cashAssemblyToBin } from "@bitauth/libauth";
import { COMMITTED_LAYERS, FRI_FINAL, FRI_N } from "../backends/circle/params.ts";
import {
  AIR_OFF_DIGEST,
  AIR_OFF_FINAL,
  AIR_OFF_ROOTS,
  BE16_UNSIGNED,
  CIRCLE_ADD,
  G1024,
  SCALAR_MUL_FAST,
} from "./air-cqz.ts";
import { M31_ADD, M31_INV, M31_MUL, M31_P, M31_SUB, M31_TWO_INV } from "./m31-asm.ts";

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function defineFn(asm: string, index: number, name: string): string {
  const body = cashAssemblyToBin(asm);
  if (typeof body === "string") throw new Error(`${name}: ${body}`);
  return `${hexPush(body)}\n<${index}>\nOP_DEFINE`;
}

function pushFelt(n: bigint): string {
  return `<${n.toString()}>`;
}

/** 4-byte big-endian → unsigned integer (trailing 0x00 keeps BIN2NUM unsigned). */
function be4UnsignedAsm(): string {
  return `
OP_1 OP_SPLIT
OP_1 OP_SPLIT
OP_1 OP_SPLIT
OP_SWAP
OP_CAT
OP_SWAP
OP_CAT
OP_SWAP
OP_CAT
<0x00>
OP_CAT
OP_BIN2NUM
`;
}

/** 8-byte big-endian → integer, then mod M31 (hashToM31). Same value as the byte-loop. */
export const BE8_MOD_P = `
<4> OP_SPLIT
OP_SWAP
${be4UnsignedAsm()}
<4294967296>
OP_MUL
OP_SWAP
${be4UnsignedAsm()}
OP_ADD
<${M31_P}> OP_MOD
`;

/** Stack: packed r → packed λ. λ = first-8-BE(SHA256(digest || r || root[r] || "lambda")) mod p. */
export function lambdaFromPackedAsm(): string {
  return `
OP_TOALTSTACK
OP_DUP
<${AIR_OFF_DIGEST}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_FROMALTSTACK
OP_DUP
OP_TOALTSTACK
<1> OP_NUM2BIN
OP_CAT
OP_OVER
OP_FROMALTSTACK
<32> OP_MUL
<${AIR_OFF_ROOTS}> OP_ADD
OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
OP_CAT
<0x6c616d626461> OP_CAT
OP_SHA256
<8> OP_SPLIT OP_DROP
${BE8_MOD_P}
`;
}

/**
 * Stack: px py fP fConj λ inv → folded.
 * Witness inv must satisfy inv · (px==0 ? py : px) ≡ 1 (mod M31).
 * foldPair: (fP+fConj)/2 + λ · (fP−fConj)/2 · inv.
 */
export const FOLD_PAIR_ASM = `
OP_5 OP_PICK
OP_0 OP_NUMEQUAL
OP_IF
  OP_4 OP_PICK
OP_ELSE
  OP_5 OP_PICK
OP_ENDIF
OP_OVER
${M31_MUL}
<1>
OP_NUMEQUALVERIFY
OP_TOALTSTACK
OP_2 OP_PICK
OP_2 OP_PICK
${M31_ADD}
<${M31_TWO_INV}>
${M31_MUL}
OP_3 OP_PICK
OP_3 OP_PICK
${M31_SUB}
<${M31_TWO_INV}>
${M31_MUL}
OP_FROMALTSTACK
${M31_MUL}
OP_2 OP_PICK
${M31_MUL}
${M31_ADD}
OP_NIP
OP_NIP
OP_NIP
OP_NIP
OP_NIP
`;

function smulInvokeAsm(): string {
  return SCALAR_MUL_FAST.split(CIRCLE_ADD).join("<0> OP_INVOKE");
}

export function foldDefinesAsm(): string {
  return [
    defineFn(CIRCLE_ADD, 0, "cadd"),
    defineFn(smulInvokeAsm(), 1, "smul"),
    defineFn(FOLD_PAIR_ASM, 2, "fold"),
    defineFn(lambdaFromPackedAsm(), 3, "lambda"),
  ].join("\n");
}

/** Stack: a → −a (mod M31). */
function m31NegAsm(): string {
  return `OP_0 OP_SWAP\n${M31_SUB}`;
}

/**
 * Layer-0 domain point: [idx % (FRI_N/2)] · G1024.
 * Stack in: packed built idxBlob q. Stack out: … Px Py.
 */
function layer0PointAsm(): string {
  return `
OP_1 OP_PICK
OP_1 OP_PICK
<2> OP_MUL
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_N >> 1}>
OP_MOD
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<1> OP_INVOKE
`;
}

/**
 * P_r → P_{r+1} by doubling, then (−x,−y) when the next lo bit is set.
 * Matches [idx % (FRI_N>>(r+1))] · 2^r G without a fresh 10-bit scalar mul.
 * Stack in: packed built idxBlob q Px Py (P_{r-1}). Stack out: … P_r x y.
 * `r` is the layer being entered (r ≥ 1).
 */
function advancePointAsm(r: number): string {
  return `
OP_2DUP
<0> OP_INVOKE
OP_3 OP_PICK
OP_3 OP_PICK
<2> OP_MUL
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_N >> r}>
OP_MOD
<${FRI_N >> (r + 1)}>
OP_GREATERTHANOREQUAL
OP_IF
  ${m31NegAsm()}
  OP_SWAP
  ${m31NegAsm()}
  OP_SWAP
OP_ENDIF
`;
}

const PAIR_GROUP_BYTES = COMMITTED_LAYERS * 8;
const INV_GROUP_BYTES = COMMITTED_LAYERS * 4;

/**
 * extraOnTop: items above `blob packed cq idx q`.
 * `cq` is pair group || inv group, so the pair half is still at offset layer×8.
 */
function extractPairAsm(layer: number, extraOnTop = 0): string {
  const cqPick = 2 + extraOnTop;
  return `
<${cqPick}>
OP_PICK
<${layer * 8}>
OP_SPLIT
OP_NIP
<4> OP_SPLIT
OP_TOALTSTACK
OP_BIN2NUM
OP_FROMALTSTACK
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
`;
}

/** extraOnTop: items above `blob packed cq idx q`. Inv felt is at cq[56 + layer×4]. */
function extractInvAsm(layer: number, extraOnTop = 0): string {
  const cqPick = 2 + extraOnTop;
  return `
<${cqPick}>
OP_PICK
<${PAIR_GROUP_BYTES + layer * 4}>
OP_SPLIT
OP_NIP
<4>
OP_SPLIT
OP_DROP
OP_BIN2NUM
`;
}

function nextPairCheckAsm(r: number): string {
  return `
${extractPairAsm(r + 1, 1)}
OP_2 OP_PICK
OP_2 OP_PICK
OP_NUMEQUAL
OP_3 OP_PICK
OP_2 OP_PICK
OP_NUMEQUAL
OP_BOOLOR
OP_VERIFY
OP_2DROP
OP_DROP
`;
}

function finalCheckAsm(): string {
  return `
OP_2 OP_PICK
OP_2 OP_PICK
<2> OP_MUL
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_FINAL}> OP_MOD
OP_5 OP_PICK
OP_SWAP
<4> OP_MUL
<${AIR_OFF_FINAL}> OP_ADD
OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_NUMEQUALVERIFY
`;
}

function layerFoldAsm(r: number): string {
  const restore = r === 0 ? "" : "OP_FROMALTSTACK\nOP_FROMALTSTACK";
  const point = r === 0 ? layer0PointAsm() : advancePointAsm(r);
  const save =
    r + 1 < COMMITTED_LAYERS ? "OP_2DUP\nOP_TOALTSTACK\nOP_TOALTSTACK" : "";
  return `
${restore}
${point}
${save}
${extractPairAsm(r, 2)}
OP_7 OP_PICK
<${r}>
<3> OP_INVOKE
OP_NIP
${extractInvAsm(r, 5)}
<2> OP_INVOKE
${r + 1 < COMMITTED_LAYERS ? nextPairCheckAsm(r) : finalCheckAsm()}
`;
}

/**
 * Stack: invs blob packed idx q. `invs` sits under blob so OP_7/OP_3 picks stay valid.
 * Each iteration copies the 56-byte pair group and concatenates the 28-byte inv group.
 */
export function foldQueriesAsm(nFold: number, _queryBase = 0): string {
  const pairBytes = PAIR_GROUP_BYTES;
  const invBytes = INV_GROUP_BYTES;
  const layers = Array.from({ length: COMMITTED_LAYERS }, (_, r) => layerFoldAsm(r)).join("\n");
  return `
<0>
OP_BEGIN
  OP_DUP
  <${nFold}>
  OP_LESSTHAN
  OP_IF
    OP_3 OP_PICK
    OP_OVER
    <${pairBytes}>
    OP_MUL
    OP_SPLIT
    OP_NIP
    <${pairBytes}>
    OP_SPLIT
    OP_DROP
    OP_DEPTH
    OP_1SUB
    OP_PICK
    OP_2 OP_PICK
    <${invBytes}>
    OP_MUL
    OP_SPLIT
    OP_NIP
    <${invBytes}>
    OP_SPLIT
    OP_DROP
    OP_CAT
    OP_SWAP
    OP_ROT
    OP_SWAP
    ${layers}
    OP_ROT
    OP_DROP
    OP_1ADD
    OP_0
  OP_ELSE
    OP_DROP
    OP_1
  OP_ENDIF
OP_UNTIL
OP_2DROP
OP_2DROP
`;
}

export function compileM31InvLock(expected: bigint): Uint8Array {
  const bin = cashAssemblyToBin(`${M31_INV}\n${pushFelt(expected)}\nOP_NUMEQUAL`);
  if (typeof bin === "string") throw new Error(`m31-inv: ${bin}`);
  return bin;
}

export function compileFoldPairLock(expected: bigint): Uint8Array {
  const asm = `
${FOLD_PAIR_ASM}
${pushFelt(expected)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`fold-pair: ${bin}`);
  return bin;
}

export function compileLambdaLock(expected: bigint): Uint8Array {
  const asm = `
${lambdaFromPackedAsm()}
${pushFelt(expected)}
OP_NUMEQUAL
`;
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`lambda: ${bin}`);
  return bin;
}
