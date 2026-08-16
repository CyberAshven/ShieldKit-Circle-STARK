/**
 * On-chain Circle FRI fold (2024/278 foldPair) for the 2026 VM.
 * Function indices used by the production FRI kernel:
 *   0 CIRCLE_ADD   1 SCALAR_MUL   2 M31_INV   3 FOLD_PAIR
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

/** 8-byte big-endian → integer, then mod M31 (hashToM31). */
export const BE8_MOD_P = `
<0>
OP_SWAP
${Array.from({ length: 8 }, () => `
OP_1 OP_SPLIT
OP_ROT
<256> OP_MUL
OP_ROT
<0x00> OP_CAT
OP_BIN2NUM
OP_ADD
OP_SWAP
`).join("\n")}
OP_DROP
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
 * Stack: px py fP fConj λ → folded.
 * foldPair: (fP+fConj)/2 + λ · (fP−fConj)/2 · inv(px or py).
 */
export const FOLD_PAIR_ASM = `
OP_4 OP_PICK
OP_0 OP_NUMEQUAL
OP_IF
  OP_3 OP_PICK
OP_ELSE
  OP_4 OP_PICK
OP_ENDIF
${M31_INV}
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
  ].join("\n");
}

/** extraOnTop: items above `packed built idx q`. */
function extractPairAsm(layer: number, extraOnTop = 0): string {
  const qPick = extraOnTop === 0 ? "OP_DUP" : `<${extraOnTop}> OP_PICK`;
  const builtPick = 3 + extraOnTop;
  return `
${qPick}
<${COMMITTED_LAYERS}> OP_MUL
<${layer}> OP_ADD
<8> OP_MUL
<${builtPick}> OP_PICK
OP_SWAP
OP_SPLIT OP_NIP
<4> OP_SPLIT
OP_TOALTSTACK
OP_BIN2NUM
OP_FROMALTSTACK
<4> OP_SPLIT OP_DROP
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
OP_4 OP_PICK
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
  const doubles =
    r === 0 ? "" : Array.from({ length: r }, () => "OP_2DUP\n<0> OP_INVOKE").join("\n");
  return `
OP_1 OP_PICK
OP_1 OP_PICK
<2> OP_MUL
OP_SPLIT OP_NIP
<2> OP_SPLIT OP_DROP
${BE16_UNSIGNED}
<${FRI_N >> (r + 1)}>
OP_MOD
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<1> OP_INVOKE
${doubles}
${extractPairAsm(r, 2)}
OP_7 OP_PICK
<${r}>
${lambdaFromPackedAsm()}
OP_NIP
<2> OP_INVOKE
${r + 1 < COMMITTED_LAYERS ? nextPairCheckAsm(r) : finalCheckAsm()}
`;
}

/** Stack: packed builtPairs idxBlob → (consumed). Every query is folded. */
export function foldQueriesAsm(): string {
  const layers = Array.from({ length: COMMITTED_LAYERS }, (_, r) => layerFoldAsm(r)).join("\n");
  return `
OP_DUP
OP_SIZE
OP_NIP
<2> OP_DIV
OP_2 OP_PICK
OP_SIZE
OP_NIP
OP_OVER
<${COMMITTED_LAYERS * 8}>
OP_MUL
OP_NUMEQUALVERIFY
<0>
OP_BEGIN
  OP_DUP
  OP_2 OP_PICK
  OP_LESSTHAN
  OP_IF
    ${layers}
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
