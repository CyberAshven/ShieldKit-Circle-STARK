/**
 * On-chain R_on(i) + Z(i)·R_off(i). Slot kernels check (qTable−R)·Z against
 * C(z) of the algebraicC residual interpolant (FRI_VERSION 9) — not nTable.
 * Honest C is the zero polynomial.
 */
import { cashAssemblyToBin } from "@bitauth/libauth";
import {
  FRI_OPEN_MASK_TAG,
  OPEN_MASK_DEGREE,
  OPEN_MASK_OFF_DEGREE,
  VIEWING_TAG,
} from "../backends/circle/witness-mask.ts";
import { M31_ADD, M31_MUL, M31_SUB } from "./m31-asm.ts";
import {
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  G1024,
  SCALAR_MUL_FAST,
  VANISH_XS,
  fsIndexSlotAsm,
  packedMagicAsm,
  vanishingUnrolledAsm,
} from "./air-cqz.ts";

function hexPush(data: Uint8Array): string {
  return `<0x${Buffer.from(data).toString("hex")}>`;
}

function pushFelt(n: bigint): string {
  return `<${n.toString()}>`;
}

function defineFn(asm: string, index: number, name: string): string {
  const body = cashAssemblyToBin(asm);
  if (typeof body === "string") throw new Error(`${name}: ${body}`);
  return `${hexPush(body)}\n<${index}>\nOP_DEFINE`;
}

/** SHA256 blob → M31 felt (first 4 bytes, high bit cleared). */
export const FELT_FROM_SHA256 = `
OP_SHA256
<4> OP_SPLIT OP_DROP
<3> OP_SPLIT
<0x7f> OP_AND
OP_CAT
OP_BIN2NUM
<2147483647> OP_MOD
`;

/**
 * Horner eval of the PRF mask poly. Stack: prefix x → R.
 * prefix = VIEWING_TAG || commit || FRI_OPEN_MASK_TAG.
 */
export function evalMaskPolyAsm(stream: 0 | 1, degree: number): string {
  const lines: string[] = [`<0>`, `<1>`];
  for (let k = 0; k <= degree; k += 1) {
    lines.push(
      `OP_3 OP_PICK`,
      hexPush(Uint8Array.of(stream, k)),
      `OP_CAT`,
      FELT_FROM_SHA256,
      `OP_OVER`,
      M31_MUL,
      `OP_ROT`,
      M31_ADD,
      `OP_SWAP`,
    );
    if (k < degree) lines.push(`OP_2 OP_PICK`, M31_MUL);
  }
  lines.push(`OP_DROP`, `OP_NIP`, `OP_NIP`);
  return lines.join("\n");
}

/**
 * Stack: packed i Z → packed R.
 * R = R_on(i) + Z · R_off(i), x = i+1.
 */
export function openingMaskAtPackedAsm(): string {
  return `
OP_TOALTSTACK
OP_SWAP
OP_DUP
<${AIR_OFF_OPEN_MASK}> OP_SPLIT OP_NIP
<32> OP_SPLIT OP_DROP
${hexPush(VIEWING_TAG)} OP_SWAP OP_CAT
${hexPush(FRI_OPEN_MASK_TAG)} OP_CAT
OP_ROT
<1> OP_ADD
OP_2DUP
${evalMaskPolyAsm(0, OPEN_MASK_DEGREE)}
OP_TOALTSTACK
${evalMaskPolyAsm(1, OPEN_MASK_OFF_DEGREE)}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_ROT
${M31_MUL}
${M31_ADD}
`;
}

/**
 * Requires OP_DEFINE 2=fast, 3=vanish.
 * Stack: packed i → packed i N Z
 * FRI_VERSION 9: N = C(z) of the algebraicC residual interpolant.
 * Honest residuals vanish ⇒ C is the zero polynomial ⇒ N = 0.
 */
export function nAndZFromPackedIAsm(): string {
  return `
OP_DUP
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<2> OP_INVOKE
OP_OVER
<3> OP_INVOKE
OP_TOALTSTACK
OP_2DROP
<0>
OP_FROMALTSTACK
`;
}

function slotDefines(): string {
  return `
${defineFn(SCALAR_MUL_FAST, 2, "fast")}
${defineFn(vanishingUnrolledAsm(VANISH_XS), 3, "vanish")}
`;
}

/**
 * One FS slot: (qTable[slot] − R(i)) · Z([i]G) equals C(z).
 * Honest C = 0 (FRI_VERSION 9 residual interpolant). Independent of nTable.
 */
export function slotRCqzAsm(slot = 0): string {
  const qOff = AIR_OFF_QTABLE + slot * 4;
  return `
${slotDefines()}
${packedMagicAsm()}
${fsIndexSlotAsm(slot)}
${nAndZFromPackedIAsm()}
OP_DUP
OP_TOALTSTACK
OP_SWAP
OP_TOALTSTACK
${openingMaskAtPackedAsm()}
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_3 OP_PICK
<${qOff}> OP_SPLIT OP_NIP
<4> OP_SPLIT OP_DROP
OP_BIN2NUM
OP_3 OP_PICK
${M31_SUB}
OP_1 OP_PICK
OP_0
OP_NUMEQUAL
OP_IF
  OP_0
  OP_NUMEQUALVERIFY
  OP_1 OP_PICK
  OP_0
  OP_NUMEQUALVERIFY
  OP_2DROP
  OP_2DROP
OP_ELSE
  OP_1 OP_PICK
  ${M31_MUL}
  OP_2 OP_PICK
  OP_NUMEQUALVERIFY
  OP_2DROP
  OP_2DROP
OP_ENDIF
`;
}

function compileOrThrow(asm: string, name: string): Uint8Array {
  const bin = cashAssemblyToBin(asm);
  if (typeof bin === "string") throw new Error(`${name}: ${bin}`);
  return bin;
}

/** Isolated R at FS slot 0. Unlocking: packed. Leaves true iff R matches `expected`. */
export function compileRAtSlot0Lock(expected: bigint): Uint8Array {
  return compileOrThrow(
    `
${slotDefines()}
${packedMagicAsm()}
${fsIndexSlotAsm(0)}
OP_DUP
${pushFelt(G1024.x)}
${pushFelt(G1024.y)}
<2> OP_INVOKE
OP_OVER
<3> OP_INVOKE
OP_TOALTSTACK
OP_2DROP
OP_FROMALTSTACK
${openingMaskAtPackedAsm()}
OP_NIP
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "r-slot0",
  );
}

/** Isolated N = C(z) at FS slot 0. Unlocking: packed. Honest C(z) = 0. */
export function compileNFromTSlot0Lock(expected: bigint): Uint8Array {
  return compileOrThrow(
    `
${slotDefines()}
${packedMagicAsm()}
${fsIndexSlotAsm(0)}
${nAndZFromPackedIAsm()}
OP_DROP
OP_NIP
OP_NIP
${pushFelt(expected)}
OP_NUMEQUAL
`,
    "n-slot0",
  );
}

export function compileSlotRCqzLock(slot = 0): Uint8Array {
  return compileOrThrow(`${slotRCqzAsm(slot)}\nOP_1`, `slot-${slot}-r-cqz`);
}
