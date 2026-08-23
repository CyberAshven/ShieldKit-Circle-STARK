/**
 * Circle FRI parameters + ethSTARK-style conjectural accounting (ePrint 2021/582).
 * Composition is FRI'd at rate 1/B (quotient degree < TRACE_LEN, LDE = TRACE*BLOWUP).
 *
 * bits = queries * log2(blowup) + grind   (rate 1/B)
 * bits = queries * (log2(blowup)-1) + grind  (rate 2/B)
 *
 * Floor 100, target 128 **query-conjecture bits** (ethSTARK toy, rate 2/B).
 * Not Stwo QM31 field+query bits. M31 is 31-bit; SZ on TRACE 64 is tens of bits.
 * The old n=32 / q=8 / sound:false bench is a fail.
 */
export const M31_P = 2147483647n;
/** log2(p+1) ≈ 31. FRI here is base-field M31, not QM31. */
export const FIELD_BIT_LENGTH = 31;
/** False: this vk is not Stwo's extension-field FRI. */
export const STWO_FIELD_PARITY = false;

export const TRACE_LEN = 64;
export const BLOWUP = 16;
export const FRI_N = TRACE_LEN * BLOWUP; // 1024
export const FRI_LOG_N = 10;
export const FRI_QUERIES = 36;
export const GRIND_BITS = 20;
export const FRI_FINAL = 8;
export const FRI_VERSION = 9;
export const COMMITTED_LAYERS = Math.log2(FRI_N / FRI_FINAL); // 7
/** Cubic merkle mix ⇒ deg(C) ~ 3T, Q = C/Z_H ⇒ rate 2/B. */
export const RATE: "2/B" = "2/B";
export const SOUNDNESS_FLOOR = 100;
export const SOUNDNESS_TARGET = 128;

export const VK_ID = `circle-fri-m31-t${TRACE_LEN}-b${BLOWUP}-q${FRI_QUERIES}-g${GRIND_BITS}-fri${FRI_VERSION}`;

export function log2pow2(n: number): number {
  if (n < 2 || (n & (n - 1)) !== 0) throw new Error(`not a power of two: ${n}`);
  return Math.log2(n);
}

export function conjecturalBits(args: {
  queries: number;
  blowup: number;
  grind: number;
  rate: "1/B" | "2/B";
}): number {
  const logB = log2pow2(args.blowup);
  const per = args.rate === "1/B" ? logB : logB - 1;
  return args.queries * per + args.grind;
}

export const CONJECTURAL_BITS = conjecturalBits({
  queries: FRI_QUERIES,
  blowup: BLOWUP,
  grind: GRIND_BITS,
  rate: RATE,
});

export function assertSoundParams(): void {
  if ((FRI_N as number) === 32 && (FRI_QUERIES as number) === 8) {
    throw new Error("refusing unsound bench params n=32 q=8");
  }
  if (CONJECTURAL_BITS < SOUNDNESS_FLOOR) {
    throw new Error(`soundness ${CONJECTURAL_BITS} < floor ${SOUNDNESS_FLOOR}`);
  }
  if (TRACE_LEN * BLOWUP !== FRI_N) {
    throw new Error("FRI_N must equal TRACE_LEN * BLOWUP");
  }
  if (FRI_N >> FRI_LOG_N !== 1) throw new Error("FRI_LOG_N mismatch");
}

assertSoundParams();
