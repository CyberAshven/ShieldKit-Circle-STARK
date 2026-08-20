/**
 * BCH size envelopes. Relay policy ≠ consensus.
 * One tx: standard 100 KB, consensus 1 MB.
 * Chained / anchored txs (standard or not) can go much larger (user: 32 MB).
 * After Velma, **both** script/redeem size **and** input bytecode are 10 KB
 * (the old ~1650-byte input-bytecode box is gone). Chunk the verifier across inputs.
 * Chipnet + a miner can include nonstandard txs. Never mainnet from this lab.
 */
import { concatBytes } from "../pool/bytes.ts";

export const RELAY_STANDARD_TX_BYTES = 100_000;
export const CONSENSUS_TX_BYTES = 1_000_000;
export const CHAINED_TX_BYTES = 32_000_000;
export const UNLOCKING_MAX_BYTES = 10_000;
export const DUST_SATS = 546n;
/** Public Chipnet relay is 1 sat/byte. 100k covers the ~80–95 KB standard spend. */
export const STANDARD_SUCCESSOR_FEE_SATS = 100_000n;
/** Consensus (~270–480 KB) needs a matching fee or electrum/BCHN returns code 66. */
export const CONSENSUS_SUCCESSOR_FEE_SATS = 400_000n;

export function successorFeeSats(envelope: TxEnvelope = "standard"): bigint {
  return envelope === "consensus" ? CONSENSUS_SUCCESSOR_FEE_SATS : STANDARD_SUCCESSOR_FEE_SATS;
}

/** Fee coin = miner/covenant fee + dust change. Leftover treasury is a separate output. */
export function successorFeeCoinSats(envelope: TxEnvelope = "standard"): bigint {
  return successorFeeSats(envelope) + DUST_SATS;
}
/**
 * High-index unique-orbit FS (consensus slots/folds ≥ 6) needs a dummy prefix
 * so 2026 densityControlLength = 41+unlocking stays above ~800×ops.
 * Standard 100 KB path uses slot/fold 0–5 unpadded beyond one dummy byte.
 */
export const KERNEL_UNLOCK_PAD_HIGH = 6_000;

export type TxEnvelope = "standard" | "consensus";

export function txLimitBytes(envelope: TxEnvelope): number {
  return envelope === "consensus" ? CONSENSUS_TX_BYTES : RELAY_STANDARD_TX_BYTES;
}

function pushDummy(n: number): Uint8Array {
  const data = new Uint8Array(Math.max(1, n));
  data.fill(0x22);
  if (data.length <= 75) return Uint8Array.of(data.length, ...data);
  if (data.length <= 255) return Uint8Array.of(0x4c, data.length, ...data);
  return Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff, ...data);
}

/**
 * Prepend a dummy stack item so operation-cost density has headroom.
 * The matching redeem must `OP_DROP` this item (P2SH32 last push is still the redeem).
 */
export function densityPadUnlocking(rest: Uint8Array, target: number): Uint8Array {
  const t = Math.max(rest.length + 1, Math.min(UNLOCKING_MAX_BYTES, Math.floor(target)));
  const fill = (n: number): Uint8Array => concatBytes(pushDummy(n), rest);
  let out = fill(1);
  if (out.length < t) {
    for (const overhead of [1, 2, 3]) {
      out = fill(Math.max(1, t - rest.length - overhead));
      if (out.length >= t) break;
    }
  }
  if (out.length > UNLOCKING_MAX_BYTES) {
    throw new Error(`unlocking ${out.length} > ${UNLOCKING_MAX_BYTES}`);
  }
  return out;
}
