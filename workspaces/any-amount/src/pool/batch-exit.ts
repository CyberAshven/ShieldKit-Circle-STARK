/**
 * Opt-in batch exit: wait a CSPRNG delay, then group ready claims into one
 * CashFusion-*shaped* multi-P2PKH output list (shuffled). Not the CashFusion
 * Pedersen / blind-Schnorr / OP_RETURN FUSE protocol.
 *
 * Timing privacy is the shipped increment (request time ↛ chain time).
 * One-successor N-payout (sum of P2PKH = abs-net) is a later lock; today's
 * redeem still binds a single HASH256 payout at output 1.
 */

/** Default window. Knobs, not magic: CLI `--batch-min` / `--batch-max` override. */
export const BATCH_EXIT_MIN_SECONDS_DEFAULT = 30;
export const BATCH_EXIT_MAX_SECONDS_DEFAULT = 180;
/** Inclusive floor/ceiling for the knobs so a later dapp can retune safely. */
export const BATCH_EXIT_KNOB_FLOOR_SECONDS = 0;
export const BATCH_EXIT_KNOB_CEILING_SECONDS = 86_400;

export type BatchExitWindow = {
  minSeconds: number;
  maxSeconds: number;
};

export type BatchExitClaim = {
  id: string;
  sats: bigint;
  lockingBytecode: Uint8Array;
  enqueuedAtMs: number;
  readyAtMs: number;
};

export type FusionPayout = {
  sats: bigint;
  lockingBytecode: Uint8Array;
};

export type FusionBatchSketch = {
  version: 2;
  outputCount: number;
  totalSats: string;
  shuffled: true;
  shape: "cashfusion-like-multi-p2pkh";
  /** We do not emit OP_RETURN FUSE or speak CashFusion session hashes. */
  protocol: "not-cashfusion-fuse";
};

export function parseBatchWindow(minSeconds: number, maxSeconds: number): BatchExitWindow {
  if (!Number.isInteger(minSeconds) || !Number.isInteger(maxSeconds)) {
    throw new Error("batch-exit window must be integer seconds");
  }
  if (minSeconds < BATCH_EXIT_KNOB_FLOOR_SECONDS || maxSeconds > BATCH_EXIT_KNOB_CEILING_SECONDS) {
    throw new Error(
      `batch-exit window must be in [${BATCH_EXIT_KNOB_FLOOR_SECONDS}, ${BATCH_EXIT_KNOB_CEILING_SECONDS}] seconds`,
    );
  }
  if (minSeconds > maxSeconds) {
    throw new Error(`batch-exit min ${minSeconds} > max ${maxSeconds}`);
  }
  return { minSeconds, maxSeconds };
}

export function defaultBatchWindow(): BatchExitWindow {
  return parseBatchWindow(BATCH_EXIT_MIN_SECONDS_DEFAULT, BATCH_EXIT_MAX_SECONDS_DEFAULT);
}

/** Map CSPRNG bytes onto [min, max] inclusive. 8-byte modulus bias is negligible for these spans. */
export function uniformInt(min: number, max: number, entropy: Uint8Array): number {
  if (!Number.isInteger(min) || !Number.isInteger(max)) throw new Error("uniformInt bounds must be integers");
  if (min > max) throw new Error("uniformInt min > max");
  if (entropy.length === 0) throw new Error("uniformInt needs entropy");
  const span = max - min + 1;
  if (span === 1) return min;
  let acc = 0n;
  for (const b of entropy) acc = (acc << 8n) | BigInt(b);
  return min + Number(acc % BigInt(span));
}

export function sampleBatchWaitSeconds(
  window: BatchExitWindow = defaultBatchWindow(),
  entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(8)),
): number {
  return uniformInt(window.minSeconds, window.maxSeconds, entropy);
}

export function randomClaimId(entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(16))): string {
  return Buffer.from(entropy).toString("hex");
}

export function makeBatchExitClaim(args: {
  sats: bigint;
  lockingBytecode: Uint8Array;
  waitSeconds: number;
  nowMs?: number;
  id?: string;
}): BatchExitClaim {
  if (args.sats <= 0n) throw new Error("batch-exit claim sats must be positive");
  if (args.lockingBytecode.length === 0) throw new Error("batch-exit claim needs a locking bytecode");
  if (!Number.isInteger(args.waitSeconds) || args.waitSeconds < 0) {
    throw new Error("batch-exit waitSeconds must be a non-negative integer");
  }
  const nowMs = args.nowMs ?? Date.now();
  return {
    id: args.id ?? randomClaimId(),
    sats: args.sats,
    lockingBytecode: args.lockingBytecode,
    enqueuedAtMs: nowMs,
    readyAtMs: nowMs + args.waitSeconds * 1000,
  };
}

export function claimsReadyAt(claims: readonly BatchExitClaim[], nowMs: number): BatchExitClaim[] {
  return claims.filter((c) => c.readyAtMs <= nowMs);
}

function entropyAt(entropy: Uint8Array, offset: number, width: number): Uint8Array {
  const out = new Uint8Array(width);
  for (let i = 0; i < width; i += 1) out[i] = entropy[(offset + i) % entropy.length]!;
  return out;
}

/** Fisher–Yates with supplied entropy (CSPRNG in production). */
export function shuffleInPlace<T>(items: T[], entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32))): T[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = uniformInt(0, i, entropyAt(entropy, i * 8, 8));
    const tmp = items[i]!;
    items[i] = items[j]!;
    items[j] = tmp;
  }
  return items;
}

/**
 * CashFusion-shaped outputs: shuffled P2PKH (or any locking bytecode) list.
 * Any-amount means values are *not* equalized — equal outputs would be a
 * later denomination round, not this profile.
 */
export function shapeFusionOutputs(
  claims: readonly BatchExitClaim[],
  entropy: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): FusionPayout[] {
  const out: FusionPayout[] = claims.map((c) => ({
    sats: c.sats,
    lockingBytecode: c.lockingBytecode,
  }));
  shuffleInPlace(out, entropy);
  return out;
}

export function fusionBatchSketch(outputs: readonly FusionPayout[]): FusionBatchSketch {
  const total = outputs.reduce((n, o) => n + o.sats, 0n);
  return {
    version: 2,
    outputCount: outputs.length,
    totalSats: total.toString(),
    shuffled: true,
    shape: "cashfusion-like-multi-p2pkh",
    protocol: "not-cashfusion-fuse",
  };
}

export type CountdownIo = {
  sleep?: (ms: number) => Promise<void>;
  write?: (text: string) => void;
};

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/** One-second CLI countdown. Inject clock/sleep in tests. Seconds=0 is a no-op write. */
export async function runBatchExitCountdown(seconds: number, io: CountdownIo = {}): Promise<void> {
  if (!Number.isInteger(seconds) || seconds < 0) throw new Error("countdown seconds must be a non-negative integer");
  const write = io.write ?? ((text: string) => process.stderr.write(text));
  const sleep = io.sleep ?? defaultSleep;
  if (seconds === 0) {
    write("batch-exit countdown 0s remaining\n");
    return;
  }
  for (let left = seconds; left > 0; left -= 1) {
    write(`\rbatch-exit countdown ${left}s remaining   `);
    await sleep(1000);
  }
  write("\rbatch-exit countdown 0s remaining   \n");
}

export type BatchExitPlan = {
  window: BatchExitWindow;
  waitSeconds: number;
  claim: BatchExitClaim;
  ready: BatchExitClaim[];
  outputs: FusionPayout[];
  sketch: FusionBatchSketch;
};

export function planBatchExit(args: {
  sats: bigint;
  lockingBytecode: Uint8Array;
  queued?: readonly BatchExitClaim[];
  window?: BatchExitWindow;
  entropy?: Uint8Array;
  nowMs?: number;
  waitSeconds?: number;
}): BatchExitPlan {
  const window = args.window ?? defaultBatchWindow();
  const entropy = args.entropy ?? crypto.getRandomValues(new Uint8Array(32));
  const waitSeconds = args.waitSeconds ?? sampleBatchWaitSeconds(window, entropy.subarray(0, 8));
  const nowMs = args.nowMs ?? Date.now();
  const claim = makeBatchExitClaim({
    sats: args.sats,
    lockingBytecode: args.lockingBytecode,
    waitSeconds,
    nowMs,
    id: randomClaimId(entropy.subarray(8, 24)),
  });
  const queued = [...(args.queued ?? []), claim];
  const ready = claimsReadyAt(queued, claim.readyAtMs);
  const outputs = shapeFusionOutputs(ready, entropy);
  return { window, waitSeconds, claim, ready, outputs, sketch: fusionBatchSketch(outputs) };
}
