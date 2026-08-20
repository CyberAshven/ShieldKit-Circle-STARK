import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BATCH_EXIT_KNOB_CEILING_SECONDS,
  BATCH_EXIT_KNOB_FLOOR_SECONDS,
  BATCH_EXIT_MAX_SECONDS_DEFAULT,
  BATCH_EXIT_MIN_SECONDS_DEFAULT,
  claimsReadyAt,
  defaultBatchWindow,
  fusionBatchSketch,
  makeBatchExitClaim,
  parseBatchWindow,
  planBatchExit,
  runBatchExitCountdown,
  sampleBatchWaitSeconds,
  shapeFusionOutputs,
  shuffleInPlace,
  uniformInt,
} from "../src/pool/batch-exit.ts";
import { LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";

function lock(fill: number): Uint8Array {
  const out = new Uint8Array(LAB_PAYOUT_LOCKING);
  out[3] = fill;
  return out;
}

describe("opt-in batch exit", () => {
  it("default window is 30–180s and knobs reject inverted / out-of-range", () => {
    const w = defaultBatchWindow();
    assert.equal(w.minSeconds, 30);
    assert.equal(w.maxSeconds, 180);
    assert.equal(BATCH_EXIT_MIN_SECONDS_DEFAULT, 30);
    assert.equal(BATCH_EXIT_MAX_SECONDS_DEFAULT, 180);
    assert.equal(BATCH_EXIT_KNOB_FLOOR_SECONDS, 0);
    assert.equal(BATCH_EXIT_KNOB_CEILING_SECONDS, 86_400);
    assert.deepEqual(parseBatchWindow(0, 0), { minSeconds: 0, maxSeconds: 0 });
    assert.throws(() => parseBatchWindow(180, 30), /min 180 > max 30/);
    assert.throws(() => parseBatchWindow(-1, 30), /must be in/);
    assert.throws(() => parseBatchWindow(0, 86_401), /must be in/);
  });

  it("CSPRNG wait stays inside the knob window; same entropy is deterministic", () => {
    const window = parseBatchWindow(30, 180);
    const entropy = Uint8Array.of(0, 1, 2, 3, 4, 5, 6, 7);
    const a = sampleBatchWaitSeconds(window, entropy);
    const b = sampleBatchWaitSeconds(window, entropy);
    assert.equal(a, b);
    assert.ok(a >= 30 && a <= 180);
    const seen = new Set<number>();
    for (let i = 0; i < 64; i += 1) {
      const e = crypto.getRandomValues(new Uint8Array(8));
      const v = sampleBatchWaitSeconds(window, e);
      assert.ok(v >= 30 && v <= 180, `out of window: ${v}`);
      seen.add(v);
    }
    assert.ok(seen.size > 1, "entropy should not collapse to one wait");
    assert.equal(uniformInt(7, 7, entropy), 7);
  });

  it("ready claims group into a shuffled CashFusion-shaped multi-output, not FUSE", () => {
    const now = 1_000_000;
    const a = makeBatchExitClaim({
      sats: 1_000n,
      lockingBytecode: lock(1),
      waitSeconds: 30,
      nowMs: now,
      id: "aa",
    });
    const b = makeBatchExitClaim({
      sats: 2_000n,
      lockingBytecode: lock(2),
      waitSeconds: 0,
      nowMs: now + 30_000,
      id: "bb",
    });
    assert.equal(a.readyAtMs, now + 30_000);
    const ready = claimsReadyAt([a, b], now + 30_000);
    assert.equal(ready.length, 2);
    const entropy = new Uint8Array(32).fill(9);
    const outputs = shapeFusionOutputs(ready, entropy);
    assert.equal(outputs.length, 2);
    const sats = outputs.map((o) => o.sats).sort((x, y) => (x < y ? -1 : 1));
    assert.deepEqual(sats, [1_000n, 2_000n]);
    const sketch = fusionBatchSketch(outputs);
    assert.equal(sketch.version, 2);
    assert.equal(sketch.outputCount, 2);
    assert.equal(sketch.totalSats, "3000");
    assert.equal(sketch.shape, "cashfusion-like-multi-p2pkh");
    assert.equal(sketch.protocol, "not-cashfusion-fuse");
    const items = [1, 2, 3, 4];
    shuffleInPlace(items, entropy);
    assert.deepEqual([...items].sort(), [1, 2, 3, 4]);
  });

  it("planBatchExit records knobs, wait, and a fusion sketch", () => {
    const plan = planBatchExit({
      sats: 5_000n,
      lockingBytecode: LAB_PAYOUT_LOCKING,
      window: parseBatchWindow(30, 180),
      entropy: new Uint8Array(32).fill(3),
      nowMs: 0,
    });
    assert.ok(plan.waitSeconds >= 30 && plan.waitSeconds <= 180);
    assert.equal(plan.claim.sats, 5_000n);
    assert.equal(plan.ready.length, 1);
    assert.equal(plan.outputs.length, 1);
    assert.equal(plan.sketch.outputCount, 1);
  });

  it("countdown writes remaining seconds and honors injected sleep", async () => {
    const writes: string[] = [];
    const sleeps: number[] = [];
    await runBatchExitCountdown(3, {
      write: (t) => writes.push(t),
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    assert.deepEqual(sleeps, [1000, 1000, 1000]);
    assert.match(writes[0] ?? "", /3s remaining/);
    assert.match(writes.at(-1) ?? "", /0s remaining/);
    const zero: string[] = [];
    await runBatchExitCountdown(0, { write: (t) => zero.push(t) });
    assert.match(zero.join(""), /0s remaining/);
  });

  it("CLI help and knobs exist; lock still binds one HASH256 payout", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const cli = readFileSync(join(here, "..", "src", "cli.ts"), "utf8");
    assert.match(cli, /--batch-exit/);
    assert.match(cli, /--batch-min/);
    assert.match(cli, /--batch-max/);
    assert.match(cli, /runBatchExitCountdown/);
    const lock = readFileSync(join(here, "..", "src", "chain", "covenant-p2s.ts"), "utf8");
    assert.match(lock, /OP_1 OP_OUTPUTBYTECODE/);
    assert.match(lock, /OP_HASH256/);
    assert.match(lock, /OP_1 OP_OUTPUTVALUE/);
  });
});
