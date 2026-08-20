import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BATCH_EXIT_KNOB_CEILING_SECONDS,
  BATCH_EXIT_KNOB_FLOOR_SECONDS,
  BATCH_EXIT_WINDOW_SECONDS_DEFAULT,
  decodeRound,
  encodeRound,
  fusionBatchSketch,
  joinRound,
  parseBatchWindowSeconds,
  planBatchExit,
  remainingSeconds,
  roundIsOpen,
  runBatchExitCountdown,
  shapeFusionOutputs,
  shuffleInPlace,
} from "../src/pool/batch-exit.ts";
import { LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";

function lock(fill: number): Uint8Array {
  const out = new Uint8Array(LAB_PAYOUT_LOCKING);
  out[3] = fill;
  return out;
}

describe("opt-in batch exit", () => {
  it("one shared window default 180s; rejects out-of-range", () => {
    assert.equal(BATCH_EXIT_WINDOW_SECONDS_DEFAULT, 180);
    assert.equal(BATCH_EXIT_KNOB_FLOOR_SECONDS, 1);
    assert.equal(BATCH_EXIT_KNOB_CEILING_SECONDS, 86_400);
    assert.equal(parseBatchWindowSeconds(180), 180);
    assert.equal(parseBatchWindowSeconds(1), 1);
    assert.throws(() => parseBatchWindowSeconds(0), /must be in/);
    assert.throws(() => parseBatchWindowSeconds(86_401), /must be in/);
    assert.throws(() => parseBatchWindowSeconds(30.5), /integer/);
  });

  it("first joiner opens the round; later joiners share the same close and do not restart the clock", () => {
    const t0 = 1_000_000;
    const first = joinRound({
      round: null,
      sats: 1_000n,
      lockingBytecode: lock(1),
      nowMs: t0,
      windowSeconds: 180,
      id: "aa",
    });
    assert.equal(first.openedNew, true);
    assert.equal(first.remainingSeconds, 180);
    assert.equal(first.round.closesAtMs, t0 + 180_000);
    assert.equal(roundIsOpen(first.round, t0 + 179_000), true);
    assert.equal(roundIsOpen(first.round, t0 + 180_000), false);

    const late = joinRound({
      round: first.round,
      sats: 2_000n,
      lockingBytecode: lock(2),
      nowMs: t0 + 60_000,
      windowSeconds: 180,
      id: "bb",
    });
    assert.equal(late.openedNew, false);
    assert.equal(late.remainingSeconds, 120);
    assert.equal(late.round.closesAtMs, first.round.closesAtMs);
    assert.equal(late.round.claims.length, 2);

    const afterClose = joinRound({
      round: late.round,
      sats: 3_000n,
      lockingBytecode: lock(3),
      nowMs: t0 + 180_000,
      windowSeconds: 180,
      id: "cc",
    });
    assert.equal(afterClose.openedNew, true);
    assert.equal(afterClose.round.claims.length, 1);
    assert.equal(afterClose.round.claims[0]!.id, "cc");
    assert.equal(afterClose.remainingSeconds, 180);
  });

  it("at close, flush everyone already in — a late joiner does not miss a still-open round", () => {
    const t0 = 5_000;
    const a = joinRound({
      round: null,
      sats: 1_000n,
      lockingBytecode: lock(1),
      nowMs: t0,
      windowSeconds: 180,
      id: "a",
    });
    const b = joinRound({
      round: a.round,
      sats: 2_000n,
      lockingBytecode: lock(2),
      nowMs: t0 + 179_000,
      windowSeconds: 999,
      id: "b",
    });
    assert.equal(b.openedNew, false);
    assert.equal(remainingSeconds(b.round, t0 + 179_000), 1);
    const outputs = shapeFusionOutputs(b.round.claims, new Uint8Array(32).fill(9));
    assert.equal(outputs.length, 2);
    const sats = outputs.map((o) => o.sats).sort((x, y) => (x < y ? -1 : 1));
    assert.deepEqual(sats, [1_000n, 2_000n]);
    const sketch = fusionBatchSketch(outputs);
    assert.equal(sketch.shape, "cashfusion-like-multi-p2pkh");
    assert.equal(sketch.protocol, "not-cashfusion-fuse");
    assert.equal(sketch.totalSats, "3000");
  });

  it("planBatchExit records remaining time against the shared close", () => {
    const first = planBatchExit({
      sats: 5_000n,
      lockingBytecode: LAB_PAYOUT_LOCKING,
      windowSeconds: 180,
      nowMs: 0,
      id: "one",
    });
    assert.equal(first.openedNew, true);
    assert.equal(first.remainingSeconds, 180);
    const second = planBatchExit({
      sats: 7_000n,
      lockingBytecode: LAB_PAYOUT_LOCKING,
      round: first.round,
      windowSeconds: 180,
      nowMs: 30_000,
      id: "two",
    });
    assert.equal(second.openedNew, false);
    assert.equal(second.remainingSeconds, 150);
    assert.equal(second.round.claims.length, 2);
    assert.equal(second.sketch.outputCount, 2);
  });

  it("round JSON round-trips", () => {
    const joined = joinRound({
      round: null,
      sats: 9n,
      lockingBytecode: lock(4),
      nowMs: 42,
      windowSeconds: 180,
      id: "zz",
    });
    const back = decodeRound(encodeRound(joined.round));
    assert.equal(back.windowSeconds, 180);
    assert.equal(back.openedAtMs, 42);
    assert.equal(back.claims[0]!.sats, 9n);
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
    assert.match(writes[0] ?? "", /3s/);
    assert.match(writes.at(-1) ?? "", /0s/);
    const items = [1, 2, 3, 4];
    shuffleInPlace(items, new Uint8Array(32).fill(2));
    assert.deepEqual([...items].sort(), [1, 2, 3, 4]);
  });

  it("CLI uses --batch-window, not per-user min/max waits", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const cli = readFileSync(join(here, "..", "src", "cli.ts"), "utf8");
    assert.match(cli, /--batch-exit/);
    assert.match(cli, /\[--batch-window 180\]/);
    assert.match(cli, /planBatchExit/);
    assert.match(cli, /shared round/);
    const lock = readFileSync(join(here, "..", "src", "chain", "covenant-p2s.ts"), "utf8");
    assert.match(lock, /OP_1 OP_OUTPUTBYTECODE/);
    assert.match(lock, /OP_HASH256/);
  });
});
