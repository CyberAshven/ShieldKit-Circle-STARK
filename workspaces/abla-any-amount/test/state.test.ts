import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeState, emptyState, encodeState, ANY_STATE_BYTES } from "../src/pool/state.ts";
import {
  IncrementalMerkle,
  NullifierSet,
  commitNote,
  nullifierOf,
  type Note,
} from "../src/pool/notes.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { hashLabPlugin } from "../src/backends/hash-lab.ts";
import { circleFriPlugin, CIRCLE_FRI_NOT_SOUND_YET } from "../src/backends/circle/plugin.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

describe("PAA1 state", () => {
  it("round-trips 128 bytes", () => {
    const s = emptyState(rnd32());
    const bin = encodeState(s);
    assert.equal(bin.length, ANY_STATE_BYTES);
    const back = decodeState(bin);
    assert.equal(back.reserveSats, 0n);
    assert.deepEqual(back.poolInstanceId, s.poolInstanceId);
  });
});

describe("any-amount machine", () => {
  it("deposits any amount and partial-withdraws with change", async () => {
    const id = rnd32();
    let machine = {
      state: emptyState(id),
      notes: new IncrementalMerkle(),
      nullifiers: new NullifierSet(),
    };
    const note: Note = { amountSats: 37_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine, note);
    machine = d.machine;
    assert.equal(machine.state.reserveSats, 37_000n);
    const leaf = commitNote(note);
    assert.ok(
      IncrementalMerkle.verify(leaf, d.index, machine.notes.authPath(d.index), machine.state.noteRoot),
    );
    const w = applyWithdraw(machine, note, d.index, rnd32(), 10_000n);
    assert.equal(w.machine.state.reserveSats, 27_000n);
    assert.ok(w.change);
    assert.equal(w.change!.amountSats, 27_000n);
    assert.deepEqual(nullifierOf(note, id), w.statement.nullifier);
    const proof = await hashLabPlugin.prove(d.statement, {});
    assert.equal(hashLabPlugin.verify(d.statement, proof).ok, true);
  });

  it("rejects over-withdraw", () => {
    const id = rnd32();
    const machine = {
      state: emptyState(id),
      notes: new IncrementalMerkle(),
      nullifiers: new NullifierSet(),
    };
    const note: Note = { amountSats: 100n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine, note);
    assert.throws(() => applyWithdraw(d.machine, note, d.index, rnd32(), 101n));
  });
});

describe("plugins", () => {
  it("circle-fri refuses to pretend it is sound", async () => {
    assert.equal(circleFriPlugin.sound, false);
    await assert.rejects(() => circleFriPlugin.prove({} as never, {}), {
      message: CIRCLE_FRI_NOT_SOUND_YET,
    });
    assert.equal(circleFriPlugin.verify({} as never, new Uint8Array()).ok, false);
  });
});
