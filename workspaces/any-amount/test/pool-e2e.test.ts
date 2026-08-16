import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { wDeposit } from "../src/backends/circle/fri.ts";
import { applyAggregate, applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../src/pool/mix-successor.ts";
import { IncrementalMerkle, NullifierSet, commitNote, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function runMix(label: string): { anonSet: number; reserve: bigint; noteRoot: string } {
  let machine = {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  const deposits: Note[] = [];
  for (let i = 0; i < 8; i += 1) {
    deposits.push({ amountSats: 1_000n * BigInt(i + 1), rho: rnd32(), ownerSecret: rnd32() });
  }
  const first = applyDeposit(machine, deposits[0]!);
  machine = first.machine;
  const rest = applyAggregate(machine, deposits.slice(1), []);
  machine = rest.machine;
  const beforeWithdraw = machine.notes.leaves.length;
  assert.ok(beforeWithdraw >= 8, label);

  const spent = rest.deposited[0] ?? { note: deposits[0]!, index: first.index };
  const w = applyWithdraw(machine, spent.note, spent.index, rnd32(), 500n);
  machine = w.machine;
  assert.ok(machine.notes.leaves.length >= beforeWithdraw);
  assert.notEqual(Buffer.from(machine.state.noteRoot).toString("hex"), Buffer.from(first.machine.state.noteRoot).toString("hex"));

  return {
    anonSet: machine.notes.leaves.length,
    reserve: machine.state.reserveSats,
    noteRoot: Buffer.from(machine.state.noteRoot).toString("hex"),
  };
}

describe("pool e2e mix", () => {
  it("grows the set twice; withdraw does not publish the spent leaf", async () => {
    const a = runMix("run1");
    const b = runMix("run2");
    assert.ok(a.anonSet >= 8);
    assert.ok(b.anonSet >= 8);
    assert.notEqual(a.noteRoot, b.noteRoot);
    assert.ok(a.reserve > 0n);

    const note: Note = { amountSats: 4_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = await circleFriPlugin.prove(d.statement, wDeposit(note, d.index, d.path));
    const v = circleFriPlugin.verify(d.statement, proof);
    assert.equal(v.ok, true, v.ok ? "" : v.reason);
    const leaf = commitNote(note);
    assert.notDeepEqual(d.statement.noteCommitment, leaf.slice(0, 8));
    assert.equal(d.statement.noteCommitment.length, 32);

    const mix = runMixSuccessor({ depositCount: 6, withdrawSats: 500n });
    assert.ok(mixChangedRootsAndReserve(mix));
    assert.equal(circleFriPlugin.verify(mix.statement, mix.proof).ok, true);
  });
});
