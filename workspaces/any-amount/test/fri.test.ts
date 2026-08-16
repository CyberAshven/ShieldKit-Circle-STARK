import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { circleDomain, proveFri, statementToEvals, verifyFri } from "../src/backends/circle/fri.ts";
import { onCircle } from "../src/backends/circle/group.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, nullifierOf, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { commitAmount } from "../src/amounts/pedersen.ts";
import { encodeStatement } from "../src/pool/statement.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function freshMachine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

function depositNote(amount = 12_345n): { statement: ReturnType<typeof applyDeposit>["statement"]; machine: ReturnType<typeof applyDeposit>["machine"]; note: Note; index: number } {
  const note: Note = { amountSats: amount, rho: rnd32(), ownerSecret: rnd32() };
  const d = applyDeposit(freshMachine(), note);
  return { statement: d.statement, machine: d.machine, note, index: d.index };
}

describe("Circle FRI prove/verify", () => {
  it("domain points lie on the circle", () => {
    for (const p of circleDomain()) assert.ok(onCircle(p));
  });

  it("accepts an honest deposit statement via shipped plugin", async () => {
    const { statement } = depositNote();
    const proof = await circleFriPlugin.prove(statement, {});
    const v = circleFriPlugin.verify(statement, proof);
    assert.equal(v.ok, true, v.ok ? "" : v.reason);
    assert.ok(proof.length > 100);
  });

  it("accepts honest withdraw with change via shipped plugin", async () => {
    const { machine, note, index } = depositNote(20_000n);
    const w = applyWithdraw(machine, note, index, rnd32(), 5_000n);
    const proof = await circleFriPlugin.prove(w.statement, {});
    const v = circleFriPlugin.verify(w.statement, proof);
    assert.equal(v.ok, true, v.ok ? "" : v.reason);
    assert.ok(w.change);
    assert.equal(typeof w.changeIndex, "number");
    assert.notDeepEqual(w.change.rho, note.rho);
    assert.equal(w.change.amountSats, 15_000n);
  });

  it("deposit → partial withdraw → spend-change via shipped plugin", async () => {
    const { machine, note, index } = depositNote(20_000n);
    const instance = machine.state.poolInstanceId;
    const partial = applyWithdraw(machine, note, index, rnd32(), 5_000n);
    const p1 = await circleFriPlugin.prove(partial.statement, {});
    const v1 = circleFriPlugin.verify(partial.statement, p1);
    assert.equal(v1.ok, true, v1.ok ? "" : v1.reason);
    assert.ok(partial.change);
    assert.equal(typeof partial.changeIndex, "number");
    assert.notDeepEqual(partial.change.rho, note.rho);
    assert.notDeepEqual(nullifierOf(partial.change, instance), partial.statement.nullifier);
    assert.throws(() => applyWithdraw(partial.machine, note, index, rnd32(), 1n));

    const spent = applyWithdraw(
      partial.machine,
      partial.change,
      partial.changeIndex!,
      rnd32(),
      partial.change.amountSats,
    );
    const p2 = await circleFriPlugin.prove(spent.statement, {});
    const v2 = circleFriPlugin.verify(spent.statement, p2);
    assert.equal(v2.ok, true, v2.ok ? "" : v2.reason);
    assert.equal(spent.machine.state.reserveSats, 0n);
    assert.equal(spent.change, undefined);
  });

  it("rejects a false statement (tampered reserve)", async () => {
    const { statement } = depositNote();
    const proof = proveFri(statement);
    statement.newState.reserveSats += 1n;
    const v = verifyFri(statement, proof);
    assert.equal(v.ok, false);
  });

  it("rejects wrong note membership in the statement", async () => {
    const { statement } = depositNote();
    const proof = proveFri(statement);
    statement.noteCommitment = rnd32();
    const v = verifyFri(statement, proof);
    assert.equal(v.ok, false);
  });

  it("rejects wrong nullifier in the statement", async () => {
    const { machine, note, index } = depositNote(9_000n);
    const w = applyWithdraw(machine, note, index, rnd32(), 9_000n);
    const proof = proveFri(w.statement);
    w.statement.nullifier = rnd32();
    const v = verifyFri(w.statement, proof);
    assert.equal(v.ok, false);
  });

  it("statement polynomial moves when reserve, note, or nullifier change", () => {
    const { statement } = depositNote(4_000n);
    const domain = circleDomain();
    const honest = statementToEvals(statement, domain);
    const tamperedReserve = { ...statement, newState: { ...statement.newState, reserveSats: statement.newState.reserveSats + 1n } };
    const tamperedNote = { ...statement, noteCommitment: rnd32() };
    const tamperedNf = { ...statement, nullifier: rnd32() };
    assert.notDeepEqual(statementToEvals(tamperedReserve, domain), honest);
    assert.notDeepEqual(statementToEvals(tamperedNote, domain), honest);
    assert.notDeepEqual(statementToEvals(tamperedNf, domain), honest);
    assert.equal(encodeStatement(statement).length, encodeStatement(tamperedReserve).length);
  });
});

describe("Pedersen binds the public amount", () => {
  it("deposit commit is not the zero commit", () => {
    const { statement } = depositNote(777n);
    assert.notDeepEqual(statement.amountCommitOut, new Uint8Array(32));
    assert.ok(commitAmount(777n, 1n) !== 0n);
  });

  it("withdraw openings conserve note = public + change amounts", () => {
    const { machine, note, index } = depositNote(20_000n);
    const w = applyWithdraw(machine, note, index, rnd32(), 5_000n);
    assert.ok(w.change);
    assert.equal(note.amountSats, 5_000n + w.change.amountSats);
    let rIn = 0n;
    let rOut = 0n;
    for (const b of note.rho) rIn = (rIn << 8n) | BigInt(b);
    for (const b of w.change.rho) rOut = (rOut << 8n) | BigInt(b);
    assert.notEqual(rIn, rOut);
    assert.notDeepEqual(w.statement.amountCommitIn, new Uint8Array(32));
    assert.notDeepEqual(w.statement.amountCommitOut, new Uint8Array(32));
  });
});
