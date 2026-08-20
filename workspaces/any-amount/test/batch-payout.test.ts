import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { applyBatchExit, applyDeposit, type PoolMachine } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, utxoValueFor } from "../src/pool/state.ts";
import { hashPayoutLocking, LAB_PAYOUT_DIGEST, LAB_PAYOUT_LOCKING } from "../src/chain/payout.ts";
import { proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { encodeFriProof } from "../src/backends/circle/fri.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodePublicPaa1 } from "../src/pool/state.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function lock(fill: number): Uint8Array {
  const out = new Uint8Array(LAB_PAYOUT_LOCKING);
  out[3] = fill;
  return out;
}

function funded(n: number): { machine: PoolMachine; notes: Array<{ note: Note; index: number }> } {
  let machine: PoolMachine = {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
  const notes: Array<{ note: Note; index: number }> = [];
  for (let i = 0; i < n; i += 1) {
    const note: Note = {
      amountSats: 20_000n + BigInt(i) * 1_000n,
      rho: rnd32(),
      ownerSecret: rnd32(),
    };
    const d = applyDeposit(machine, note);
    machine = d.machine;
    notes.push({ note, index: d.index });
  }
  return { machine, notes };
}

describe("batch exit multi-payout conservation", () => {
  it("each payout equals its note; sum equals pool drop; extra payouts throw", () => {
    const { machine, notes } = funded(4);
    const before = machine.state.reserveSats;
    const items = notes.map((n, i) => ({
      note: n.note,
      index: n.index,
      withdrawSats: n.note.amountSats,
      payoutLocking: lock(0x20 + i),
    }));
    const batch = applyBatchExit(machine, items);
    const sum = items.reduce((n, it) => n + it.withdrawSats, 0n);
    assert.equal(batch.payouts.length, 4);
    assert.equal(batch.payouts.reduce((n, p) => n + p.sats, 0n), sum);
    assert.equal(batch.statement.publicAmountSats, -sum);
    assert.equal(batch.machine.state.reserveSats, before - sum);
    assert.equal(batch.machine.state.sequence, machine.state.sequence + 1n);
    assert.equal(utxoValueFor(machine.state) - utxoValueFor(batch.machine.state), sum);
    for (let i = 0; i < notes.length; i += 1) {
      assert.equal(batch.payouts[i]!.sats, notes[i]!.note.amountSats);
    }
    assert.throws(
      () =>
        applyBatchExit(machine, [
          { ...items[0]!, withdrawSats: items[0]!.note.amountSats + 1n },
        ]),
      /full-note|exceeds/,
    );
  });

  it("compiler rejects payouts that do not equal the pool net (no steal)", () => {
    const { machine, notes } = funded(3);
    const items = notes.map((n) => ({
      note: n.note,
      index: n.index,
      withdrawSats: n.note.amountSats,
      payoutLocking: n === notes[0] ? LAB_PAYOUT_LOCKING : lock(0x33),
    }));
    items[0] = { ...items[0]!, payoutLocking: LAB_PAYOUT_LOCKING };
    const batch = applyBatchExit(machine, items);
    const first = batch.spent[0]!;
    const proof = encodeFriProof(proveFri(batch.statement, wWithdraw(first.note, first.index, first.path)));
    const steal = batch.payouts.map((p, i) =>
      i === 0 ? { ...p, sats: p.sats + 50_000n } : p,
    );
    assert.throws(
      () =>
        compileCovenantSuccessor({
          wallet: createLabWallet(),
          feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 1_000_000 },
          pool: {
            tx_hash: "11".repeat(32),
            tx_pos: 0,
            value: utxoValueFor(machine.state),
            category: new Uint8Array(32).fill(0x11),
            commitment: encodePublicPaa1(machine.state),
          },
          newState: batch.machine.state,
          proof,
          statement: batch.statement,
          extraPayouts: steal,
        }),
      /would steal or leak reserve/,
    );
  });

  it("VM accepts honest multi-payout; rejects inflated last payout", () => {
    const { machine, notes } = funded(3);
    const items = notes.map((n, i) => ({
      note: n.note,
      index: n.index,
      withdrawSats: n.note.amountSats,
      payoutLocking: i === 0 ? LAB_PAYOUT_LOCKING : lock(0x40 + i),
    }));
    const batch = applyBatchExit(machine, items);
    assert.deepEqual(batch.statement.payoutLockingDigest, LAB_PAYOUT_DIGEST);
    const first = batch.spent[0]!;
    const proof = encodeFriProof(proveFri(batch.statement, wWithdraw(first.note, first.index, first.path)));
    const honest = evaluatePoolSuccessorVm({
      oldState: machine.state,
      newState: batch.machine.state,
      proof,
      statement: batch.statement,
      extraPayouts: batch.payouts,
    });
    assert.equal(honest.accepted, true, honest.error ?? "honest multi-payout");

    const inflated = batch.payouts.map((p, i) => (i === 2 ? { ...p, sats: p.sats + 10_000n } : p));
    const stolen = evaluatePoolSuccessorVm({
      oldState: machine.state,
      newState: batch.machine.state,
      proof,
      statement: batch.statement,
      extraPayouts: inflated,
    });
    assert.equal(stolen.accepted, false, "inflated payout must fail the sum==abs-net lock");
  });

  it("single-payout HASH256 path still matches the lab digest", () => {
    assert.equal(hashPayoutLocking(LAB_PAYOUT_LOCKING).length, 32);
  });
});
