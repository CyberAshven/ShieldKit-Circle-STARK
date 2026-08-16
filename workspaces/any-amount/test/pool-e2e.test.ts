import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { decodeFriProof, wDeposit } from "../src/backends/circle/fri.ts";
import { applyAggregate, applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { mixChangedRootsAndReserve, runMixSuccessor } from "../src/pool/mix-successor.ts";
import { IncrementalMerkle, NullifierSet, commitNote, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { writeI64BE, writeU64BE } from "../src/pool/bytes.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodePublicPaa1, STATE_BASE_SATS } from "../src/pool/state.ts";
import { AIR_PACKED_SIZE } from "../src/chain/air-cqz.ts";

function parsePushes(script: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i]!;
    if (op === 0) {
      out.push(new Uint8Array());
      i += 1;
      continue;
    }
    if (op >= 1 && op <= 75) {
      out.push(script.slice(i + 1, i + 1 + op));
      i += 1 + op;
      continue;
    }
    if (op === 0x4c) {
      const n = script[i + 1]!;
      out.push(script.slice(i + 2, i + 2 + n));
      i += 2 + n;
      continue;
    }
    if (op === 0x4d) {
      const n = script[i + 1]! + (script[i + 2]! << 8);
      out.push(script.slice(i + 3, i + 3 + n));
      i += 3 + n;
      continue;
    }
    if (op >= 0x4f && op <= 0x60) {
      i += 1;
      continue;
    }
    i += 1;
  }
  return out;
}

function containsBytes(hay: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return false;
  outer: for (let i = 0; i + needle.length <= hay.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

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

    const spent = decodeFriProof(mix.proof).auth;
    const measured = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: Number(STATE_BASE_SATS),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(mix.statement.oldState),
      },
      newState: mix.statement.newState,
      proof: mix.proof,
      statement: mix.statement,
      lockKind: "p2sh32",
    });
    const tx = decodeTransaction(measured.raw);
    if (typeof tx === "string") throw new Error(tx);
    const unlocking = tx.inputs[0]!.unlockingBytecode;
    const pushes = parsePushes(unlocking);
    assert.equal(pushes.length, 2, "unlocking is packed AIR + redeem only");
    assert.equal(pushes[0]!.length, AIR_PACKED_SIZE);
    assert.equal(containsBytes(unlocking, spent.leaf), false, "spent leaf must not appear");
    assert.equal(containsBytes(unlocking, spent.rho), false, "rho must not appear");
    assert.equal(containsBytes(unlocking, spent.owner), false, "owner must not appear");
    assert.equal(containsBytes(unlocking, spent.nullifier), false, "nullifier stays in verifyFri");
    for (const sib of spent.path) {
      assert.equal(containsBytes(unlocking, sib), false, "spent merkle path must not appear");
    }
    assert.equal(
      containsBytes(unlocking, writeI64BE(mix.statement.publicAmountSats)),
      false,
      "publicAmountSats must not appear",
    );
    assert.equal(
      containsBytes(unlocking, writeU64BE(mix.statement.oldState.reserveSats)),
      false,
      "old reserve u64 must not appear",
    );
    assert.equal(
      containsBytes(unlocking, writeU64BE(mix.statement.newState.reserveSats)),
      false,
      "new reserve u64 must not appear",
    );
  });
});
