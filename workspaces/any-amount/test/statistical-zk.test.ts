import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import {
  decodeFriProof,
  encodeFriProof,
  proveFri,
  unmaskFriProof,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { freshViewingKey, openingMaskFelt, unmaskAuth, viewingCommit } from "../src/backends/circle/witness-mask.ts";
import { nqzAt } from "../src/chain/air-cqz.ts";
import { add, encodeLe } from "../src/backends/circle/m31.ts";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, STATE_BASE_SATS } from "../src/pool/state.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
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

function machine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

describe("statistical ZK of the published witness", () => {
  it("honest in-memory verifyFri and plugin.verify accept", async () => {
    const note: Note = { amountSats: 12_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    assert.equal(verifyFri(d.statement, proof).ok, true);
    const encoded = encodeFriProof(proof);
    assert.equal(circleFriPlugin.verify(d.statement, encoded).ok, true);
    const decoded = decodeFriProof(encoded);
    assert.equal(decoded.authMasked, true);
    assert.equal(verifyFri(d.statement, decoded).ok, true, "public verify (no viewing key) accepts honest");
    assert.equal(verifyFri(d.statement, decoded, {}, { viewingKey: proof.viewingKey }).ok, true);
  });

  it("encodeFriProof and every successor unlocking omit rho/owner", () => {
    const note: Note = { amountSats: 0x0a1b2c3d4e5f6071n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const w = applyWithdraw(d.machine, note, d.index, rnd32(), note.amountSats / 4n);
    const inner = proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created));
    const raw = encodeFriProof(inner);
    assert.equal(containsBytes(raw, note.rho), false, "encoded proof must not carry rho");
    assert.equal(containsBytes(raw, note.ownerSecret), false, "encoded proof must not carry owner");
    assert.equal(containsBytes(raw, inner.viewingKey!), false, "viewing key stays off the encoding");
    const decoded = decodeFriProof(raw);
    assert.notDeepEqual(decoded.auth.rho, note.rho);
    assert.deepEqual(unmaskAuth(decoded.auth, inner.viewingKey!).rho, note.rho);
    assert.throws(() => unmaskFriProof(decoded, freshViewingKey()));

    const measured = compileCovenantSuccessor({
      wallet: createLabWallet(),
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 250_000 },
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: Number(STATE_BASE_SATS),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(w.statement.oldState),
      },
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
      lockKind: "p2sh32",
    });
    const tx = decodeTransaction(measured.raw);
    if (typeof tx === "string") throw new Error(tx);
    for (const input of tx.inputs) {
      assert.equal(containsBytes(input.unlockingBytecode, note.rho), false);
      assert.equal(containsBytes(input.unlockingBytecode, note.ownerSecret), false);
      assert.equal(containsBytes(input.unlockingBytecode, inner.viewingKey!), false);
    }
    const vm = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: raw,
      statement: w.statement,
    });
    assert.equal(vm.accepted, true, vm.error ?? "honest VM");
    const c = openingMaskFelt(decoded.viewingCommit!);
    for (const q of decoded.queries) {
      const rawQ = nqzAt(w.statement, q.index).q;
      assert.notEqual(q.layers[0]!.value, rawQ, "opening is not plaintext Q");
      assert.equal(q.layers[0]!.value, add(rawQ, c));
    }
    const rawQ0 = nqzAt(w.statement, decoded.queries[0]!.index).q;
    const poolUnlock = tx.inputs[0]!.unlockingBytecode;
    assert.equal(containsBytes(poolUnlock, encodeLe(add(rawQ0, c))), true, "packed Q is masked");
  });

  it("wrong viewing key does not open the preimage", () => {
    const note: Note = { amountSats: 9_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const inner = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const decoded = decodeFriProof(encodeFriProof(inner));
    const bad = verifyFri(d.statement, decoded, {}, { viewingKey: freshViewingKey() });
    assert.equal(bad.ok, false);
    assert.match(bad.ok ? "" : bad.reason, /viewing key/);
    assert.deepEqual(decoded.viewingCommit, viewingCommit(inner.viewingKey!));
  });
});
