import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import {
  circleDomain,
  decodeFriProof,
  encodeFriProof,
  proveFri,
  unmaskFriProof,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { freshViewingKey, openingMaskFelt, unmaskAuth, viewingCommit } from "../src/backends/circle/witness-mask.ts";
import {
  AIR_NEWTON_BYTES,
  AIR_OFF_EVEN,
  AIR_OFF_ODD,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  G64,
  bigDomain,
  encodeAirPacked,
  newtonEvalJs,
  nqzAt,
  TRACE_XS,
} from "../src/chain/air-cqz.ts";
import { add, encodeLe, inv, mul, sub } from "../src/backends/circle/m31.ts";
import { interpolateCircle } from "../src/backends/circle/interpolate.ts";
import { decodeFeltBlob } from "../src/chain/m31-asm.ts";
import { addPoints } from "../src/backends/circle/group.ts";
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
    const packed = encodeAirPacked(w.statement, raw);
    assert.notDeepEqual(
      packed.slice(AIR_OFF_OPEN_MASK, AIR_OFF_OPEN_MASK + 4),
      encodeLe(c),
      "mask felt is not packed as a degree-0 field",
    );
    assert.deepEqual(packed.slice(AIR_OFF_OPEN_MASK, AIR_OFF_OPEN_MASK + 32), decoded.viewingCommit);
    const q0 = packed.slice(AIR_OFF_QTABLE, AIR_OFF_QTABLE + 4);
    const i0 = decoded.queries[0]!.index;
    const even = decodeFeltBlob(packed.slice(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES));
    const odd = decodeFeltBlob(packed.slice(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES));
    const z = bigDomain[i0]!;
    const zg = addPoints(z, G64);
    const zg2 = addPoints(zg, G64);
    const tAt = (p: { x: bigint; y: bigint }) =>
      add(newtonEvalJs(even, p.x, TRACE_XS), mul(p.y, newtonEvalJs(odd, p.x, TRACE_XS)));
    const tp = tAt(z);
    const tgp = tAt(zg);
    const tg2 = tAt(zg2);
    const deposit = w.statement.action === "DEPOSIT";
    const cons = deposit ? sub(sub(tgp, tp), tg2) : sub(sub(tp, tgp), tg2);
    const seq = sub(sub(tgp, tp), 1n);
    const l0 = interpolateCircle(
      circleDomain(64),
      Array.from({ length: 64 }, (_, i) => (i === 0 ? 1n : 0n)),
    );
    const l23 = interpolateCircle(
      circleDomain(64),
      Array.from({ length: 64 }, (_, i) => (i === 23 ? 1n : 0n)),
    );
    const lag = (interp: ReturnType<typeof interpolateCircle>, p: { x: bigint; y: bigint }) =>
      add(newtonEvalJs(interp.even, p.x, interp.xs), mul(p.y, newtonEvalJs(interp.odd, p.x, interp.xs)));
    const nFromT = add(mul(lag(l0, z), cons), mul(lag(l23, z), seq));
    const zVal = nqzAt(w.statement, i0).z;
    const qFromT = zVal === 0n ? 0n : mul(nFromT, inv(zVal));
    const qPacked = decodeFeltBlob(q0)[0]!;
    const cGuess = sub(qPacked, qFromT);
    assert.notEqual(cGuess, c, "Newton T must not recover the opening mask");
    assert.equal(vm.accepted, true, vm.error ?? "honest VM still accepts");
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
