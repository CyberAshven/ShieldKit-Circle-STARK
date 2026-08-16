import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { add, encodeLe, mul } from "../src/backends/circle/m31.ts";
import { addPoints, CIRCLE_GEN, scalarMul } from "../src/backends/circle/group.ts";
import { interpolateCircle } from "../src/backends/circle/interpolate.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { airQuotientLde, publicCells } from "../src/backends/circle/air.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { encodeFeltBlob } from "../src/chain/m31-asm.ts";
import {
  compileCircleAddLock,
  compileAllSlotsCqzLock,
  compileBindTLock,
  compileCqzKernel,
  compileEvalTFromBlobLock,
  compileEvalTLock,
  compileSlot0CqzLock,
  compileSlotCqzLock,
  fsIndexFromAltSlotAsm,
  compileM31MulLock,
  compileNewtonFromBlobLock,
  compileNewtonLock,
  compileQzEqualsNLock,
  compileScalarMulFastLock,
  compileScalarMulLock,
  compileVanishingLock,
  AIR_OFF_EVEN,
  AIR_OFF_IDX,
  AIR_OFF_NTABLE,
  AIR_OFF_QTABLE,
  BE16_UNSIGNED,
  encodeAirPacked,
  fiatShamirQueryIndices,
  fsIndex0Asm,
  G1024,
  G64,
  newtonEvalJs,
  nqzAt,
  statementNewton,
  TRACE_XS,
  smallDomain,
  bigDomain,
} from "../src/chain/air-cqz.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { sha256 } from "../src/pool/bytes.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";

function pushNum(n: bigint): Uint8Array {
  if (n === 0n) return Uint8Array.of(0x00);
  if (n >= 1n && n <= 16n) return Uint8Array.of(0x50 + Number(n));
  const bytes: number[] = [];
  let v = n;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(0);
  return pushData(Uint8Array.from(bytes));
}

function padUnlock(inner: Uint8Array, pad = 8_000): Uint8Array {
  const dummy = new Uint8Array(pad);
  dummy.fill(0x11);
  const suffix = pushData(dummy);
  const out = new Uint8Array(inner.length + suffix.length);
  out.set(inner, 0);
  out.set(suffix, inner.length);
  return out;
}

function evalPadded(lock: Uint8Array, inner: Uint8Array) {
  const drop = cashAssemblyToBin("OP_DROP");
  if (typeof drop === "string") throw new Error(drop);
  const locking = new Uint8Array(drop.length + lock.length);
  locking.set(drop, 0);
  locking.set(lock, drop.length);
  return evaluateBch2026(locking, padUnlock(inner));
}

describe("M31 / Newton / circle on 2026 VM", () => {
  it("Newton-from-blob matches unrolled", () => {
    const coeffs = [3n, 5n, 7n, 9n, ...Array.from({ length: 29 }, () => 0n)];
    const at = 11n;
    const expect = newtonEvalJs(coeffs, at);
    const ev = evalPadded(
      compileNewtonFromBlobLock(),
      Uint8Array.of(...pushNum(expect), ...pushData(encodeFeltBlob(coeffs)), ...pushNum(at)),
    );
    assert.equal(ev.accepted, true, ev.error ?? `blob newton ${expect}`);
  });

  it("OP_DEFINE invoke multiplies", () => {
    const body = cashAssemblyToBin("OP_MUL <2147483647> OP_MOD");
    if (typeof body === "string") throw new Error(body);
    const lock = cashAssemblyToBin(
      `<0x${Buffer.from(body).toString("hex")}> <0> OP_DEFINE <0> OP_INVOKE <15> OP_NUMEQUAL`,
    );
    if (typeof lock === "string") throw new Error(lock);
    const ev = evalPadded(lock, Uint8Array.of(...pushNum(3n), ...pushNum(5n)));
    assert.equal(ev.accepted, true, ev.error ?? "define mul");
  });

  it("multiplies in M31", () => {
    const ev = evalPadded(compileM31MulLock(), Uint8Array.of(...pushNum(3n), ...pushNum(5n)));
    assert.equal(ev.accepted, true, ev.error ?? "m31 mul");
  });

  it("Newton eval matches JS", () => {
    const coeffs = [3n, 5n, 7n, 9n, ...Array.from({ length: 28 }, () => 0n)];
    const at = 11n;
    const expect = newtonEvalJs(coeffs, at);
    const ev = evalPadded(compileNewtonLock(coeffs), Uint8Array.of(...pushNum(expect), ...pushNum(at)));
    assert.equal(ev.accepted, true, ev.error ?? `newton expect ${expect}`);
  });

  it("circle add matches JS", () => {
    const sum = addPoints(G64, G1024);
    const ev = evalPadded(
      compileCircleAddLock(sum),
      Uint8Array.of(...pushNum(G64.x), ...pushNum(G64.y), ...pushNum(G1024.x), ...pushNum(G1024.y)),
    );
    assert.equal(ev.accepted, true, ev.error ?? "circle add");
  });

  it("scalar mul [0]G is identity and [1]G is G", () => {
    const id = evalPadded(
      compileScalarMulLock({ x: 1n, y: 0n }),
      Uint8Array.of(...pushNum(0n), ...pushNum(G1024.x), ...pushNum(G1024.y)),
    );
    assert.equal(id.accepted, true, id.error ?? "[0]G");
    const one = evalPadded(
      compileScalarMulLock(G1024),
      Uint8Array.of(...pushNum(1n), ...pushNum(G1024.x), ...pushNum(G1024.y)),
    );
    assert.equal(one.accepted, true, one.error ?? "[1]G");
    const p = scalarMul(G1024, 3n);
    const three = evalPadded(
      compileScalarMulLock(p),
      Uint8Array.of(...pushNum(3n), ...pushNum(G1024.x), ...pushNum(G1024.y)),
    );
    assert.equal(three.accepted, true, three.error ?? "[3]G");
    const fast0 = evalPadded(
      compileScalarMulFastLock({ x: 1n, y: 0n }),
      Uint8Array.of(...pushNum(0n), ...pushNum(G1024.x), ...pushNum(G1024.y)),
    );
    assert.equal(fast0.accepted, true, fast0.error ?? "fast [0]G");
    const fast3 = evalPadded(
      compileScalarMulFastLock(p),
      Uint8Array.of(...pushNum(3n), ...pushNum(G1024.x), ...pushNum(G1024.y)),
    );
    assert.equal(fast3.accepted, true, fast3.error ?? "fast [3]G");
  });

  it("vanishing Z matches airQuotientLde", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const idx = 17;
    const { z } = nqzAt(d.statement, idx);
    const ev = evalPadded(compileVanishingLock(), Uint8Array.of(...pushNum(z), ...pushNum(bigDomain[idx]!.x)));
    assert.equal(ev.accepted, true, ev.error ?? `Z=${z}`);
  });

  it("Q·Z equals N for an honest query (JS + VM mul)", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const digest = sha256(encodeStatement(d.statement));
    const qIdx = fiatShamirQueryIndices(digest, proof);
    const i = qIdx[0]!;
    const { n, z, q } = nqzAt(d.statement, i);
    assert.equal(mul(q, z), n);
    const ev = evalPadded(compileQzEqualsNLock(), Uint8Array.of(...pushNum(n), ...pushNum(q), ...pushNum(z)));
    assert.equal(ev.accepted, true, ev.error ?? "Q*Z=N");
    if (z !== 0n) {
      const dummyQ = add(q, 1n);
      const bad = evalPadded(compileQzEqualsNLock(), Uint8Array.of(...pushNum(n), ...pushNum(dummyQ), ...pushNum(z)));
      assert.equal(bad.accepted, false);
    } else {
      const off = qIdx.find((j) => nqzAt(d.statement, j).z !== 0n);
      assert.ok(off !== undefined, "need an off-trace query");
      const offNqz = nqzAt(d.statement, off!);
      const dummyQ = add(offNqz.q, 1n);
      const bad = evalPadded(
        compileQzEqualsNLock(),
        Uint8Array.of(...pushNum(offNqz.n), ...pushNum(dummyQ), ...pushNum(offNqz.z)),
      );
      assert.equal(bad.accepted, false);
    }
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    assert.equal(packed.length, 1600);
    const interp = statementNewton(d.statement);
    const at = 11n;
    const blobExpect = newtonEvalJs(interp.even, at);
    const blobEv = evalPadded(
      compileNewtonFromBlobLock(),
      Uint8Array.of(...pushNum(blobExpect), ...pushData(encodeFeltBlob(interp.even)), ...pushNum(at)),
    );
    assert.equal(blobEv.accepted, true, blobEv.error ?? "newton blob");
    const z0 = bigDomain[17]!;
    const tExpect = add(newtonEvalJs(interp.even, z0.x), mul(z0.y, newtonEvalJs(interp.odd, z0.x)));
    const tBaked = evalPadded(
      compileEvalTLock(interp.even, interp.odd, tExpect),
      Uint8Array.of(...pushNum(z0.x), ...pushNum(z0.y)),
    );
    assert.equal(tBaked.accepted, true, tBaked.error ?? "evalT baked");
    const evenB = encodeFeltBlob(
      [...interp.even, ...Array.from({ length: Math.max(0, 33 - interp.even.length) }, () => 0n)].slice(0, 33),
    );
    const oddB = encodeFeltBlob(
      [...interp.odd, ...Array.from({ length: Math.max(0, 33 - interp.odd.length) }, () => 0n)].slice(0, 33),
    );
    const tBlob = evalPadded(
      compileEvalTFromBlobLock(tExpect),
      Uint8Array.of(...pushData(evenB), ...pushData(oddB), ...pushNum(z0.x), ...pushNum(z0.y)),
    );
    assert.equal(tBlob.accepted, true, tBlob.error ?? "evalT blob");
    const newt = statementNewton(d.statement);
    assert.ok(newt.even.length >= 16, `even ${newt.even.length}`);
    assert.equal(TRACE_XS.length, newt.even.length);
    const packedI0 = (packed[AIR_OFF_IDX]! << 8) | packed[AIR_OFF_IDX + 1]!;
    const slotNqz = nqzAt(d.statement, packedI0);
    assert.equal(mul(slotNqz.q, slotNqz.z), slotNqz.n, "JS slot0 Q*Z=N");
    const qPacked = packed.slice(AIR_OFF_QTABLE, AIR_OFF_QTABLE + 4);
    assert.deepEqual(qPacked, encodeLe(slotNqz.q));
  });

  it("fused slot-0 C=Q·Z accepts honest packed blob and rejects tampered Q", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    const ok = evalPadded(compileSlot0CqzLock(), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? "slot0 C=QZ");
    const bad = new Uint8Array(packed);
    bad[AIR_OFF_QTABLE] ^= 1;
    bad[AIR_OFF_NTABLE] = 1;
    const ev = evalPadded(compileSlot0CqzLock(), pushData(bad));
    assert.equal(ev.accepted, false, "tampered qTable[0] must fail");
    const cooked = new Uint8Array(packed);
    const i0 = (packed[AIR_OFF_IDX]! << 8) | packed[AIR_OFF_IDX + 1]!;
    const slot = nqzAt(d.statement, i0);
    const q2 = add(slot.q, 1n);
    cooked.set(encodeLe(q2), AIR_OFF_QTABLE);
    cooked.set(encodeLe(mul(q2, slot.z)), AIR_OFF_NTABLE);
    const cook = evalPadded(compileSlot0CqzLock(), pushData(cooked));
    assert.equal(cook.accepted, false, "cooked nTable = Q'·Z must fail N-from-T");
    assert.ok(compileCqzKernel().length <= 10_000, `cqz kernel ${compileCqzKernel().length}`);
    const tOk = evalPadded(compileBindTLock(), pushData(packed));
    assert.equal(tOk.accepted, true, tOk.error ?? "bind T");
    const cookedT = new Uint8Array(packed);
    cookedT[AIR_OFF_EVEN] ^= 1;
    const tBad = evalPadded(compileBindTLock(), pushData(cookedT));
    assert.equal(tBad.accepted, false, "cooked Newton T must fail bind");
  });

  it("36× slot-0 C=QZ ops exceed the 10KB unlocking density budget", async () => {
    const { createTestAuthenticationProgramBch, createVirtualMachineBch2026 } = await import(
      "@bitauth/libauth"
    );
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    const drop = cashAssemblyToBin("OP_DROP");
    if (typeof drop === "string") throw new Error(drop);
    const lock = compileSlot0CqzLock();
    const locking = new Uint8Array(drop.length + lock.length);
    locking.set(drop, 0);
    locking.set(lock, drop.length);
    const unlocking = padUnlock(pushData(packed));
    const vm = createVirtualMachineBch2026(true);
    const program = createTestAuthenticationProgramBch({
      lockingBytecode: locking,
      unlockingBytecode: unlocking,
      valueSatoshis: 1000n,
    });
    const state = vm.evaluate(program);
    assert.equal(vm.stateSuccess(state), true, String(vm.stateSuccess(state)));
    const cost = Number(
      (state as { metrics?: { operationCost?: number | bigint } }).metrics?.operationCost ?? 0,
    );
    const budget10k = (41 + 10_000) * 800;
    assert.ok(cost > 0, "need a measured slot-0 cost");
    assert.ok(
      cost * 36 > budget10k,
      `36× slot-0 cost ${cost * 36} should exceed 10KB budget ${budget10k} (one slot ${cost})`,
    );
    assert.ok(compileAllSlotsCqzLock().length <= 10_000);
  });

  it("unsigned BE16 decode: 0x0193 is 403, not signed 147", () => {
    const lock = cashAssemblyToBin(`${BE16_UNSIGNED}\n<403>\nOP_NUMEQUAL`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evalPadded(lock, pushData(Uint8Array.of(0x01, 0x93)));
    assert.equal(ev.accepted, true, ev.error ?? "BE16 403");
    const p = scalarMul(G1024, 403n);
    const fast = evalPadded(
      compileScalarMulFastLock(p),
      Uint8Array.of(...pushNum(403n), ...pushNum(G1024.x), ...pushNum(G1024.y)),
    );
    assert.equal(fast.accepted, true, fast.error ?? "fast [403]G");
  });

  it("fsIndex0Asm matches JS Fiat–Shamir slot 0", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    const digest = sha256(encodeStatement(d.statement));
    const i0 = fiatShamirQueryIndices(digest, proof)[0]!;
    const lock = cashAssemblyToBin(`${fsIndex0Asm()}\nOP_NIP\n<${i0}>\nOP_NUMEQUAL`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evalPadded(lock, pushData(packed));
    assert.equal(ev.accepted, true, ev.error ?? `fsIndex0 expected ${i0}`);
  });

  it("fsIndexFromAltSlot matches JS Fiat–Shamir slot 3", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    const digest = sha256(encodeStatement(d.statement));
    const i3 = fiatShamirQueryIndices(digest, proof)[3]!;
    const lock = cashAssemblyToBin(
      `<3> OP_TOALTSTACK\n${fsIndexFromAltSlotAsm()}\nOP_NIP\n<${i3}>\nOP_NUMEQUAL`,
    );
    if (typeof lock === "string") throw new Error(lock);
    const ev = evalPadded(lock, pushData(packed));
    assert.equal(ev.accepted, true, ev.error ?? `fsIndex3 expected ${i3}`);
  });

  it("slot-3 C=QZ accepts honest packed and rejects cooked qTable[3]", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    const ok = evalPadded(compileSlotCqzLock(3), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? "slot-3 honest");
    const cooked = new Uint8Array(packed);
    cooked[AIR_OFF_QTABLE + 12] ^= 1;
    const bad = evalPadded(compileSlotCqzLock(3), pushData(cooked));
    assert.equal(bad.accepted, false, "cooked qTable[3] must fail slot-3");
  });

  it("slot-0 recomputes FS index; cooked spender idx is ignored", () => {
    const note: Note = {
      amountSats: 8_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const proof = proveFri(d.statement, wDeposit(note, d.index, d.path));
    const packed = encodeAirPacked(d.statement, encodeFriProof(proof));
    packed[AIR_OFF_IDX] = (403 >> 8) & 0xff;
    packed[AIR_OFF_IDX + 1] = 403 & 0xff;
    const ok = evalPadded(compileSlot0CqzLock(), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? "cooked idx must not change recomputed FS slot-0");
  });
});
