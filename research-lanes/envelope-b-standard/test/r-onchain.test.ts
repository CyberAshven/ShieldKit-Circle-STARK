import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { encodeLe } from "../src/backends/circle/m31.ts";
import { openingMaskAt } from "../src/backends/circle/witness-mask.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { evaluateBch2026 } from "../src/chain/vm-verifier.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import {
  AIR_NEWTON_BYTES,
  AIR_OFF_EVEN,
  AIR_OFF_NTABLE,
  AIR_OFF_ODD,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  SLOT_KERNEL_COUNT,
  compileSlot0CqzLock,
  compileSlotsKernel,
  encodeAirPacked,
  fiatShamirQueryIndices,
  nqzAt,
} from "../src/chain/air-cqz.ts";
import {
  compileNFromTSlot0Lock,
  compileRAtSlot0Lock,
  compileSlotRCqzLock,
  slotRCqzAsm,
} from "../src/chain/r-kernel.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { sha256 } from "../src/pool/bytes.ts";
import { UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";


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

function mix() {
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
  const i0 = fiatShamirQueryIndices(
    digest,
    proof,
    defaultInternalHash(),
    packed.subarray(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES),
    packed.subarray(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES),
  )[0]!;
  const nqz = nqzAt(d.statement, i0);
  const r = openingMaskAt(proof.viewingCommit!, i0, undefined, nqz.z);
  return { d, proof, packed, i0, nqz, r };
}

describe("on-chain R_on + Z·R_off (plan 4)", () => {
  it("slot R redeem stays under 10 KB", () => {
    const asm = slotRCqzAsm(0);
    const bin = cashAssemblyToBin(asm);
    if (typeof bin === "string") throw new Error(bin);
    assert.ok(bin.length <= UNLOCKING_MAX_BYTES, `slotR redeem ${bin.length}`);
    assert.ok(compileSlotsKernel(0).length <= UNLOCKING_MAX_BYTES, `slots kernel ${compileSlotsKernel(0).length}`);
    assert.ok(compileSlotsKernel(SLOT_KERNEL_COUNT - 1).length <= UNLOCKING_MAX_BYTES);
    console.log(`slotR redeem ${bin.length} slots0 ${compileSlotsKernel(0).length}`);
  });

  it("isolated R at FS slot 0 matches JS openingMaskAt", () => {
    const { packed, r } = mix();
    const ok = evalPadded(compileRAtSlot0Lock(r), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? `R=${r}`);
    const bad = evalPadded(compileRAtSlot0Lock((r + 1n) % 2147483647n), pushData(packed));
    assert.equal(bad.accepted, false, "wrong R must fail");
  });

  it("isolated N = C(z) at FS slot 0 matches residual interpolant", () => {
    const { packed, nqz } = mix();
    const ok = evalPadded(compileNFromTSlot0Lock(nqz.n), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? `N=${nqz.n}`);
    const bad = evalPadded(compileNFromTSlot0Lock((nqz.n + 1n) % 2147483647n), pushData(packed));
    assert.equal(bad.accepted, false, "wrong N must fail");
  });

  it("honest (q−R)·Z == C(z) accepts", () => {
    const { packed } = mix();
    const ok = evalPadded(compileSlotRCqzLock(0), pushData(packed));
    assert.equal(ok.accepted, true, ok.error ?? "honest slot R");
    const viaCqz = evalPadded(compileSlot0CqzLock(), pushData(packed));
    assert.equal(viaCqz.accepted, true, viaCqz.error ?? "slotCqzAsm is R-aware");
  });

  it("cooked viewing-commit rejects (R mismatch)", () => {
    const { packed } = mix();
    const cooked = new Uint8Array(packed);
    cooked[AIR_OFF_OPEN_MASK] ^= 0xff;
    const ev = evalPadded(compileSlotRCqzLock(0), pushData(cooked));
    assert.equal(ev.accepted, false, "commit flip must fail R check");
  });

  it("cooked qTable rejects even if nTable is recooked to match masked C=QZ", () => {
    const { packed, nqz, r } = mix();
    if (nqz.z === 0n) return;
    const cooked = new Uint8Array(packed);
    const qPrime = (nqz.q + r + 1n) % 2147483647n;
    const nPrime = (qPrime * nqz.z) % 2147483647n;
    cooked.set(encodeLe(qPrime), AIR_OFF_QTABLE);
    cooked.set(encodeLe(nPrime), AIR_OFF_NTABLE);
    const ev = evalPadded(compileSlotRCqzLock(0), pushData(cooked));
    assert.equal(ev.accepted, false, "masked-consistent recook of Q/N must still fail independent N");
  });
});
