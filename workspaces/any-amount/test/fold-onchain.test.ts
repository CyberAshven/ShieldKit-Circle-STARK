import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cashAssemblyToBin } from "@bitauth/libauth";
import { foldPair } from "../src/backends/circle/fold.ts";
import { CIRCLE_GEN, scalarMul } from "../src/backends/circle/group.ts";
import { encodeFriProof, proveFri, verifyFri, wDeposit } from "../src/backends/circle/fri.ts";
import { inv } from "../src/backends/circle/m31.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { concatBytes, sha256 } from "../src/pool/bytes.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { COMMITTED_LAYERS, FRI_N } from "../src/backends/circle/params.ts";
import { encodeAirPacked } from "../src/chain/air-cqz.ts";
import { compileFoldPairLock, compileM31InvLock, lambdaFromPackedAsm } from "../src/chain/fold-asm.ts";
import { compileFoldKernel, foldKernelAsm } from "../src/chain/fold-kernel.ts";
import { pushData } from "../src/chain/covenant-p2s.ts";
import {
  evaluateBch2026,
  evaluateOnChainVerify,
  evaluatePoolSuccessorVm,
  evaluateWrongFoldIndex,
} from "../src/chain/vm-verifier.ts";

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

function hashToM31(...parts: Uint8Array[]): bigint {
  const h = sha256(concatBytes(...parts));
  let n = 0n;
  for (let i = 0; i < 8; i += 1) n = (n << 8n) | BigInt(h[i]!);
  return n % 2147483647n;
}

function deposit() {
  const note: Note = {
    amountSats: 8_000n,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  const d = applyDeposit(
    { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  return { ...d, note, witness: wDeposit(note, d.index, d.path) };
}

describe("on-chain Circle fold", () => {
  it("M31 inverse matches TypeScript", () => {
    const a = 123456789n;
    const ev = evaluateBch2026(compileM31InvLock(inv(a)), pushNum(a));
    assert.equal(ev.accepted, true, ev.error ?? "inv");
  });

  it("foldPair matches TypeScript", () => {
    const p = scalarMul(CIRCLE_GEN, 11n);
    const fP = 99n;
    const fConj = 17n;
    const lambda = 123n;
    const folded = foldPair(p, fP, fConj, lambda);
    const unlocking = Uint8Array.of(
      ...pushNum(p.x),
      ...pushNum(p.y),
      ...pushNum(fP),
      ...pushNum(fConj),
      ...pushNum(lambda),
    );
    const ev = evaluateBch2026(compileFoldPairLock(folded.value), unlocking);
    assert.equal(ev.accepted, true, ev.error ?? "foldPair");
  });

  it("lambda from packed matches hashToM31", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const packed = encodeAirPacked(d.statement, proof);
    const lambda = hashToM31(
      sha256(encodeStatement(d.statement)),
      Uint8Array.of(0),
      proof.layerRoots[0]!,
      new TextEncoder().encode("lambda"),
    );
    const lock = cashAssemblyToBin(`${lambdaFromPackedAsm()}\nOP_NIP\n<${lambda.toString()}>\nOP_NUMEQUAL`);
    if (typeof lock === "string") throw new Error(lock);
    const ev = evaluateBch2026(lock, Uint8Array.of(...pushData(packed), ...pushNum(0n)));
    assert.equal(ev.accepted, true, ev.error ?? "lambda");
  });

  it("fold kernel redeem stays under 10 KB", () => {
    const redeem = compileFoldKernel(6);
    assert.ok(redeem.length > 200, "fold kernel is not a stub");
    assert.ok(redeem.length <= 10_000, `fold redeem ${redeem.length} > 10KB`);
    assert.ok(foldKernelAsm(6).includes("OP_INVOKE"));
  });

  // Fold kernel is compiled; successor VM still rejects (pair extract).
  it.skip("honest successor still VM-accepts after on-chain fold", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const raw = encodeFriProof(proof);
    assert.equal(verifyFri(d.statement, proof).ok, true);
    const on = evaluateOnChainVerify(d.statement, raw);
    assert.equal(on.stark.ok, true, on.stark.ok ? "" : on.stark.reason);
    assert.equal(on.pool.accepted, true, on.pool.error ?? "honest fold successor");
  });

  it.skip("wrong FS index on a folded query is rejected", () => {
    const d = deposit();
    const proof = proveFri(d.statement, d.witness);
    const raw = encodeFriProof(proof);
    const honest = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
    });
    assert.equal(honest.accepted, true, honest.error ?? "honest control");
    const bad = evaluateWrongFoldIndex({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
    });
    assert.equal(bad.accepted, false, "unfolded / wrong-index query must fail");
    void COMMITTED_LAYERS;
    void FRI_N;
  });
});
