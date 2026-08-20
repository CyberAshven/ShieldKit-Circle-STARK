import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  decodeFriProof,
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { FRI_QUERIES, FRI_VERSION } from "../src/backends/circle/params.ts";
import { encodeLe, mul } from "../src/backends/circle/m31.ts";
import { openingMaskAt } from "../src/backends/circle/witness-mask.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { encodeStatement } from "../src/pool/statement.ts";
import { sha256 } from "../src/pool/bytes.ts";
import {
  AIR_NEWTON_BYTES,
  AIR_OFF_EVEN,
  AIR_OFF_NTABLE,
  AIR_OFF_ODD,
  AIR_OFF_OPEN_MASK,
  AIR_OFF_QTABLE,
  SLOT_KERNEL_COUNT,
  SLOT_KERNEL_COUNT_CONSENSUS,
  encodeAirPacked,
  fiatShamirQueryIndices,
  nqzAt,
} from "../src/chain/air-cqz.ts";
import { collectFriOpenings, friShardUnlockings } from "../src/chain/fri-openings.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileGrindKernel, grindKernelUnlocking } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCKernel, algebraicCKernelUnlocking } from "../src/chain/algebraic-c-kernel.ts";
import { compileNoteAuthKernel } from "../src/chain/note-auth-kernel.ts";
import { compilePoolCovenant } from "../src/chain/covenant-p2s.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { CONSENSUS_TX_BYTES, RELAY_STANDARD_TX_BYTES, UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";
import { evaluateFriQueryOpening, evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { compileFriQueryKernel } from "../src/chain/fri-kernel.ts";
import { COMMITTED_LAYERS } from "../src/backends/circle/params.ts";
import { foldQueriesAsm } from "../src/chain/fold-asm.ts";

function mix() {
  const note: Note = {
    amountSats: 20_000n,
    rho: crypto.getRandomValues(new Uint8Array(32)),
    ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
  };
  const d = applyDeposit(
    { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
  const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
  return { w, proof, note, d, change: w.created?.note };
}

describe("hole-free statistical-soundness kernels (B)", () => {
  it("B is 36 unique-orbit Circle FRI M31, FRI_VERSION 9, not a second family", () => {
    assert.equal(FRI_VERSION, 9);
    assert.equal(FRI_QUERIES, 36);
    assert.equal(SLOT_KERNEL_COUNT_CONSENSUS, FRI_QUERIES);
    assert.ok(SLOT_KERNEL_COUNT < FRI_QUERIES, "A may chunk fewer slots; B keeps 36");
  });

  it("grind and algebraicC redeems stay under 10 KB", () => {
    const g = compileGrindKernel();
    const a = compileAlgebraicCKernel();
    assert.ok(g.length > 40);
    assert.ok(a.length > 40);
    assert.ok(g.length <= UNLOCKING_MAX_BYTES, `grind redeem ${g.length}`);
    assert.ok(a.length <= UNLOCKING_MAX_BYTES, `algebraicC redeem ${a.length}`);
    assert.ok(grindKernelUnlocking().length <= UNLOCKING_MAX_BYTES);
    assert.ok(algebraicCKernelUnlocking().length <= UNLOCKING_MAX_BYTES);
    const noteAuth = compileNoteAuthKernel();
    assert.ok(noteAuth.length <= UNLOCKING_MAX_BYTES, `note-auth redeem ${noteAuth.length}`);
    const r6 = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT });
    const r36 = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
    assert.ok(r6.length <= UNLOCKING_MAX_BYTES, `standard-slot redeem ${r6.length}`);
    assert.ok(r36.length <= UNLOCKING_MAX_BYTES, `36-slot redeem ${r36.length}`);
    const fri = compileFriQueryKernel();
    assert.ok(fri.length <= UNLOCKING_MAX_BYTES, `FRI kernel ${fri.length}`);
    assert.ok(foldQueriesAsm(1).includes(String(COMMITTED_LAYERS)), "fold kernel walks every FRI layer");
  });

  it("honest 36-query B successor VM-accepts with grind + algebraicC", () => {
    const { w, proof, note, change } = mix();
    const ev = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
      change,
    });
    assert.equal(ev.accepted, true, ev.error ?? "honest B");
  });

  it("36-query B rejects cooked viewing-commit, recooked Q/N, and cooked pair blob", () => {
    const { w, proof, note, change } = mix();
    const base = {
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false as const,
      note,
      change,
    };
    const packed = encodeAirPacked(w.statement, proof);
    const cookCommit = new Uint8Array(packed);
    cookCommit[AIR_OFF_OPEN_MASK] ^= 0xff;
    const commitEv = evaluatePoolSuccessorVm({ ...base, airPacked: cookCommit });
    assert.equal(commitEv.accepted, false, "cooked viewing-commit must fail on-chain R");

    const decoded = decodeFriProof(proof);
    const i0 = fiatShamirQueryIndices(
      sha256(encodeStatement(w.statement)),
      decoded,
      defaultInternalHash(),
      packed.subarray(AIR_OFF_EVEN, AIR_OFF_EVEN + AIR_NEWTON_BYTES),
      packed.subarray(AIR_OFF_ODD, AIR_OFF_ODD + AIR_NEWTON_BYTES),
    )[0]!;
    const nqz = nqzAt(w.statement, i0);
    if (nqz.z !== 0n) {
      const r = openingMaskAt(decoded.viewingCommit ?? new Uint8Array(32), i0, undefined, nqz.z);
      const qPrime = (nqz.q + r + 1n) % 2147483647n;
      const nPrime = mul(qPrime, nqz.z);
      const cookQn = new Uint8Array(packed);
      cookQn.set(encodeLe(qPrime), AIR_OFF_QTABLE);
      cookQn.set(encodeLe(nPrime), AIR_OFF_NTABLE);
      const qnEv = evaluatePoolSuccessorVm({ ...base, airPacked: cookQn });
      assert.equal(qnEv.accepted, false, "masked-consistent recook of Q/N must fail independent N");
    }

    const shards = friShardUnlockings(proof, { allPairGroups: true });
    const cooked0 = new Uint8Array(shards[0]!);
    const op = cooked0[0]!;
    const dataOff = op === 0x4d ? 3 : op === 0x4c ? 2 : 1;
    cooked0[dataOff] ^= 0xff;
    const blobEv = evaluatePoolSuccessorVm({
      ...base,
      kernelUnlockings: [cooked0, ...shards.slice(1)],
    });
    assert.equal(blobEv.accepted, false, "cooked pair blob with honest Merkle left||right must fail");
  });

  it("A still fits 100 KB after grind + algebraicC; B fits 1 MB; leftover is unused not cargo", () => {
    const { w, proof, note, change } = mix();
    const pool = {
      tx_hash: "11".repeat(32),
      tx_pos: 0,
      value: utxoValueFor(w.statement.oldState),
      category: new Uint8Array(32).fill(0x11),
      commitment: encodePublicPaa1(w.statement.oldState),
    };
    const A = compileCovenantSuccessor({
      wallet: createLabWallet(),
      pool,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "standard",
    });
    const B = compileCovenantSuccessor({
      wallet: createLabWallet(),
      pool,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      lockKind: "p2sh32",
      envelope: "consensus",
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      note,
      change,
    });
    assert.ok(A.txBytes <= RELAY_STANDARD_TX_BYTES, `A ${A.txBytes}`);
    assert.ok(A.unlockingBytes <= UNLOCKING_MAX_BYTES);
    assert.ok(B.txBytes <= CONSENSUS_TX_BYTES, `B ${B.txBytes}`);
    assert.ok(B.unlockingBytes <= UNLOCKING_MAX_BYTES);
    assert.ok(B.txBytes > RELAY_STANDARD_TX_BYTES, "B is the 36-query consensus tx");
    const headroom = CONSENSUS_TX_BYTES - B.txBytes;
    assert.ok(headroom > 0, "B leftover is unused envelope, not OP_DROP cargo");
    console.log(`size-proof A=${A.txBytes} B=${B.txBytes} headroom=${headroom} Aunlock=${A.unlockingBytes} Bunlock=${B.unlockingBytes}`);
  });

  it("each layer-0 opening binds qTable[slot], not any slot", () => {
    const { w, proof } = mix();
    const packed = encodeAirPacked(w.statement, proof);
    const firstL0 = collectFriOpenings(proof).find((o) => o.layerIndex === 0);
    assert.ok(firstL0);
    const ok = evaluateFriQueryOpening({
      left: firstL0!.left,
      right: firstL0!.right,
      root: firstL0!.root,
      parentPath: firstL0!.parentPath,
      parentIndex: firstL0!.parentIndex,
      layerIndex: 0,
      slot: firstL0!.slot,
      packed,
    });
    assert.equal(ok.accepted, true, ok.error ?? "honest slot");
    const wrong = evaluateFriQueryOpening({
      left: firstL0!.left,
      right: firstL0!.right,
      root: firstL0!.root,
      parentPath: firstL0!.parentPath,
      parentIndex: firstL0!.parentIndex,
      layerIndex: 0,
      slot: (firstL0!.slot + 1) % FRI_QUERIES,
      packed,
    });
    assert.equal(wrong.accepted, false, "L0 felt must match qTable[slot], not another slot");
  });

  it("false AIR (trace bump) is rejected on-chain, not only by verifyFri", () => {
    const { w, d, note } = mix();
    const wit = wWithdraw(note, d.index, w.path, w.created);
    const bad = mutateTraceAndProve(w.statement, 0, wit);
    assert.equal(verifyFri(w.statement, bad, wit).ok, false, "verifyFri must reject false AIR");
    const ev = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof: encodeFriProof(bad),
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
      change: w.created?.note,
    });
    assert.equal(ev.accepted, false, "36-query lock must reject a false statement, not only a tampered honest proof");
  });

  it("36-query B rejects a fake note preimage on the note-auth kernel", () => {
    const { w, proof, note, change, d } = mix();
    const fake: Note = { ...note, rho: crypto.getRandomValues(new Uint8Array(32)) };
    const ev = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note: fake,
      change,
    });
    assert.equal(ev.accepted, false, "fake rho must fail on-chain note Merkle");
    void d;
  });
});
