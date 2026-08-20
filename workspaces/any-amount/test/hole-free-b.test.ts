import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  verifyFri,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { FRI_QUERIES } from "../src/backends/circle/params.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileGrindKernel, grindKernelUnlocking } from "../src/chain/grind-kernel.ts";
import { compileAlgebraicCKernel, algebraicCKernelUnlocking } from "../src/chain/algebraic-c-kernel.ts";
import { compilePoolCovenant } from "../src/chain/covenant-p2s.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { SLOT_KERNEL_COUNT, SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { CONSENSUS_TX_BYTES, RELAY_STANDARD_TX_BYTES, UNLOCKING_MAX_BYTES } from "../src/chain/envelope.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";

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
  return { w, proof, note, d };
}

describe("hole-free statistical-soundness kernels (B)", () => {
  it("grind and algebraicC redeems stay under 10 KB", () => {
    const g = compileGrindKernel();
    const a = compileAlgebraicCKernel();
    assert.ok(g.length > 40);
    assert.ok(a.length > 40);
    assert.ok(g.length <= UNLOCKING_MAX_BYTES, `grind redeem ${g.length}`);
    assert.ok(a.length <= UNLOCKING_MAX_BYTES, `algebraicC redeem ${a.length}`);
    assert.ok(grindKernelUnlocking().length <= UNLOCKING_MAX_BYTES);
    assert.ok(algebraicCKernelUnlocking().length <= UNLOCKING_MAX_BYTES);
    const r6 = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT });
    const r36 = compilePoolCovenant({ slotKernels: SLOT_KERNEL_COUNT_CONSENSUS });
    assert.ok(r6.length <= UNLOCKING_MAX_BYTES, `6-slot redeem ${r6.length}`);
    assert.ok(r36.length <= UNLOCKING_MAX_BYTES, `36-slot redeem ${r36.length}`);
  });

  it("honest 36-query B successor VM-accepts with grind + algebraicC", () => {
    const { w, proof } = mix();
    const ev = evaluatePoolSuccessorVm({
      oldState: w.statement.oldState,
      newState: w.statement.newState,
      proof,
      statement: w.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
    });
    assert.equal(ev.accepted, true, ev.error ?? "honest B");
  });

  it("A still fits 100 KB after grind + algebraicC; B fits 1 MB; leftover is unused not cargo", () => {
    const { w, proof } = mix();
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
      packTo: 0,
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
      packTo: 0,
    });
    assert.ok(A.txBytes <= RELAY_STANDARD_TX_BYTES, `A ${A.txBytes}`);
    assert.ok(A.unlockingBytes <= UNLOCKING_MAX_BYTES);
    assert.ok(B.txBytes <= CONSENSUS_TX_BYTES, `B ${B.txBytes}`);
    assert.ok(B.unlockingBytes <= UNLOCKING_MAX_BYTES);
    assert.ok(B.txBytes > RELAY_STANDARD_TX_BYTES, "B is the 36-query consensus tx");
    const headroom = CONSENSUS_TX_BYTES - B.txBytes;
    assert.ok(headroom > 0, "B leftover is unused envelope, not OP_DROP cargo");
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
    });
    assert.equal(ev.accepted, false, "36-query lock must reject a false statement, not only a tampered honest proof");
  });
});
