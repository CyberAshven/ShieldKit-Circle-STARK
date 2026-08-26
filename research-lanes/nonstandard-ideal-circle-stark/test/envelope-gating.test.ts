/**
 * Envelope A/B/C size + VM gates for occupancy packing.
 * A: 36-query fused folds in one standard tx ≤ 100 KB (omits B booleanity + note-auth).
 * B: consensus ≤ 1 MB, honest accept, occupancy-only leftover + honest T reject.
 * C: B's 36 queries chunked; each hop ≤ 100 KB and > 20 KB; tape tip binds.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import {
  encodeFriProof,
  proveFri,
  proveFromTLde,
  wDeposit,
  wWithdraw,
} from "../src/backends/circle/fri.ts";
import { algebraicCQuotientLde } from "../src/backends/circle/air.ts";
import { circleDomain } from "../src/backends/circle/fri.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { FRI_N, FRI_QUERIES, FRI_VERSION, GRIND_BITS, TRACE_LEN } from "../src/backends/circle/params.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { compileChainedWithdraw } from "../src/chain/chained.ts";
import { booleanityKernelCount } from "../src/chain/booleanity-kernel.ts";
import { slotRCqzBodyBlobAsm } from "../src/chain/r-kernel.ts";
import { bindPackedNfAndIdAsm } from "../src/chain/air-cqz.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { foldKernelCount, foldQueriesPerKernel } from "../src/chain/fold-kernel.ts";
import {
  CONSENSUS_TX_BYTES,
  KERNEL_UNLOCK_PAD_HIGH,
  RELAY_STANDARD_TX_BYTES,
  UNLOCKING_MAX_BYTES,
} from "../src/chain/envelope.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { encodePublicPaa1, emptyState, utxoValueFor } from "../src/pool/state.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));

function leak(raw: Uint8Array, note: Note): boolean {
  const h = Buffer.from(raw).toString("hex");
  return (
    h.includes(Buffer.from(note.rho).toString("hex")) ||
    h.includes(Buffer.from(note.ownerSecret).toString("hex"))
  );
}

function maxUnlock(raw: Uint8Array): { n: number; pad: number } {
  const tx = decodeTransaction(raw);
  if (typeof tx === "string") throw new Error(tx);
  const lens = tx.inputs.map((i) => i.unlockingBytecode.length);
  return { n: Math.max(...lens), pad: lens.filter((x) => x === KERNEL_UNLOCK_PAD_HIGH).length };
}

function mixWithdraw() {
  const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
  const d = applyDeposit(
    { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
    note,
  );
  const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
  const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
  return { note, d, w, proof, change: w.created?.note };
}

describe("envelope A/B/C occupancy gating", () => {
  it("occupancy params stay 36q / 20 grind / TRACE 64 / FRI11", () => {
    assert.equal(FRI_QUERIES, 36);
    assert.equal(GRIND_BITS, 20);
    assert.equal(TRACE_LEN, 64);
    assert.equal(FRI_VERSION, 11);
    assert.equal(foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS), 6);
    assert.equal(foldQueriesPerKernel(SLOT_KERNEL_COUNT_CONSENSUS), 6);
    assert.equal(booleanityKernelCount(SLOT_KERNEL_COUNT_CONSENSUS, false), 0);
    assert.equal(booleanityKernelCount(SLOT_KERNEL_COUNT_CONSENSUS, true), 3);
    const fused = slotRCqzBodyBlobAsm(1, 7, 0);
    assert.equal(
      /OP_0\s*\nOP_NUMEQUALVERIFY/.test(fused),
      false,
      "fused leftover must not be vacuous N=0",
    );
    assert.ok(fused.includes("OP_NUMEQUALVERIFY"), "fused leftover EQUALVERIFYs (q-R)·Z against nTable");
    const nfBind = bindPackedNfAndIdAsm();
    assert.ok(nfBind.includes("<96>"), "cqz binds packed nullifierRoot beyond noteRoot");
  });

  it(
    "A: occupancy 36-query fused folds in one standard tx ≤ 100 KB, silent, no pad",
    { timeout: 180_000 },
    () => {
      const { note, w, proof, change } = mixWithdraw();
      const measured = compileCovenantSuccessor({
        wallet: createLabWallet(),
        feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 2_000_000 },
        pool: {
          tx_hash: "11".repeat(32),
          tx_pos: 0,
          value: utxoValueFor(w.statement.oldState),
          category: new Uint8Array(32).fill(0x11),
          commitment: encodePublicPaa1(w.statement.oldState),
        },
        newState: w.statement.newState,
        proof,
        statement: w.statement,
        lockKind: "p2sh32",
        envelope: "standard",
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        note,
        change,
      });
      const u = maxUnlock(measured.raw);
      assert.ok(measured.txBytes <= RELAY_STANDARD_TX_BYTES, `A txBytes ${measured.txBytes}`);
      assert.ok(measured.txBytes > 50_000, `A occupancy packing, got ${measured.txBytes}`);
      assert.ok(u.n <= UNLOCKING_MAX_BYTES, `A unlock ${u.n}`);
      assert.equal(u.pad, 0, "no KERNEL_UNLOCK_PAD");
      assert.equal(leak(measured.raw, note), false, "A unlocking silent");
      assert.equal(foldKernelCount(SLOT_KERNEL_COUNT_CONSENSUS) * foldQueriesPerKernel(SLOT_KERNEL_COUNT_CONSENSUS), 36);
      const vm = evaluatePoolSuccessorVm({
        oldState: w.statement.oldState,
        newState: w.statement.newState,
        proof,
        statement: w.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: true,
        booleanity: false,
        note,
        change,
      });
      assert.equal(vm.accepted, true, vm.error ?? "A occupancy VM");
    },
  );

  it(
    "B: consensus ≤ 1 MB, honest accept, occupancy-only leftover + honest T reject",
    { timeout: 180_000 },
    () => {
      const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
      const d = applyDeposit(
        { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
        note,
      );
      const wit = wDeposit(note, d.index, d.path);
      const honest = proveFri(d.statement, wit);
      const raw = encodeFriProof(honest);
      const measured = compileCovenantSuccessor({
        wallet: createLabWallet(),
        feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 2_000_000 },
        pool: {
          tx_hash: "11".repeat(32),
          tx_pos: 0,
          value: utxoValueFor(d.statement.oldState),
          category: new Uint8Array(32).fill(0x11),
          commitment: encodePublicPaa1(d.statement.oldState),
        },
        newState: d.statement.newState,
        proof: raw,
        statement: d.statement,
        lockKind: "p2sh32",
        envelope: "consensus",
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        note,
      });
      const u = maxUnlock(measured.raw);
      assert.ok(measured.txBytes <= CONSENSUS_TX_BYTES, `B txBytes ${measured.txBytes}`);
      assert.ok(u.n <= UNLOCKING_MAX_BYTES, `B unlock ${u.n}`);
      assert.equal(u.pad, 0);
      assert.equal(leak(measured.raw, note), false);
      const vm = evaluatePoolSuccessorVm({
        oldState: d.statement.oldState,
        newState: d.statement.newState,
        proof: raw,
        statement: d.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
      });
      assert.equal(vm.accepted, true, vm.error ?? "B honest VM");
      const { qLde } = algebraicCQuotientLde(
        d.statement,
        circleDomain(TRACE_LEN),
        circleDomain(FRI_N),
        defaultInternalHash(),
      );
      const occ = proveFromTLde(d.statement, qLde, honest.auth, {
        hashRoot: honest.hashRoot,
        hashLeaves: honest.hashLeaves,
        hashBitRoot: honest.hashBitRoot,
      });
      const occVm = evaluatePoolSuccessorVm({
        oldState: d.statement.oldState,
        newState: d.statement.newState,
        proof: encodeFriProof(occ),
        statement: d.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
      });
      assert.equal(occVm.accepted, false, "occupancy-only leftover + honest T must VM-reject");
    },
  );

  it("C: hops ≤ 100 KB and > 20 KB, tape tip binds pay hop", { timeout: 180_000 }, () => {
    const { note, w, proof, change } = mixWithdraw();
    const chain = compileChainedWithdraw({
      wallet: createLabWallet(),
      tapeUtxo: { tx_hash: "aa".repeat(32), tx_pos: 0, value: 400_000 },
      digest: proof.slice(0, 32),
      proof,
      pool: {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: utxoValueFor(w.statement.oldState),
        category: new Uint8Array(32).fill(0x11),
        commitment: encodePublicPaa1(w.statement.oldState),
      },
      newState: w.statement.newState,
      statement: w.statement,
      note,
      change,
    });
    assert.ok(chain.hops.length >= 2);
    const hop0 = decodeTransaction(chain.hops[0]!.raw);
    const hop3 = decodeTransaction(chain.hops[3]!.raw);
    if (typeof hop0 === "string") throw new Error(hop0);
    if (typeof hop3 === "string") throw new Error(hop3);
    assert.ok(
      hop0.inputs.length > hop3.inputs.length,
      "C hops 0-2 carry B booleanity extras",
    );
    assert.ok(chain.hops[0]!.txBytes > chain.hops[3]!.txBytes, "completeness hops are larger");
    for (const [i, hop] of chain.hops.entries()) {
      const u = maxUnlock(hop.raw);
      assert.ok(hop.txBytes <= RELAY_STANDARD_TX_BYTES, `C hop ${i} ${hop.txBytes}`);
      assert.ok(hop.txBytes > 20_000, `C hop ${i} stub ${hop.txBytes}`);
      assert.ok(u.n <= UNLOCKING_MAX_BYTES, `C hop ${i} unlock ${u.n}`);
      assert.equal(u.pad, 0);
      assert.equal(leak(hop.raw, note), false);
    }
    const pay = chain.hops[chain.payIndex]!;
    const tapeTip = chain.hops[chain.payIndex - 1]!;
    const payTx = decodeTransaction(pay.raw);
    if (typeof payTx === "string") throw new Error(payTx);
    assert.equal(
      payTx.inputs.some(
        (inp) => Buffer.from(inp.outpointTransactionHash).toString("hex") === tapeTip.txid && inp.outpointIndex === 1,
      ),
      true,
      "pay hop spends counted tape tip",
    );
  });

  it("compileCovenantSuccessor occupancy A is stable across two compiles", { timeout: 180_000 }, () => {
    const { note, w, proof, change } = mixWithdraw();
    const once = () =>
      compileCovenantSuccessor({
        wallet: createLabWallet(),
        feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: 2_000_000 },
        pool: {
          tx_hash: "11".repeat(32),
          tx_pos: 0,
          value: utxoValueFor(w.statement.oldState),
          category: new Uint8Array(32).fill(0x11),
          commitment: encodePublicPaa1(w.statement.oldState),
        },
        newState: w.statement.newState,
        proof,
        statement: w.statement,
        lockKind: "p2sh32",
        envelope: "standard",
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        note,
        change,
      });
    const a = once();
    const b = once();
    assert.equal(a.raw.length === 0, false);
    assert.equal(b.raw.length === 0, false);
    assert.ok(a.txBytes <= RELAY_STANDARD_TX_BYTES);
    assert.ok(b.txBytes <= RELAY_STANDARD_TX_BYTES);
    assert.ok(Math.abs(a.txBytes - b.txBytes) < 500, `launch size class ${a.txBytes} vs ${b.txBytes}`);
  });
});
