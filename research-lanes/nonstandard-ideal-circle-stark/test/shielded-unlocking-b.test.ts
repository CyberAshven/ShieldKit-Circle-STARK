import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { createVirtualMachineBch2026, decodeTransaction, hexToBin } from "@bitauth/libauth";
import {
  BLOWUP,
  FRI_QUERIES,
  FRI_VERSION,
  GRIND_BITS,
  TRACE_LEN,
  VK_ID,
} from "../src/backends/circle/params.ts";
import { soundnessWorksheet } from "../src/backends/circle/soundness.ts";
import {
  decodeFriProof,
  encodeFriProof,
  mutateTraceAndProve,
  proveFri,
  swapShaBitAndRegrind,
  verifyFri,
  wDeposit,
} from "../src/backends/circle/fri.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { compileCovenantSuccessor } from "../src/chain/covenant-spend.ts";
import { SLOT_KERNEL_COUNT_CONSENSUS } from "../src/chain/air-cqz.ts";
import { KERNEL_UNLOCK_PAD_HIGH } from "../src/chain/envelope.ts";
import { FRI_KERNEL_INPUTS, FRI_LEFTOVER_BYTES as PAIR_LEFTOVER } from "../src/chain/fri-kernel.ts";
import { compileNoteAuthKernel, noteAuthKernelUnlocking, noteAuthPublicOpens } from "../src/chain/note-auth-kernel.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { buildPoolSuccessorTx, evaluatePoolSuccessorVm } from "../src/chain/vm-verifier.ts";
import { encodePublicPaa1, emptyState, utxoValueFor } from "../src/pool/state.ts";
import { applyDeposit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const hasPreimage = (u: Uint8Array, n: Note) => {
  const h = hex(u);
  return h.includes(hex(n.rho)) || h.includes(hex(n.ownerSecret));
};

describe("occupancy FRI10 / 124-bit start", () => {
  it("live params are occupancy FRI10 QM31 124-bit", () => {
    assert.equal(FRI_VERSION, 11);
    assert.equal(TRACE_LEN, 64);
    assert.equal(BLOWUP, 16);
    assert.equal(FRI_QUERIES, 36);
    assert.equal(GRIND_BITS, 20);
    assert.equal(VK_ID.includes("qm31"), true);
    assert.equal(VK_ID.includes("fri11"), true);
    const w = soundnessWorksheet();
    assert.equal(w.field, "QM31");
    assert.equal(w.fieldBits, 124);
    assert.equal(w.queryConjectureBits, 128);
    assert.equal(w.minBits, 124);
    assert.equal(w.minBits >= 100, true);
  });

  it("frozen Chipnet pack is the occupancy successor", () => {
    const pack = join(dirname(fileURLToPath(import.meta.url)), "../survey/artifacts/qm31-fri10");
    const hexPath = join(pack, "chipnet-successor.hex");
    const raw = hexToBin(readFileSync(hexPath, "utf8").trim());
    if (typeof raw === "string") throw new Error(raw);
    assert.equal(raw.length, 99043);
    const vk = readFileSync(join(pack, "vk.txt"), "utf8").trim();
    assert.equal(
      vk,
      "circle-fri-m31-qm31-t64-b16-q36-g20-fri10-de1f4dcf0b16d9f8cec265719673a108e2ac4703059fd9d1998d09fcd121de22",
    );
  });

  it(
    "honest occupancy successor: verifyFri + consensus VM; unlocking silent",
    { timeout: 180_000 },
    () => {
      const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
      const d = applyDeposit(
        { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
        note,
      );
      const proved = proveFri(d.statement, wDeposit(note, d.index, d.path));
      const raw = encodeFriProof(proved);
      const shipped = decodeFriProof(raw);
      const fri = verifyFri(d.statement, shipped, wDeposit(note, d.index, d.path));
      assert.equal(fri.ok, true, fri.ok ? "ok" : fri.reason);
      assert.equal(Boolean(shipped.shaBit), true, "shipped proof carries shaBit");
      assert.equal(Boolean(shipped.hashBitLde), false, "shipped proof does not carry mix SHA-LDE");
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
      assert.ok(measured.txBytes <= 1_000_000, String(measured.txBytes));
      const tx = decodeTransaction(measured.raw);
      if (typeof tx === "string") throw new Error(tx);
      const maxUnlock = Math.max(...tx.inputs.map((i) => i.unlockingBytecode.length));
      assert.ok(maxUnlock <= 10_000, String(maxUnlock));
      assert.equal(
        tx.inputs.some((i) => hasPreimage(i.unlockingBytecode, note)),
        false,
        "rho/owner must not appear in any unlocking",
      );
      const vm = evaluatePoolSuccessorVm({
        oldState: d.statement.oldState,
        newState: d.statement.newState,
        proof: raw,
        statement: d.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
      });
      assert.equal(vm.accepted, true, vm.error ?? "vm");
      const redeems = tx.inputs.map((i) => {
        const u = i.unlockingBytecode;
        return u.length;
      });
      assert.ok(Math.max(...redeems) <= 10_000);
      assert.equal(PAIR_LEFTOVER, 7200);
      assert.ok(tx.inputs[9]!.unlockingBytecode.length > 8000, "grind carries shaBit paths");
      assert.ok(tx.inputs[11]!.unlockingBytecode.length <= 10_000);
      assert.equal(
        tx.inputs.filter((i) => i.unlockingBytecode.length === KERNEL_UNLOCK_PAD_HIGH).length,
        0,
        "no KERNEL_UNLOCK_PAD",
      );
      assert.ok(compileNoteAuthKernel().length <= 10_000, "note-auth redeem ≤ 10k");
    },
  );

  it("mixed leaf, nf, or amount-auth are JS-fail and consensus VM-reject", { timeout: 180_000 }, () => {
    const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
    const other: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const wit = wDeposit(note, d.index, d.path);
    const proved = proveFri(d.statement, wit);
    const raw = encodeFriProof(proved);
    const shipped = decodeFriProof(raw);
    const mixedLeafJs = verifyFri({ ...d.statement, noteCommitment: rnd32() }, shipped, wit);
    assert.equal(mixedLeafJs.ok, false, "mixed leaf must JS-fail");
    const mixedLeafVm = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note: other,
    });
    assert.equal(mixedLeafVm.accepted, false, "mixed leaf must VM-reject");

    const wrongAmt: Note = { amountSats: 11_000n, rho: note.rho, ownerSecret: note.ownerSecret };
    const mixedAmtJs = verifyFri({ ...d.statement, amountCommitOut: rnd32() }, shipped, wit);
    assert.equal(mixedAmtJs.ok, false, "mixed amount-auth must JS-fail");
    const mixedAmtVm = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note: wrongAmt,
    });
    assert.equal(mixedAmtVm.accepted, false, "mixed amount-auth must VM-reject");

    const mixedNfJs = verifyFri({ ...d.statement, nullifier: rnd32() }, shipped, wit);
    assert.equal(mixedNfJs.ok, false, "mixed nf must JS-fail");
    const honestOpens = noteAuthPublicOpens({
      note,
      action: "DEPOSIT",
      poolInstanceId: d.statement.oldState.poolInstanceId,
    });
    const built = buildPoolSuccessorTx({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
    });
    const noteIdx = 1 + FRI_KERNEL_INPUTS + 3;
    built.transaction.inputs[noteIdx]!.unlockingBytecode = noteAuthKernelUnlocking({
      note,
      spentIndex: d.index,
      spentPath: d.path,
      createdIndex: d.index,
      createdPath: d.path,
      poolInstanceId: d.statement.oldState.poolInstanceId,
      action: "DEPOSIT",
      opens: { ...honestOpens, nf: rnd32() },
    });
    const mixedNfVm = createVirtualMachineBch2026(false).verify({
      sourceOutputs: built.sourceOutputs,
      transaction: built.transaction,
    } as never);
    assert.equal(mixedNfVm === true, false, "mixed nf must VM-reject");
  });

  it("foreign shaBit at re-opened queries is sha-bit walk JS-fail and note-auth VM-reject", { timeout: 180_000 }, () => {
    const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
    const other: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const wit = wDeposit(note, d.index, d.path);
    const proved = proveFri(d.statement, wit);
    const hash = defaultInternalHash();
    const noteIdx = 1 + FRI_KERNEL_INPUTS + 3;
    const runForeign = (label: string, foreign: { amountSats: bigint; rho: Uint8Array; owner: Uint8Array; poolInstanceId: Uint8Array; action: "DEPOSIT" | "WITHDRAW" }) => {
      const swapped = swapShaBitAndRegrind(proved, foreign, d.statement, hash);
      assert.notEqual(
        swapped.queries.map((q) => q.index).join(","),
        proved.queries.map((q) => q.index).join(","),
        `${label}: occupancy queries must re-open at the new FS indices`,
      );
      const raw = encodeFriProof(swapped);
      const shipped = decodeFriProof(raw);
      assert.equal(Boolean(shipped.shaBit), true, `${label}: shipped proof carries shaBit`);
      assert.equal(Boolean(shipped.hashBitLde), false, `${label}: shipped proof does not carry mix SHA-LDE`);
      const js = verifyFri(d.statement, shipped, wit);
      assert.equal(js.ok, false, `${label} must JS-fail`);
      assert.equal(!js.ok && js.reason, "sha-bit walk", js.ok ? "ok" : js.reason);
      const built = buildPoolSuccessorTx({
        oldState: d.statement.oldState,
        newState: d.statement.newState,
        proof: raw,
        statement: d.statement,
        slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
        standard: false,
        note,
      });
      const vm = createVirtualMachineBch2026(false);
      const noteAuth = vm.evaluate({
        inputIndex: noteIdx,
        sourceOutputs: built.sourceOutputs,
        transaction: built.transaction,
      } as never);
      assert.equal(vm.stateSuccess(noteAuth) === true, false, `${label} must VM-reject note-auth`);
      for (let f = 0; f < 6; f += 1) {
        const fold = vm.evaluate({
          inputIndex: noteIdx + 1 + f,
          sourceOutputs: built.sourceOutputs,
          transaction: built.transaction,
        } as never);
        assert.equal(vm.stateSuccess(fold), true, `${label}: occupancy fold ${f} must accept`);
      }
    };
    runForeign("foreign leaf/amount", {
      amountSats: other.amountSats,
      rho: other.rho,
      owner: other.ownerSecret,
      poolInstanceId: d.statement.oldState.poolInstanceId,
      action: "DEPOSIT",
    });
    runForeign("foreign nf", {
      amountSats: note.amountSats,
      rho: note.rho,
      owner: note.ownerSecret,
      poolInstanceId: d.statement.oldState.poolInstanceId,
      action: "WITHDRAW",
    });
  });

  it("mutated FRI proof JS-fail and consensus VM-reject", { timeout: 180_000 }, () => {
    const note: Note = { amountSats: 10_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const wit = wDeposit(note, d.index, d.path);
    const bad = mutateTraceAndProve(d.statement, 0, wit);
    const raw = encodeFriProof(bad);
    const shipped = decodeFriProof(raw);
    const fri = verifyFri(d.statement, shipped, wit);
    assert.equal(fri.ok, false, "mutated proof must JS-fail");
    const vm = evaluatePoolSuccessorVm({
      oldState: d.statement.oldState,
      newState: d.statement.newState,
      proof: raw,
      statement: d.statement,
      slotKernels: SLOT_KERNEL_COUNT_CONSENSUS,
      standard: false,
      note,
    });
    assert.equal(vm.accepted, false, "mutated proof must VM-reject");
  });
});
