/**
 * What a note-auth kernel reveals on chain.
 *
 * This test exists because the written claims pulled in two directions: the proof
 * one-time-pads the note preimage, and the on-chain kernel publishes it in the
 * clear. Both were true and stated separately, and nothing connected them. The
 * consequence — that a walked note is linkable to its exact deposit — was written
 * nowhere. So it is asserted here instead of described.
 *
 * These are CHARACTERISATION tests: they pin the current behaviour, including the
 * parts that are bad for privacy. If someone changes the design so the preimage
 * stops being published, these tests SHOULD fail, and the fix is to update them
 * along with STATUS.md — not to delete them.
 *
 * Applies to the audited kernel too, so envelope B and C's pay hop as landed have
 * this property. Batching multiplies it by N.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { noteAuthKernelUnlocking } from "../src/chain/note-auth-kernel.ts";
import { noteAuthStepUnlocking, stepPlan } from "../src/chain/note-auth-step-kernel.ts";
import { emptyState } from "../src/pool/state.ts";
import { applyDeposit, applyBatchExit } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, commitNote, type Note } from "../src/pool/notes.ts";
import { defaultInternalHash } from "../src/backends/circle/internal-hash.ts";
import { writeI64LE } from "../src/pool/bytes.ts";

const rnd32 = () => crypto.getRandomValues(new Uint8Array(32));
const PAYOUT = Uint8Array.of(0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac);
const H = defaultInternalHash();
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");

/** A pool with `n` deposits, of which `spend` are exited in one batch. */
function pool(n: number, spend: number) {
  let m: {
    state: ReturnType<typeof emptyState>;
    notes: IncrementalMerkle;
    nullifiers: NullifierSet;
  } = { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() };
  const deposits: Array<{ note: Note; index: number; leaf: Uint8Array }> = [];
  for (let i = 0; i < n; i += 1) {
    const note: Note = { amountSats: 1000n * BigInt(i + 1), rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(m, note);
    m = d.machine;
    deposits.push({ note, index: d.index, leaf: commitNote(note, H) });
  }
  const picked = deposits.slice(0, spend);
  const b = applyBatchExit(
    m,
    picked.map((p) => ({
      note: p.note,
      index: p.index,
      withdrawSats: p.note.amountSats,
      payoutLocking: PAYOUT,
    })),
  );
  return { deposits, b };
}

describe("what a walked note reveals on chain", () => {
  it("the AUDITED kernel does not publish amount, rho or owner", () => {
    const { b } = pool(4, 1);
    const sp = b.spent[0]!;
    const u = hex(
      noteAuthKernelUnlocking({
        note: sp.note,
        spentIndex: sp.index,
        spentPath: sp.path,
        createdIndex: 0,
        createdPath: [],
      }),
    );
    assert.equal(u.includes(hex(sp.note.rho)), false, "rho is not in unlocking");
    assert.equal(u.includes(hex(sp.note.ownerSecret)), false, "owner is not in unlocking");
    assert.equal(u.includes(hex(writeI64LE(sp.note.amountSats))), false, "amount is not in unlocking");
  });

  it("the STEP kernel does not publish amount, rho or owner", () => {
    const { b } = pool(4, 1);
    const plan = stepPlan({
      oldNfRoot: b.statement.oldState.nullifierRoot,
      poolInstanceId: b.statement.oldState.poolInstanceId,
      spends: b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })),
    });
    const u = hex(
      noteAuthStepUnlocking({ ...plan.spends[0]!, poolInstanceId: b.statement.oldState.poolInstanceId }),
    );
    const n = plan.spends[0]!.note;
    assert.equal(u.includes(hex(n.rho)), false, "rho is not in unlocking");
    assert.equal(u.includes(hex(n.ownerSecret)), false, "owner is not in unlocking");
    assert.equal(u.includes(hex(writeI64LE(n.amountSats))), false, "amount is not in unlocking");
  });

  it("a walked note's unlocking does not contain rho/owner to match the deposit", () => {
    const { b } = pool(6, 2);
    const plan = stepPlan({
      oldNfRoot: b.statement.oldState.nullifierRoot,
      poolInstanceId: b.statement.oldState.poolInstanceId,
      spends: b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })),
    });
    for (const sp of plan.spends) {
      const u = hex(noteAuthStepUnlocking({ ...sp, poolInstanceId: b.statement.oldState.poolInstanceId }));
      assert.equal(u.includes(hex(sp.note.rho)), false);
      assert.equal(u.includes(hex(sp.note.ownerSecret)), false);
    }
  });

  it("batching does not put N owners into N unlockings", () => {
    for (const n of [1, 3]) {
      const { b } = pool(6, n);
      const plan = stepPlan({
        oldNfRoot: b.statement.oldState.nullifierRoot,
        poolInstanceId: b.statement.oldState.poolInstanceId,
        spends: b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })),
      });
      for (const s of plan.spends) {
        assert.equal(
          hex(noteAuthStepUnlocking({ ...s, poolInstanceId: b.statement.oldState.poolInstanceId })).includes(
            hex(s.note.ownerSecret),
          ),
          false,
        );
      }
    }
  });

  it("the proof, by contrast, does mask the preimage", async () => {
    // The OTP masking in the PROOF is real and is a different thing from the
    // on-chain unlocking. This is why the two written claims both looked true.
    const { maskAuth, freshViewingKey } = await import("../src/backends/circle/witness-mask.ts");
    const key = freshViewingKey();
    const auth = {
      leaf: new Uint8Array(32),
      index: 0,
      path: [],
      root: new Uint8Array(32),
      nullifier: new Uint8Array(32),
      rho: new Uint8Array(32).fill(0xaa),
      owner: new Uint8Array(32).fill(0xbb),
      amountSats: 1234n,
      publicDeltaSats: 0n,
      amountCommit: new Uint8Array(32),
      createdLeaf: new Uint8Array(32),
      createdIndex: 0,
      createdPath: [],
    } as never;
    const masked = maskAuth(auth, key) as { rho: Uint8Array; owner: Uint8Array };
    assert.notDeepEqual(masked.rho, new Uint8Array(32).fill(0xaa), "rho is masked in the proof");
    assert.notDeepEqual(masked.owner, new Uint8Array(32).fill(0xbb), "owner is masked in the proof");
  });
});
