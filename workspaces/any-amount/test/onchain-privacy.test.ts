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
  it("the AUDITED kernel publishes amount, rho and owner in the clear", () => {
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
    assert.ok(u.includes(hex(sp.note.rho)), "rho is on chain");
    assert.ok(u.includes(hex(sp.note.ownerSecret)), "owner is on chain");
    assert.ok(u.includes(hex(writeI64LE(sp.note.amountSats))), "amount is on chain");
  });

  it("the STEP kernel publishes the same three fields — no better, no worse", () => {
    const { b } = pool(4, 1);
    const plan = stepPlan({
      oldNfRoot: b.statement.oldState.nullifierRoot,
      poolInstanceId: b.statement.oldState.poolInstanceId,
      spends: b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })),
    });
    const u = hex(noteAuthStepUnlocking(plan.spends[0]!));
    const n = plan.spends[0]!.note;
    assert.ok(u.includes(hex(n.rho)), "rho is on chain");
    assert.ok(u.includes(hex(n.ownerSecret)), "owner is on chain");
    assert.ok(u.includes(hex(writeI64LE(n.amountSats))), "amount is on chain");
  });

  it("so a walked note links to its exact deposit: anonymity set 1", () => {
    const { deposits, b } = pool(6, 2);
    const plan = stepPlan({
      oldNfRoot: b.statement.oldState.nullifierRoot,
      poolInstanceId: b.statement.oldState.poolInstanceId,
      spends: b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })),
    });
    let linked = 0;
    for (const sp of plan.spends) {
      // An observer parses the literal pushes out of the unlocking, rebuilds the
      // note, recomputes the leaf, and matches it against the public deposit leaves.
      const leaf = commitNote(sp.note, H);
      const match = deposits.findIndex((d) => hex(d.leaf) === hex(leaf));
      assert.notEqual(match, -1, "the recomputed leaf must match a published deposit");
      linked += 1;
    }
    assert.equal(linked, 2, "every walked note is linkable");
  });

  it("batching multiplies the exposure: N walked notes reveal N owners", () => {
    for (const n of [1, 3]) {
      const { b } = pool(6, n);
      const plan = stepPlan({
        oldNfRoot: b.statement.oldState.nullifierRoot,
        poolInstanceId: b.statement.oldState.poolInstanceId,
        spends: b.spent.map((s) => ({ note: s.note, index: s.index, path: s.path })),
      });
      const owners = new Set(plan.spends.map((s) => hex(s.note.ownerSecret)));
      assert.equal(owners.size, n, `${n} walked notes have ${n} distinct owners`);
      for (const s of plan.spends) {
        assert.ok(
          hex(noteAuthStepUnlocking(s)).includes(hex(s.note.ownerSecret)),
          "and each owner is literally present in its own unlocking",
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
