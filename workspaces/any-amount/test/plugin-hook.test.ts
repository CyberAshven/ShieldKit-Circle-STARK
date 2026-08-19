import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { circleFriPlugin } from "../src/backends/circle/plugin.ts";
import { hashLabPlugin } from "../src/backends/hash-lab.ts";
import { wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, nullifierOf, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import {
  DEFAULT_ZKP_FAMILY,
  defaultZkpPlugin,
  describePlugins,
  zkpPluginByFamily,
  zkpPlugins,
} from "../src/plugins/registry.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function machine() {
  return {
    state: emptyState(rnd32()),
    notes: new IncrementalMerkle(),
    nullifiers: new NullifierSet(),
  };
}

describe("ZKP plugin hook on the pool statement", () => {
  it("registry default is Circle FRI; hash-lab is a second registered family", () => {
    assert.equal(DEFAULT_ZKP_FAMILY, "circle-fri-m31");
    assert.equal(defaultZkpPlugin().family, "circle-fri-m31");
    assert.ok(zkpPlugins.length >= 2);
    const families = zkpPlugins.map((p) => p.family);
    assert.ok(families.includes("circle-fri-m31"));
    assert.ok(families.includes("hash-lab-v0"));
    assert.equal(zkpPluginByFamily("circle-fri-m31").family, "circle-fri-m31");
    assert.equal(zkpPluginByFamily("hash-lab-v0").family, "hash-lab-v0");
    assert.throws(() => zkpPluginByFamily("groth16"));
    const d = describePlugins() as { defaultZkp: string; zkp: Array<{ family: string }> };
    assert.equal(d.defaultZkp, "circle-fri-m31");
    assert.ok(d.zkp.length >= 2);
  });

  it("same statement: each registered plugin prove/verify accepts; cross-family rejects", async () => {
    const note: Note = { amountSats: 12_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(machine(), note);
    const witness = wDeposit(note, d.index, d.path);

    const circleProof = await circleFriPlugin.prove(d.statement, witness);
    const circleOk = circleFriPlugin.verify(d.statement, circleProof);
    assert.equal(circleOk.ok, true, circleOk.ok ? "" : circleOk.reason);

    const labProof = await hashLabPlugin.prove(d.statement, {
      leaf: d.statement.noteCommitment,
      index: d.index,
      path: d.path,
    });
    const labOk = hashLabPlugin.verify(d.statement, labProof);
    assert.equal(labOk.ok, true, labOk.ok ? "" : labOk.reason);

    const labVsCircle = hashLabPlugin.verify(d.statement, circleProof);
    assert.equal(labVsCircle.ok, false, "Circle proof must not verify as hash-lab");
    const circleVsLab = circleFriPlugin.verify(d.statement, labProof);
    assert.equal(circleVsLab.ok, false, "hash-lab proof must not verify as Circle FRI");

    const other = applyDeposit(machine(), { amountSats: 5_000n, rho: rnd32(), ownerSecret: rnd32() });
    const crossStmt = hashLabPlugin.verify(other.statement, labProof);
    assert.equal(crossStmt.ok, false, "hash-lab proof is bound to this statement");
  });

  it("notes/nullifiers/change do not depend on which plugin proved", async () => {
    const id = rnd32();
    let m = {
      state: emptyState(id),
      notes: new IncrementalMerkle(),
      nullifiers: new NullifierSet(),
    };
    const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
    const dep = applyDeposit(m, note);
    const lab = await hashLabPlugin.prove(dep.statement, {});
    assert.equal(hashLabPlugin.verify(dep.statement, lab).ok, true);
    const circle = await circleFriPlugin.prove(dep.statement, wDeposit(note, dep.index, dep.path));
    assert.equal(circleFriPlugin.verify(dep.statement, circle).ok, true);
    assert.deepEqual(dep.machine.state.noteRoot, dep.machine.notes.root);

    const partial = applyWithdraw(dep.machine, note, dep.index, rnd32(), 5_000n);
    assert.ok(partial.change);
    assert.notDeepEqual(partial.change.rho, note.rho);
    assert.notDeepEqual(nullifierOf(partial.change, id), partial.statement.nullifier);
    assert.throws(() => applyWithdraw(partial.machine, note, dep.index, rnd32(), 1n));
    const spent = applyWithdraw(partial.machine, partial.change, partial.changeIndex!, rnd32(), partial.change.amountSats);
    const p2 = await circleFriPlugin.prove(
      spent.statement,
      wWithdraw(partial.change, partial.changeIndex!, partial.machine.notes.authPath(partial.changeIndex!)),
    );
    assert.equal(circleFriPlugin.verify(spent.statement, p2).ok, true);
  });
});
