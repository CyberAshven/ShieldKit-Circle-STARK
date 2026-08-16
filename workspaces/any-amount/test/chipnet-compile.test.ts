import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { measureGenesisAndSuccessor } from "../src/chain/covenant-spend.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri, wDeposit } from "../src/backends/circle/fri.ts";
import { compilePoolCovenant } from "../src/chain/covenant-p2s.ts";
import { compileNoteMerkleWalk } from "../src/chain/note-merkle.ts";

describe("covenant five-point compile", () => {
  it("signs P2S and P2SH32 genesis plus a P2SH32 successor under envelope limits", () => {
    const note: Note = {
      amountSats: 10_000n,
      rho: crypto.getRandomValues(new Uint8Array(32)),
      ownerSecret: crypto.getRandomValues(new Uint8Array(32)),
    };
    const d = applyDeposit(
      { state: emptyState(crypto.getRandomValues(new Uint8Array(32))), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, new Uint8Array(32), 3_000n);
    const proof = encodeFriProof(proveFri(d.statement, wDeposit(note, d.index, d.path)));
    const sizes = measureGenesisAndSuccessor(d.machine.state, w.machine.state, proof);
    assert.ok(sizes.genesisP2sh32.txBytes <= 100_000);
    assert.ok(sizes.genesisP2s.txBytes <= 100_000);
    assert.ok(sizes.successorP2sh32.txBytes <= 100_000);
    assert.ok(sizes.genesisP2sh32.unlockingBytes <= 10_000);
    assert.ok(sizes.successorP2sh32.unlockingBytes <= 10_000);
    assert.notEqual(sizes.genesisP2sh32.lockP2sh32Bytes, sizes.genesisP2sh32.lockP2sBytes);
    assert.equal(sizes.genesisP2sh32.lockKind, "p2sh32");
    assert.equal(sizes.genesisP2s.lockKind, "p2s");
    assert.ok(proof.length > 100);
    assert.equal(sizes.successorP2sh32.proofSlotBytes, 0);
    assert.ok(sizes.successorP2sh32.txBytes > 10_000, "successor must carry sharded FRI, not a 1 KB stub");
    assert.ok(sizes.successorP2sh32.txBytes <= 100_000);
    const redeem = compilePoolCovenant();
    assert.ok(redeem.length > 40);
    assert.notEqual(redeem[0], 0x6a, "pool redeem is not an OP_RETURN stub");
    assert.ok(compileNoteMerkleWalk().length > 10);
  });
});
