import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeTransaction } from "@bitauth/libauth";
import { buildMarkerTransaction, genesisStateFor } from "../src/chain/chipnet.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import { measureGenesisAndSuccessor } from "../src/chain/covenant-spend.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState } from "../src/pool/state.ts";
import { encodeFriProof, proveFri } from "../src/backends/circle/fri.ts";

describe("chipnet marker compile", () => {
  it("signs a PAA1 OP_RETURN spend locally", () => {
    const w = createLabWallet();
    const fakeUtxo = {
      tx_hash: "11".repeat(32),
      tx_pos: 0,
      value: 100_000,
    };
    const tx = buildMarkerTransaction(w, fakeUtxo, genesisStateFor(w));
    const raw = encodeTransaction(tx);
    assert.ok(raw.length > 100);
    assert.equal(tx.outputs.length, 2);
    assert.equal(tx.outputs[1]!.valueSatoshis, 0n);
    assert.equal(tx.outputs[1]!.lockingBytecode[0], 0x6a);
  });
});

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
    const proof = encodeFriProof(proveFri(d.statement));
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
    assert.ok(sizes.genesisP2sh32.proofSlotBytes < 80);
  });
});
