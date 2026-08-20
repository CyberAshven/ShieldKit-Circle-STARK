import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { compileCovenantSuccessor, compileFundVerifierKernels } from "../src/chain/covenant-spend.ts";
import { createLabWallet, p2pkhLockingOf } from "../src/chain/wallet.ts";
import { DUST_SATS, successorFeeCoinSats, successorFeeSats } from "../src/chain/envelope.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

describe("fee coin sized to the fee; fresh change address", () => {
  it("successor change is not the funder lock; fee coin is fee+dust", () => {
    const note: Note = { amountSats: 20_000n, rho: rnd32(), ownerSecret: rnd32() };
    const d = applyDeposit(
      { state: emptyState(rnd32()), notes: new IncrementalMerkle(), nullifiers: new NullifierSet() },
      note,
    );
    const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
    const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
    const funder = createLabWallet();
    const feeCoin = Number(successorFeeCoinSats("standard"));
    const measured = compileCovenantSuccessor({
      wallet: funder,
      feeUtxo: { tx_hash: "33".repeat(32), tx_pos: 0, value: feeCoin },
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
    });
    const decoded = decodeTransaction(measured.raw);
    if (typeof decoded === "string") throw new Error(decoded);
    const changeOut = decoded.outputs[decoded.outputs.length - 1]!;
    assert.equal(changeOut.valueSatoshis, DUST_SATS);
    assert.notDeepEqual(changeOut.lockingBytecode, p2pkhLockingOf(funder));
    const funderFee = BigInt(feeCoin) - changeOut.valueSatoshis;
    assert.equal(funderFee, successorFeeSats("standard"));
  });

  it("kernel fund splits leftover treasury off the fee coin", () => {
    const wallet = createLabWallet();
    const funded = compileFundVerifierKernels(
      wallet,
      { tx_hash: "44".repeat(32), tx_pos: 0, value: 5_000_000 },
      1_000,
    );
    assert.equal(funded.changeValue, Number(successorFeeCoinSats("standard")));
    assert.ok(funded.treasuryValue !== undefined && funded.treasuryValue > 1_000_000);
    assert.ok(funded.treasuryAddress && funded.treasuryAddress.startsWith("bchtest:"));
    const decoded = decodeTransaction(funded.raw);
    if (typeof decoded === "string") throw new Error(decoded);
    const feeOut = decoded.outputs[funded.changePos]!;
    assert.equal(feeOut.valueSatoshis, BigInt(funded.changeValue));
    assert.deepEqual(feeOut.lockingBytecode, p2pkhLockingOf(wallet));
    const treOut = decoded.outputs[funded.treasuryPos!]!;
    assert.equal(treOut.valueSatoshis, BigInt(funded.treasuryValue!));
    assert.notDeepEqual(treOut.lockingBytecode, p2pkhLockingOf(wallet));
  });
});
