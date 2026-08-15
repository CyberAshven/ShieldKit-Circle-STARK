import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { encodeTransaction } from "@bitauth/libauth";
import { buildMarkerTransaction, genesisStateFor } from "../src/chain/chipnet.ts";
import { createLabWallet } from "../src/chain/wallet.ts";

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
