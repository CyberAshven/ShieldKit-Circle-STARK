import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeTransaction } from "@bitauth/libauth";
import { encodeFriProof, proveFri, wDeposit, wWithdraw } from "../src/backends/circle/fri.ts";
import { applyDeposit, applyWithdraw } from "../src/pool/transition.ts";
import { IncrementalMerkle, NullifierSet, type Note } from "../src/pool/notes.ts";
import { emptyState, encodePublicPaa1, utxoValueFor } from "../src/pool/state.ts";
import { LAB_PAYOUT_DIGEST } from "../src/chain/payout.ts";
import { createLabWallet } from "../src/chain/wallet.ts";
import {
  CHAINED_HOPS_DEFAULT,
  CHAINED_HOPS_MAX,
  CHAINED_TX_BYTES,
  RELAY_STANDARD_TX_BYTES,
  TAPE_TIMEOUT_CSV,
  parseChainedHops,
  parseTxEnvelope,
} from "../src/chain/envelope.ts";
import { broadcastChained, compileChainedWithdraw, TAPE_MAGIC } from "../src/chain/chained.ts";

function rnd32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function mixProof() {
  const note: Note = {
    amountSats: 20_000n,
    rho: rnd32(),
    ownerSecret: rnd32(),
  };
  const d = applyDeposit(
    {
      state: emptyState(rnd32()),
      notes: new IncrementalMerkle(),
      nullifiers: new NullifierSet(),
    },
    note,
  );
  const w = applyWithdraw(d.machine, note, d.index, LAB_PAYOUT_DIGEST, 7_777n);
  const proof = encodeFriProof(proveFri(w.statement, wWithdraw(note, d.index, w.path, w.created)));
  return { w, proof };
}

describe("envelope A/B/C parse", () => {
  it("maps a/b/c and long names onto the three envelopes", () => {
    assert.equal(parseTxEnvelope("a"), "standard");
    assert.equal(parseTxEnvelope("standard"), "standard");
    assert.equal(parseTxEnvelope("B"), "consensus");
    assert.equal(parseTxEnvelope("consensus"), "consensus");
    assert.equal(parseTxEnvelope("c"), "chained");
    assert.equal(parseTxEnvelope("chained"), "chained");
    assert.throws(() => parseTxEnvelope("d"), /envelope/);
    assert.equal(parseChainedHops(3), CHAINED_HOPS_DEFAULT);
    assert.throws(() => parseChainedHops(1), /hops/);
    assert.throws(() => parseChainedHops(CHAINED_HOPS_MAX + 1), /hops/);
  });
});

describe("envelope C chained tape + last-hop pay", () => {
  it("pre-signs tape hops with zero payouts and pays only on the last hop", () => {
    const { w, proof } = mixProof();
    const wallet = createLabWallet();
    const chain = compileChainedWithdraw({
      wallet,
      tapeUtxo: { tx_hash: "aa".repeat(32), tx_pos: 0, value: 50_000 },
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
    });
    assert.equal(chain.envelope, "chained");
    assert.equal(chain.hops.length, CHAINED_HOPS_DEFAULT);
    assert.equal(chain.payIndex, CHAINED_HOPS_DEFAULT - 1);
    assert.ok(chain.totalBytes <= CHAINED_TX_BYTES);
    assert.ok(chain.totalBytes > chain.hops[chain.payIndex]!.txBytes);

    for (let i = 0; i < chain.payIndex; i += 1) {
      const hop = chain.hops[i]!;
      assert.equal(hop.role, "tape");
      assert.equal(hop.payoutCount, 0);
      assert.ok(hop.txBytes <= RELAY_STANDARD_TX_BYTES);
      const decoded = decodeTransaction(hop.raw);
      if (typeof decoded === "string") throw new Error(decoded);
      assert.equal(decoded.outputs.some((o) => o.lockingBytecode[0] === 0x6a), true, "tape commits OP_RETURN");
      const opreturn = decoded.outputs.find((o) => o.lockingBytecode[0] === 0x6a)!;
      assert.ok(Buffer.from(opreturn.lockingBytecode).includes(Buffer.from(TAPE_MAGIC)));
      assert.equal(
        decoded.outputs.filter((o) => o.lockingBytecode[0] === 0x76).length,
        1,
        "tape has the next carrier, not a user payout",
      );
      assert.equal(decoded.outputs.every((o) => o.token === undefined), true, "tape must not spend the pool NFT");
    }

    const pay = chain.hops[chain.payIndex]!;
    assert.equal(pay.role, "pay");
    assert.ok(pay.payoutCount >= 1);
    assert.ok(pay.txBytes <= RELAY_STANDARD_TX_BYTES);
    const payTx = decodeTransaction(pay.raw);
    if (typeof payTx === "string") throw new Error(payTx);
    const tapeTip = chain.hops[chain.payIndex - 1]!;
    const spentTape = payTx.inputs.some(
      (inp) => Buffer.from(inp.outpointTransactionHash).toString("hex") === tapeTip.txid && inp.outpointIndex === 0,
    );
    assert.equal(spentTape, true, "pay hop must spend the tape tip so a missing hop rejects the withdraw");
    assert.equal(payTx.inputs.some((inp) => Buffer.from(inp.outpointTransactionHash).toString("hex") === "11".repeat(32)), true);
    assert.ok(payTx.outputs.some((o) => o.token !== undefined), "pay hop moves the pool");
    assert.ok(payTx.outputs.some((o) => o.lockingBytecode[0] === 0x76 && o.valueSatoshis === 7_777n));

    const timeoutTx = decodeTransaction(chain.timeout.raw);
    if (typeof timeoutTx === "string") throw new Error(timeoutTx);
    assert.equal(chain.timeout.sequence, TAPE_TIMEOUT_CSV);
    assert.equal(timeoutTx.inputs[0]!.sequenceNumber, TAPE_TIMEOUT_CSV);
    assert.equal(Buffer.from(timeoutTx.inputs[0]!.outpointTransactionHash).toString("hex"), tapeTip.txid);
    assert.equal(timeoutTx.inputs[0]!.outpointIndex, 0);
  });

  it("does not broadcast the pay hop if an earlier tape hop is rejected", async () => {
    const { w, proof } = mixProof();
    const chain = compileChainedWithdraw({
      wallet: createLabWallet(),
      tapeUtxo: { tx_hash: "aa".repeat(32), tx_pos: 0, value: 50_000 },
      hops: 2,
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
    });
    const sent: number[] = [];
    await assert.rejects(
      () =>
        broadcastChained({
          hops: chain.hops,
          electrum: async () => {
            sent.push(sent.length);
            throw new Error("missing inputs");
          },
        }),
      /missing inputs/,
    );
    assert.deepEqual(sent, [0], "must stop before the pay hop");
  });
});

describe("CLI envelope choice", () => {
  it("documents --envelope a|b|c on withdraw, measure-tx, and land", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const cli = readFileSync(join(here, "..", "src", "cli.ts"), "utf8");
    assert.match(cli, /--envelope a\|b\|c/);
    assert.match(cli, /pool land/);
    assert.match(cli, /parseTxEnvelope/);
  });
});
