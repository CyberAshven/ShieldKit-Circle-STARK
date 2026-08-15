import test from 'node:test';
import assert from 'node:assert/strict';

import {
  encodeScriptTransactionFixture,
  evaluateScriptFixture,
} from '../../research-lanes/bch-shielded-pool-design/p2/bch-kernels/m31-kernel.mjs';

import {
  hashMerkleNode,
} from '../../src/circle-fri/commitment.mjs';

import {
  buildBchM31MultiproofRedeemBytecode,
  createBchM31MultiproofFixture,
  evaluateBchM31MultiproofP2sh32,
  materializeBchM31MultiproofP2sh32,
} from '../../src/circle-fri/bch-multiproof-kernel.mjs';

const codeword = (length) => {
  let state = 0x1234_5678_9abcn;
  return Array.from({ length }, () => {
    state = (state * 6_364_136_223_846_793_005n + 1_442_695_040_888_963_407n) & ((1n << 64n) - 1n);
    return (state >> 11n) % 2_147_483_647n;
  });
};

test('BCH-2026 P2SH32 accepts canonical two-leaf M31 multiproofs through a 512-leaf tree', () => {
  for (const [length, indices] of [[2, [0, 1]], [8, [1, 6]], [32, [8, 13]], [512, [7, 510]]]) {
    const fixture = createBchM31MultiproofFixture({ values: codeword(length), indices });
    const materialized = materializeBchM31MultiproofP2sh32(fixture);
    const result = evaluateBchM31MultiproofP2sh32(fixture);
    assert.equal(result.accepted, true, `${length}/${indices}: ${result.error ?? 'rejected'}`);
    assert.equal(result.standard, true);
    assert.equal(fixture.canonicalBottomUpFrontier, true);
    assert.equal(materialized.lockingBytecode.length, 35);
    assert.ok(materialized.redeemBytecode.length <= 10_000);
    assert.ok(materialized.unlockingBytecode.length <= 10_000);
  }
});

test('512-leaf two-leaf multiproof records actual standard-VM and transaction metrics', () => {
  const fixture = createBchM31MultiproofFixture({ values: codeword(512), indices: [7, 510] });
  const materialized = materializeBchM31MultiproofP2sh32(fixture);
  const result = evaluateBchM31MultiproofP2sh32(fixture);
  const wires = encodeScriptTransactionFixture(materialized);
  assert.equal(fixture.frontier.length, 16);
  assert.equal(materialized.redeemBytecode.length, 686);
  assert.equal(materialized.operandUnlockingBytecode.length, 562);
  assert.equal(materialized.unlockingBytecode.length, 1_251);
  assert.equal(wires.transactionHex.length / 2, 1_314);
  assert.equal(result.metrics.operationCost, 159_874);
  assert.equal(result.metrics.hashDigestIterations, 67);
  assert.equal(result.metrics.stackMaximums.cumulativeMemoryItems, 11);
  assert.equal(result.metrics.stackMaximums.elementBytes, 686);
  assert.equal(result.metrics.signatureCheckCount, 0);
  assert.ok(result.metrics.operationCost < result.metrics.limits.maximumOperationCost);
});

test('one fixed tree length produces one shared lock for every runtime index pair', () => {
  const values = codeword(512);
  const pairs = [[7, 510], [8, 13], [100, 101], [254, 255]];
  const materialized = pairs.map((indices) => materializeBchM31MultiproofP2sh32(
    createBchM31MultiproofFixture({ values, indices }),
  ));
  for (const candidate of materialized.slice(1)) {
    assert.deepEqual(candidate.redeemBytecode, materialized[0].redeemBytecode);
    assert.deepEqual(candidate.lockingBytecode, materialized[0].lockingBytecode);
  }
  assert.equal(new Set(materialized.map((candidate) => candidate.unlockingBytecode.length)).size > 1, true);
});

test('the shared lock accepts every ordered pair in a small committed tree', () => {
  const values = codeword(16);
  const expectedRedeem = buildBchM31MultiproofRedeemBytecode(
    createBchM31MultiproofFixture({ values, indices: [0, 1] }),
  );
  let pairCount = 0;
  for (let index0 = 0; index0 < values.length; index0 += 1) {
    for (let index1 = index0 + 1; index1 < values.length; index1 += 1) {
      const fixture = createBchM31MultiproofFixture({ values, indices: [index0, index1] });
      assert.deepEqual(buildBchM31MultiproofRedeemBytecode(fixture), expectedRedeem);
      assert.equal(evaluateBchM31MultiproofP2sh32(fixture).accepted, true, `${index0},${index1}`);
      pairCount += 1;
    }
  }
  assert.equal(pairCount, 120);
});

test('runtime root, values, and canonical frontier are all binding', () => {
  const fixture = createBchM31MultiproofFixture({ values: codeword(32), indices: [8, 13] });
  const redeem = buildBchM31MultiproofRedeemBytecode(fixture);

  const wrongRoot = structuredClone(fixture);
  wrongRoot.root[0] ^= 1;
  assert.deepEqual(buildBchM31MultiproofRedeemBytecode(wrongRoot), redeem);
  assert.equal(evaluateBchM31MultiproofP2sh32(wrongRoot).accepted, false);

  const wrongValue = structuredClone(fixture);
  wrongValue.rawValues = wrongValue.values.map((value) => new Uint8Array([
    Number(value & 0xffn), Number((value >> 8n) & 0xffn), Number((value >> 16n) & 0xffn), Number((value >> 24n) & 0xffn),
  ]));
  wrongValue.rawValues[1][0] ^= 1;
  assert.equal(evaluateBchM31MultiproofP2sh32(wrongValue).accepted, false);

  const wrongFrontier = structuredClone(fixture);
  wrongFrontier.frontier[0][0] ^= 1;
  assert.equal(evaluateBchM31MultiproofP2sh32(wrongFrontier).accepted, false);
});

test('the kernel rejects ambiguous index and frontier encodings before or during VM execution', () => {
  const values = codeword(8);
  assert.throws(() => createBchM31MultiproofFixture({ values, indices: [4, 4] }), /strictly increasing and unique/);
  assert.throws(() => createBchM31MultiproofFixture({ values, indices: [6, 1] }), /strictly increasing and unique/);

  const fixture = createBchM31MultiproofFixture({ values, indices: [1, 6] });
  const truncated = structuredClone(fixture);
  truncated.frontier.pop();
  assert.equal(evaluateBchM31MultiproofP2sh32(truncated).accepted, false);

  const unused = structuredClone(fixture);
  unused.frontier.push(new Uint8Array(32));
  assert.equal(evaluateBchM31MultiproofP2sh32(unused).accepted, false);

  // Caller-supplied frontier length is never a loop bound: even rebinding the
  // runtime root to an extra level cannot reinterpret the fixed tree length.
  const reboundUnused = structuredClone(fixture);
  const extraSibling = new Uint8Array(32).fill(7);
  reboundUnused.frontier.push(extraSibling);
  reboundUnused.root = hashMerkleNode(reboundUnused.root, extraSibling);
  assert.equal(evaluateBchM31MultiproofP2sh32(reboundUnused).accepted, false);

  const materialized = materializeBchM31MultiproofP2sh32(fixture);
  const redeemPush = Uint8Array.from([
    0x4d,
    materialized.redeemBytecode.length & 0xff,
    materialized.redeemBytecode.length >>> 8,
    ...materialized.redeemBytecode,
  ]);
  const extraWitness = evaluateScriptFixture({
    lockingBytecode: materialized.lockingBytecode,
    unlockingBytecode: Uint8Array.from([
      ...materialized.operandUnlockingBytecode,
      1, 0x42, // an otherwise-unused extra frontier-like stack item
      ...redeemPush,
    ]),
  });
  assert.equal(extraWitness.accepted, false);

  const noncanonicalField = structuredClone(fixture);
  noncanonicalField.rawValues = [Uint8Array.of(0xff, 0xff, 0xff, 0x7f), new Uint8Array([1, 0, 0, 0])];
  assert.equal(evaluateBchM31MultiproofP2sh32(noncanonicalField).accepted, false);

  const noncanonicalIndex = structuredClone(fixture);
  noncanonicalIndex.rawIndices = [Uint8Array.of(1, 0), Uint8Array.of(6)];
  assert.equal(evaluateBchM31MultiproofP2sh32(noncanonicalIndex).accepted, false);
});
