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
  buildBchM31Multiproof4RedeemBytecode,
  createBchM31Multiproof4Fixture,
  evaluateBchM31Multiproof4P2sh32,
  materializeBchM31Multiproof4P2sh32,
} from '../../src/circle-fri/bch-multiproof4-kernel.mjs';

const codeword = (length) => {
  let state = 0x1234_5678_9abcn;
  return Array.from({ length }, () => {
    state = (state * 6_364_136_223_846_793_005n + 1_442_695_040_888_963_407n) & ((1n << 64n) - 1n);
    return (state >> 11n) % 2_147_483_647n;
  });
};

const encodeM31Raw = (value) => Uint8Array.of(
  Number(value & 0xffn),
  Number((value >> 8n) & 0xffn),
  Number((value >> 16n) & 0xffn),
  Number((value >> 24n) & 0xffn),
);

const encodeSmallScriptNumber = (value) => (
  value === 0 ? new Uint8Array() : Uint8Array.of(value)
);

const encodePush = (value) => {
  if (value.length <= 75) return Uint8Array.from([value.length, ...value]);
  if (value.length <= 0xff) return Uint8Array.from([0x4c, value.length, ...value]);
  return Uint8Array.from([0x4d, value.length & 0xff, value.length >>> 8, ...value]);
};

test('BCH-2026 P2SH32 accepts diverse canonical exactly-four-leaf topologies', () => {
  const cases = [
    [4, [0, 1, 2, 3]],
    [8, [0, 1, 2, 7]],
    [8, [0, 2, 4, 6]],
    [16, [1, 2, 8, 15]],
    [32, [4, 5, 6, 7]],
    [32, [0, 15, 16, 31]],
    [512, [7, 100, 254, 510]],
  ];
  for (const [length, indices] of cases) {
    const fixture = createBchM31Multiproof4Fixture({ values: codeword(length), indices });
    const materialized = materializeBchM31Multiproof4P2sh32(fixture);
    const result = evaluateBchM31Multiproof4P2sh32(fixture);
    assert.equal(result.accepted, true, `${length}/${indices}: ${result.error ?? 'rejected'}`);
    assert.equal(result.standard, true);
    assert.equal(fixture.canonicalBottomUpFrontier, true);
    assert.equal(Object.hasOwn(fixture, 'flags'), false);
    assert.equal(Object.hasOwn(fixture, 'positions'), false);
    assert.equal(materialized.lockingBytecode.length, 35);
    assert.ok(materialized.redeemBytecode.length <= 10_000);
    assert.ok(materialized.unlockingBytecode.length <= 10_000);
    assert.ok([...materialized.redeemBytecode].every((byte) => Number.isInteger(byte)));
  }
});

test('one fixed length produces one identical redeem and P2SH32 lock across index sets', () => {
  const values = codeword(512);
  const indexSets = [
    [7, 100, 254, 510],
    [8, 9, 10, 11],
    [100, 101, 102, 103],
    [0, 170, 340, 511],
  ];
  const materialized = indexSets.map((indices) => materializeBchM31Multiproof4P2sh32(
    createBchM31Multiproof4Fixture({ values, indices }),
  ));
  for (const candidate of materialized.slice(1)) {
    assert.deepEqual(candidate.redeemBytecode, materialized[0].redeemBytecode);
    assert.deepEqual(candidate.lockingBytecode, materialized[0].lockingBytecode);
  }
  assert.equal(new Set(materialized.map((candidate) => candidate.operandUnlockingBytecode.length)).size > 1, true);
});

test('the shared lock accepts every ordered four-index set in an eight-leaf tree', () => {
  const values = codeword(8);
  const expectedRedeem = buildBchM31Multiproof4RedeemBytecode(
    createBchM31Multiproof4Fixture({ values, indices: [0, 1, 2, 3] }),
  );
  let count = 0;
  for (let i0 = 0; i0 < 5; i0 += 1) {
    for (let i1 = i0 + 1; i1 < 6; i1 += 1) {
      for (let i2 = i1 + 1; i2 < 7; i2 += 1) {
        for (let i3 = i2 + 1; i3 < 8; i3 += 1) {
          const fixture = createBchM31Multiproof4Fixture({ values, indices: [i0, i1, i2, i3] });
          assert.deepEqual(buildBchM31Multiproof4RedeemBytecode(fixture), expectedRedeem);
          const result = evaluateBchM31Multiproof4P2sh32(fixture);
          assert.equal(result.accepted, true, `${i0},${i1},${i2},${i3}: ${result.error ?? 'rejected'}`);
          count += 1;
        }
      }
    }
  }
  assert.equal(count, 70);
});

test('runtime root, all values, and every canonical frontier position are binding', () => {
  const fixture = createBchM31Multiproof4Fixture({
    values: codeword(32),
    indices: [0, 15, 16, 31],
  });
  const redeem = buildBchM31Multiproof4RedeemBytecode(fixture);

  const wrongRoot = structuredClone(fixture);
  wrongRoot.root[0] ^= 1;
  assert.deepEqual(buildBchM31Multiproof4RedeemBytecode(wrongRoot), redeem);
  assert.equal(evaluateBchM31Multiproof4P2sh32(wrongRoot).accepted, false);

  for (let ordinal = 0; ordinal < 4; ordinal += 1) {
    const wrongValue = structuredClone(fixture);
    wrongValue.rawValues = wrongValue.values.map(encodeM31Raw);
    wrongValue.rawValues[ordinal][0] ^= 1;
    assert.equal(evaluateBchM31Multiproof4P2sh32(wrongValue).accepted, false, `value ${ordinal}`);
  }

  for (let ordinal = 0; ordinal < fixture.frontier.length; ordinal += 1) {
    const wrongFrontier = structuredClone(fixture);
    wrongFrontier.frontier[ordinal][ordinal % 32] ^= 1;
    assert.equal(evaluateBchM31Multiproof4P2sh32(wrongFrontier).accepted, false, `frontier ${ordinal}`);
  }

  const swappedFrontier = structuredClone(fixture);
  [swappedFrontier.frontier[0], swappedFrontier.frontier[1]] = [
    swappedFrontier.frontier[1],
    swappedFrontier.frontier[0],
  ];
  assert.equal(evaluateBchM31Multiproof4P2sh32(swappedFrontier).accepted, false);
});

test('fixed depth enforces truncation, exact frontier consumption, and rebound-root rejection', () => {
  const fixture = createBchM31Multiproof4Fixture({ values: codeword(32), indices: [0, 15, 16, 31] });

  const truncated = structuredClone(fixture);
  truncated.frontier.pop();
  assert.equal(evaluateBchM31Multiproof4P2sh32(truncated).accepted, false);

  const shortItem = structuredClone(fixture);
  shortItem.frontier[0] = shortItem.frontier[0].slice(0, -1);
  assert.equal(evaluateBchM31Multiproof4P2sh32(shortItem).accepted, false);

  const unused = structuredClone(fixture);
  unused.frontier.push(new Uint8Array(32));
  assert.equal(evaluateBchM31Multiproof4P2sh32(unused).accepted, false);

  // Rebinding the runtime root to the extra hash cannot add a caller-selected
  // level: the loop count remains fixed by the redeem's committed tree length.
  const rebound = structuredClone(fixture);
  const extraSibling = new Uint8Array(32).fill(7);
  rebound.frontier.push(extraSibling);
  rebound.root = hashMerkleNode(rebound.root, extraSibling);
  assert.equal(evaluateBchM31Multiproof4P2sh32(rebound).accepted, false);

  const materialized = materializeBchM31Multiproof4P2sh32(fixture);
  const extraStackItem = evaluateScriptFixture({
    lockingBytecode: materialized.lockingBytecode,
    unlockingBytecode: Uint8Array.from([
      1, 0x42,
      ...materialized.operandUnlockingBytecode,
      ...encodePush(materialized.redeemBytecode),
    ]),
  });
  assert.equal(extraStackItem.accepted, false);
});

test('host and runtime reject duplicate, unsorted, out-of-range, and noncanonical inputs', () => {
  const values = codeword(8);
  assert.throws(
    () => createBchM31Multiproof4Fixture({ values, indices: [0, 1, 1, 7] }),
    /strictly increasing and unique/,
  );
  assert.throws(
    () => createBchM31Multiproof4Fixture({ values, indices: [0, 2, 1, 7] }),
    /strictly increasing and unique/,
  );
  assert.throws(
    () => createBchM31Multiproof4Fixture({ values, indices: [0, 1, 2] }),
    /exactly four/,
  );

  const fixture = createBchM31Multiproof4Fixture({ values, indices: [0, 2, 4, 6] });
  const rawCases = [
    [0, 4, 2, 6],
    [0, 2, 2, 6],
    [0, 2, 4, 8],
  ];
  for (const indices of rawCases) {
    const tampered = structuredClone(fixture);
    tampered.rawIndices = indices.map(encodeSmallScriptNumber);
    assert.equal(evaluateBchM31Multiproof4P2sh32(tampered).accepted, false, `${indices}`);
  }

  const negativeIndex = structuredClone(fixture);
  negativeIndex.rawIndices = [Uint8Array.of(0x81), ...fixture.indices.slice(1).map(encodeSmallScriptNumber)];
  assert.equal(evaluateBchM31Multiproof4P2sh32(negativeIndex).accepted, false);

  const nonminimalIndex = structuredClone(fixture);
  nonminimalIndex.rawIndices = fixture.indices.map(encodeSmallScriptNumber);
  nonminimalIndex.rawIndices[1] = Uint8Array.of(2, 0);
  assert.equal(evaluateBchM31Multiproof4P2sh32(nonminimalIndex).accepted, false);

  const noncanonicalField = structuredClone(fixture);
  noncanonicalField.rawValues = fixture.values.map(encodeM31Raw);
  noncanonicalField.rawValues[0] = Uint8Array.of(0xff, 0xff, 0xff, 0x7f);
  assert.equal(evaluateBchM31Multiproof4P2sh32(noncanonicalField).accepted, false);

  const wrongWidthField = structuredClone(fixture);
  wrongWidthField.rawValues = fixture.values.map(encodeM31Raw);
  wrongWidthField.rawValues[3] = wrongWidthField.rawValues[3].slice(0, 3);
  assert.equal(evaluateBchM31Multiproof4P2sh32(wrongWidthField).accepted, false);
});

test('512-leaf four-leaf multiproof records real standard-VM transaction metrics', () => {
  const fixture = createBchM31Multiproof4Fixture({
    values: codeword(512),
    indices: [7, 100, 254, 510],
  });
  const materialized = materializeBchM31Multiproof4P2sh32(fixture);
  const result = evaluateBchM31Multiproof4P2sh32(fixture);
  const wires = encodeScriptTransactionFixture(materialized);

  assert.equal(result.accepted, true, result.error ?? 'rejected');
  assert.equal(result.standard, true);
  assert.equal(fixture.frontier.length, 27);
  assert.equal(materialized.redeemBytecode.length, 596);
  assert.equal(materialized.operandUnlockingBytecode.length, 929);
  assert.equal(materialized.unlockingBytecode.length, 1_528);
  assert.equal(wires.transactionHex.length / 2, 1_591);
  assert.equal(result.metrics.operationCost, 536_219);
  assert.equal(result.metrics.hashDigestIterations, 109);
  assert.equal(result.metrics.stackMaximums.cumulativeMemoryItems, 14);
  assert.equal(result.metrics.stackMaximums.elementBytes, 864);
  assert.equal(result.metrics.signatureCheckCount, 0);
  assert.ok(result.metrics.operationCost < result.metrics.limits.maximumOperationCost);
});
