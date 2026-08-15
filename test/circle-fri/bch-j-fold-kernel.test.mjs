import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
  add,
  mul,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  buildStandardCoset,
} from '../../src/circle-fri/circle.mjs';

import {
  createM31JFoldFixture,
  encodeM31JFoldP2sh32TransactionFixture,
  encodeM31JFoldTransactionFixture,
  evaluateM31JFold,
  evaluateM31JFoldP2sh32,
} from '../../src/circle-fri/bch-j-fold-kernel.mjs';

const point = buildStandardCoset(4)[2];
const honest = createM31JFoldFixture({
  positive: add(111n, mul(point.y, 222n)),
  negative: add(111n, mul(M31_MODULUS - point.y, 222n)),
  y: point.y,
  beta: 333n,
});

test('BCH-2026 standard VM accepts the exact J-fold relation', () => {
  const result = evaluateM31JFold(honest);
  assert.equal(result.accepted, true, result.error ?? 'VM rejected');
  assert.equal(result.standard, true);
  assert.equal(result.lockingHex.length / 2, 229);
  assert.equal(result.unlockingHex.length / 2, 30);
  assert.equal(result.metrics.signatureCheckCount, 0);
  assert.equal(result.metrics.hashDigestIterations, 0);
  assert.ok(result.metrics.operationCost > 0);
  assert.ok(result.metrics.operationCost < result.metrics.limits.maximumOperationCost);
});

test('encoded fixture is one complete parseable transaction/source-output pair', () => {
  const wires = encodeM31JFoldTransactionFixture(honest);
  assert.match(wires.transactionHex, /^[0-9a-f]+$/);
  assert.match(wires.sourceOutputsHex, /^[0-9a-f]+$/);
  assert.ok(wires.transactionHex.length / 2 < 100_000);
});

test('the actual deployed form is a standard 35-byte P2SH32 source', () => {
  const result = evaluateM31JFoldP2sh32(honest);
  const wires = encodeM31JFoldP2sh32TransactionFixture(honest);
  assert.equal(result.accepted, true, result.error ?? 'P2SH32 VM rejected');
  assert.equal(result.lockingHex.length / 2, 35);
  assert.equal(result.unlockingHex.length / 2, 261);
  assert.ok(wires.transactionHex.length / 2 < 100_000);
  assert.equal(wires.sourceOutputsHex.length / 2, 45);
});

test('wrong result, inverse, or coordinate rejects', () => {
  assert.equal(evaluateM31JFold({ ...honest, folded: add(honest.folded, 1n) }).accepted, false);
  assert.equal(evaluateM31JFold({ ...honest, inverseTwoY: add(honest.inverseTwoY, 1n) }).accepted, false);
  assert.equal(evaluateM31JFold({ ...honest, y: add(honest.y, 1n) }).accepted, false);
});

test('noncanonical fixed-width inputs reject before arithmetic', () => {
  const rawOutOfRange = Uint8Array.of(0xff, 0xff, 0xff, 0x7f);
  const rawShort = Uint8Array.of(0x01, 0x00, 0x00);
  assert.equal(evaluateM31JFold({ ...honest, rawPositive: rawOutOfRange }).accepted, false);
  assert.equal(evaluateM31JFold({ ...honest, rawBeta: rawShort }).accepted, false);
});
