import assert from 'node:assert/strict';
import test from 'node:test';

import {
  M31_BASE_OP_CASES,
  encodeBaseOpTransactionFixture,
  evaluateBaseOpCase,
  materializeBaseOpCase,
} from './base-ops.mjs';

const LOCKING_HEX = Object.freeze({
  add: '82549d760051807e81777600a2697604ffffff7f9f697c82549d760051807e81777600a2697604ffffff7f9f697b82549d760051807e81777600a2697604ffffff7f9f696b9304ffffff7f976c9c',
  sub: '82549d760051807e81777600a2697604ffffff7f9f697c82549d760051807e81777600a2697604ffffff7f9f697b82549d760051807e81777600a2697604ffffff7f9f696b9404ffffff7f9304ffffff7f976c9c',
  neg: '82549d760051807e81777600a2697604ffffff7f9f697c82549d760051807e81777600a2697604ffffff7f9f696b04ffffff7f7c9404ffffff7f976c9c',
  square: '82549d760051807e81777600a2697604ffffff7f9f697c82549d760051807e81777600a2697604ffffff7f9f696b769504ffffff7f976c9c',
  inverseHint: '82549d760051807e81777600a2697604ffffff7f9f697c82549d760051807e81777600a2697604ffffff7f9f699504ffffff7f97519c',
});

// Exact standard-mode Libauth artifact snapshots. Metrics are, in order:
// evaluated instructions, sigchecks, hash iterations, arithmetic cost,
// stack-pushed bytes, operation cost.
const KAT = Object.freeze({
  'add-zero': ['040000000004000000000400000000', [65, 0, 0, 0, 77, 6577]],
  'add-overflow-boundary': ['0400000000040100000004feffff7f', [65, 0, 0, 20, 96, 6616]],
  'sub-zero-minus-one': ['04feffff7f04010000000400000000', [67, 0, 0, 25, 109, 6834]],
  'sub-one-minus-p-minus-one': ['040200000004feffff7f0401000000', [67, 0, 0, 10, 106, 6816]],
  'sub-self': ['04000000000440e201000440e20100', [67, 0, 0, 20, 103, 6823]],
  'neg-zero': ['04000000000400000000', [47, 0, 0, 20, 61, 4781]],
  'neg-p-minus-one': ['040100000004feffff7f', [47, 0, 0, 6, 75, 4781]],
  'square-p-minus-one': ['040100000004feffff7f', [46, 0, 0, 57, 82, 4739]],
  'square-p-minus-two': ['040400000004fdffff7f', [46, 0, 0, 57, 82, 4739]],
  'inverse-one': ['04010000000401000000', [44, 0, 0, 7, 62, 4469]],
  'inverse-p-minus-one': ['04feffff7f04feffff7f', [44, 0, 0, 57, 87, 4544]],
  'inverse-two': ['04000000400402000000', [44, 0, 0, 30, 75, 4505]],
  'inverse-x-zero': ['04010000000400000000', [44, 0, 0, 0, 56, 4456]],
  'inverse-hint-zero': ['04000000000402000000', [44, 0, 0, 0, 56, 4456]],
  'inverse-hint-plus-one-wrong': ['04010000000402000000', [44, 0, 0, 7, 61, 4468]],
  'inverse-hint-minus-one-wrong': ['04feffff7f0402000000', [44, 0, 0, 33, 77, 4510]],
  'inverse-hint-wrong': ['04030000000402000000', [44, 0, 0, 7, 61, 4468]],
  'inverse-malformed-value-p-plus-one': ['04010000000400000080', [20, 0, 0, 0, 42, 2042]],
  'inverse-malformed-hint-short': ['030100000401000000', [24, 0, 0, 0, 32, 2432]],
});

const coreMetrics = (result) => [
  result.metrics.evaluatedInstructionCount,
  result.metrics.signatureCheckCount,
  result.metrics.hashDigestIterations,
  result.metrics.arithmeticCost,
  result.metrics.stackPushedBytes,
  result.metrics.operationCost,
];

test('M31 base-operation KATs execute in standard-mode Libauth with exact artifacts', () => {
  assert.equal(Object.keys(KAT).length, M31_BASE_OP_CASES.length);
  for (const entry of M31_BASE_OP_CASES) {
    const expected = KAT[entry.id];
    assert.notEqual(expected, undefined, entry.id);
    const fixture = materializeBaseOpCase(entry);
    const result = evaluateBaseOpCase(entry);
    assert.equal(result.standard, true, entry.id);
    assert.equal(result.accepted, entry.accepted, `${entry.id}: ${result.error}`);
    assert.equal(result.lockingHex, LOCKING_HEX[entry.operation], entry.id);
    assert.equal(result.unlockingHex, expected[0], entry.id);
    assert.deepEqual(coreMetrics(result), expected[1], entry.id);
    assert.ok(result.metrics.limits.operationCostHeadroom >= 0, entry.id);
    assert.ok(result.metrics.limits.stackItemsHeadroom >= 0, entry.id);
    assert.ok(result.metrics.limits.elementBytesHeadroom >= 0, entry.id);
    assert.equal(fixture.unlockingBytecode.length, result.unlockingHex.length / 2, entry.id);
  }
});

test('base-op transaction fixture preserves raw fixed4 unlock pushes without normalization', () => {
  const malformed = M31_BASE_OP_CASES.find(({ id }) => id === 'inverse-malformed-value-p-plus-one');
  const wires = encodeBaseOpTransactionFixture(malformed);
  assert.match(wires.transactionHex, /04010000000400000080/);
  assert.match(wires.sourceOutputsHex, new RegExp(LOCKING_HEX.inverseHint));
  assert.equal(wires.transactionDigestSha256, 'e95a5e9b44ef04622040b92793e35ed5a205b6c14ea39db33756f997744a345f');
  assert.equal(wires.sourceOutputsDigestSha256, '8fdef8df54873be43f2412dfdb3c89a45b13bb484495d87e335281a5f28588cf');
});
