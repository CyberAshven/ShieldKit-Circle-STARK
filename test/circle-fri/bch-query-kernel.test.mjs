import test from 'node:test';
import assert from 'node:assert/strict';

import { M31_MODULUS } from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import { utf8 } from '../../src/circle-fri/bytes.mjs';

import {
  BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES,
  createBchCircleFriQueryFixture,
  encodeBchCircleFriMultiQueryTransactionFixture,
  encodeBchCircleFriQueryP2sh32TransactionFixture,
  evaluateBchCircleFriQueryP2sh32,
  materializeBchCircleFriQueryP2sh32,
} from '../../src/circle-fri/bch-query-kernel.mjs';

import { proveCircleFriQueries } from '../../src/circle-fri/query-proof.mjs';

const expected = Object.freeze({ logDegreeBound: 6, logBlowup: 3, queryCount: 1 });
const protocolContext = utf8('ShieldKit Circle-FRI BCH query component v1');

const coefficients = (() => {
  let state = 0x626368n;
  return Array.from({ length: 1 << expected.logDegreeBound }, () => {
    state = (state * 6_364_136_223_846_793_005n + 1_442_695_040_888_963_407n) & ((1n << 64n) - 1n);
    return (state >> 13n) % M31_MODULUS;
  });
})();

const proof = proveCircleFriQueries({
  coefficients,
  logBlowup: expected.logBlowup,
  queryCount: expected.queryCount,
  protocolContext,
});
const honest = createBchCircleFriQueryFixture({ proof, expected, protocolContext });

test('BCH-2026 P2SH32 accepts one complete authenticated Circle-FRI query chain', () => {
  const materialized = materializeBchCircleFriQueryP2sh32(honest);
  const result = evaluateBchCircleFriQueryP2sh32(honest);
  const wires = encodeBchCircleFriQueryP2sh32TransactionFixture(honest);
  assert.equal(result.accepted, true, result.error ?? 'BCH query component rejected');
  assert.equal(result.standard, true);
  assert.equal(honest.transcriptDerivationIncluded, true);
  assert.equal(honest.proofCommitmentsRuntimeSupplied, false);
  assert.equal(materialized.lockingBytecode.length, 35);
  assert.ok(materialized.redeemBytecode.length <= 10_000);
  assert.ok(materialized.unlockingBytecode.length <= 10_000);
  assert.ok(wires.transactionHex.length / 2 <= 100_000);
  assert.equal(wires.sourceOutputsHex.length / 2, 45);
});

test('query component measures real hashes, arithmetic, stack, and transaction bytes', () => {
  const materialized = materializeBchCircleFriQueryP2sh32(honest);
  const result = evaluateBchCircleFriQueryP2sh32(honest);
  const wires = encodeBchCircleFriQueryP2sh32TransactionFixture(honest);
  assert.equal(materialized.redeemBytecode.length, 2_503);
  assert.equal(materialized.operandUnlockingBytecode.length, 2_228);
  assert.equal(materialized.unlockingBytecode.length, 4_734);
  assert.equal(wires.transactionHex.length / 2, 4_797);
  assert.equal(result.metrics.hashDigestIterations, 335);
  assert.equal(result.metrics.operationCost, 411_212);
  assert.equal(BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES, 360);
  assert.equal(result.metrics.signatureCheckCount, 0);
  assert.ok(result.metrics.operationCost < result.metrics.limits.maximumOperationCost);
  assert.ok(result.metrics.stackMaximums.cumulativeMemoryItems < 1_000);
});

test('wrong path, value, inverse, or final value rejects', () => {
  const wrongPath = structuredClone(honest);
  wrongPath.rounds[0].opening.leftSiblings[0][0] ^= 1;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongPath).accepted, false);

  const wrongValue = structuredClone(honest);
  wrongValue.rounds[1].opening.rightValue = (wrongValue.rounds[1].opening.rightValue + 1n) % M31_MODULUS;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongValue).accepted, false);

  const wrongInverse = structuredClone(honest);
  wrongInverse.rounds[2].inverseTwoCoordinate = (wrongInverse.rounds[2].inverseTwoCoordinate + 1n) % M31_MODULUS;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongInverse).accepted, false);

  const wrongFinal = structuredClone(honest);
  wrongFinal.finalExpected = (wrongFinal.finalExpected + 1n) % M31_MODULUS;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongFinal).accepted, false);
});

test('wrong transcript context, rejection path, or derived query index rejects', () => {
  const wrongContext = structuredClone(honest);
  wrongContext.protocolContext[0] ^= 1;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongContext).accepted, false);

  const wrongAttempt = structuredClone(honest);
  wrongAttempt.rounds[0].transcriptSample.attempt += 1;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongAttempt).accepted, false);

  const wrongQueryIndex = structuredClone(honest);
  wrongQueryIndex.initialQueryIndex ^= 1;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongQueryIndex).accepted, false);
});

test('BCH Script derives canonical unique multi-query indices including duplicate retries', () => {
  const multiExpected = Object.freeze({ logDegreeBound: 2, logBlowup: 0, queryCount: 4 });
  const multiContext = utf8('multi-query-duplicate-kat');
  const multiProof = proveCircleFriQueries({
    coefficients: [1n, 2n, 3n, 4n],
    logBlowup: 0,
    queryCount: 4,
    protocolContext: multiContext,
  });
  const fixtures = Array.from({ length: 4 }, (_, queryOrdinal) => createBchCircleFriQueryFixture({
    proof: multiProof,
    expected: multiExpected,
    protocolContext: multiContext,
    queryOrdinal,
  }));
  assert.deepEqual(fixtures.map(({ initialQueryIndex }) => initialQueryIndex), [1, 3, 0, 2]);
  assert.deepEqual(fixtures[3].selectedQueryTrace.candidates.map(({ duplicateOf }) => duplicateOf), [0, 2, -1]);
  for (const fixture of fixtures) {
    const result = evaluateBchCircleFriQueryP2sh32(fixture);
    assert.equal(result.accepted, true, result.error ?? `query ${fixture.queryOrdinal} rejected`);
  }
  const wires = encodeBchCircleFriMultiQueryTransactionFixture(fixtures);
  assert.equal(wires.materialized.length, 4);
  assert.ok(wires.transactionBytes < 100_000);
  assert.equal(wires.sourceOutputsBytes, 177);

  const wrongDuplicateDisposition = structuredClone(fixtures[3]);
  wrongDuplicateDisposition.transcriptTrace.queries[3].candidates[0].duplicateOf = -1;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongDuplicateDisposition).accepted, false);
});
