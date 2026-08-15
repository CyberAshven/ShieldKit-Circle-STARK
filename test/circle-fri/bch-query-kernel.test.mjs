import test from 'node:test';
import assert from 'node:assert/strict';

import { M31_MODULUS } from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import { sha256, utf8 } from '../../src/circle-fri/bytes.mjs';

import { sampleCircleFriTranscriptState } from '../../src/circle-fri/transcript.mjs';

import {
  BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES,
  buildBchCircleFriQueryRedeemBytecode,
  createBchCircleFriQueryFixture,
  encodeBchCircleFriMultiQueryTransactionFixture,
  encodeBchCircleFriQueryP2sh32TransactionFixture,
  evaluateBchCircleFriMultiQueryTransactionFixture,
  evaluateBchCircleFriTranscriptChallenge,
  evaluateBchCircleFriQueryP2sh32,
  materializeBchCircleFriQueryP2sh32,
} from '../../src/circle-fri/bch-query-kernel.mjs';

import { proveCircleFriQueries } from '../../src/circle-fri/query-proof.mjs';

const expected = Object.freeze({ logDegreeBound: 6, logBlowup: 3, queryCount: 1 });
const protocolContext = utf8('ShieldKit Circle-FRI BCH query component v2');

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
  assert.equal(honest.transcriptAttemptsRuntimeDerived, true);
  assert.equal(honest.queryIndicesRuntimeDerived, true);
  assert.equal(honest.queryDuplicateRetriesRuntimeDerived, true);
  assert.equal(honest.proofCommitmentsRuntimeSupplied, true);
  assert.equal(honest.topologyOpeningRuntimeSupplied, true);
  assert.equal(honest.topologyPlanRuntimeConsumed, true);
  assert.equal(honest.activeInputIndexQuerySelection, true);
  assert.equal(honest.transactionInputCountRuntimeBound, true);
  assert.equal(honest.proofSpecificRedeem, false);
  assert.equal(honest.queryOrdinalSpecificRedeem, false);
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
  assert.equal(materialized.redeemBytecode.length, 4_039);
  assert.equal(materialized.operandUnlockingBytecode.length, 2_892);
  assert.equal(materialized.unlockingBytecode.length, 6_934);
  assert.equal(wires.transactionHex.length / 2, 6_997);
  assert.equal(result.metrics.hashDigestIterations, 389);
  assert.equal(result.metrics.operationCost, 663_778);
  assert.equal(BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES, 408);
  assert.equal(result.metrics.signatureCheckCount, 0);
  assert.ok(result.metrics.operationCost < result.metrics.limits.maximumOperationCost);
  assert.ok(result.metrics.stackMaximums.cumulativeMemoryItems < 1_000);
});

test('wrong root, path, value, inverse, or runtime final codeword rejects', () => {
  const honestRedeem = buildBchCircleFriQueryRedeemBytecode(honest);
  const wrongRoot = structuredClone(honest);
  wrongRoot.rounds[0].root[0] ^= 1;
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(wrongRoot), honestRedeem);
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongRoot).accepted, false);

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
  wrongFinal.finalCodeword[wrongFinal.finalIndex] = (wrongFinal.finalCodeword[wrongFinal.finalIndex] + 1n) % M31_MODULUS;
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(wrongFinal), honestRedeem);
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongFinal).accepted, false);
});

test('wrong transcript context, rejection path, or derived query index rejects', () => {
  const wrongContext = structuredClone(honest);
  wrongContext.protocolContext[0] ^= 1;
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongContext).accepted, false);

  const wrongAttempt = structuredClone(honest);
  wrongAttempt.rounds[0].transcriptSample.attempt += 1;
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(wrongAttempt), buildBchCircleFriQueryRedeemBytecode(honest));
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongAttempt).accepted, true);

  const wrongQueryIndex = structuredClone(honest);
  wrongQueryIndex.initialQueryIndex ^= 1;
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(wrongQueryIndex), buildBchCircleFriQueryRedeemBytecode(honest));
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongQueryIndex).accepted, true);
});

test('BCH Script derives a nonzero rejection attempt rather than trusting a host trace', () => {
  const state = sha256(utf8('Circle-FRI runtime rejection-loop test state'));
  const upperBound = 3_000_000_000;
  let label;
  let expectedSample;
  for (let nonce = 0; nonce < 100; nonce += 1) {
    const candidateLabel = `runtime-rejection-${nonce}`;
    const sample = sampleCircleFriTranscriptState({ state, label: candidateLabel, upperBound });
    if (sample.attempt > 0) {
      label = candidateLabel;
      expectedSample = sample;
      break;
    }
  }
  assert.notEqual(label, undefined, 'deterministic test search did not find a rejected first draw');
  const result = evaluateBchCircleFriTranscriptChallenge({ state, label, upperBound });
  assert.equal(result.accepted, true, result.error ?? 'runtime rejection loop rejected');
  assert.equal(result.sample.attempt, expectedSample.attempt);
  assert.equal(result.sample.value, expectedSample.value);
});

test('runtime topology record and opening path are bound to the fixed verifier root', () => {
  const honestRedeem = buildBchCircleFriQueryRedeemBytecode(honest);
  const wrongRecord = structuredClone(honest);
  wrongRecord.topologyOpening.record[10] ^= 1;
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(wrongRecord), honestRedeem);
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongRecord).accepted, false);

  const wrongPath = structuredClone(honest);
  wrongPath.topologyOpening.siblings[0][0] ^= 1;
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(wrongPath), honestRedeem);
  assert.equal(evaluateBchCircleFriQueryP2sh32(wrongPath).accepted, false);

  const hostTopologyMetadata = structuredClone(honest);
  hostTopologyMetadata.rounds[0].leftIndex ^= 1;
  hostTopologyMetadata.rounds[1].rightIndex ^= 1;
  hostTopologyMetadata.rounds[2].coordinate = (hostTopologyMetadata.rounds[2].coordinate + 1n) % M31_MODULUS;
  hostTopologyMetadata.rounds[3].continuitySide = hostTopologyMetadata.rounds[3].continuitySide === 'left' ? 'right' : 'left';
  hostTopologyMetadata.finalIndex ^= 1;
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(hostTopologyMetadata), honestRedeem);
  assert.equal(evaluateBchCircleFriQueryP2sh32(hostTopologyMetadata).accepted, true);
});

test('fixed parameters and input-index query selection reuse one redeem across different proofs', () => {
  const alternateProof = proveCircleFriQueries({
    coefficients: coefficients.map((value, index) => (value + BigInt(index + 1)) % M31_MODULUS),
    logBlowup: expected.logBlowup,
    queryCount: expected.queryCount,
    protocolContext,
  });
  const alternate = createBchCircleFriQueryFixture({
    proof: alternateProof,
    expected,
    protocolContext,
  });
  assert.notEqual(alternate.initialQueryIndex, honest.initialQueryIndex);
  assert.deepEqual(buildBchCircleFriQueryRedeemBytecode(alternate), buildBchCircleFriQueryRedeemBytecode(honest));
  assert.equal(evaluateBchCircleFriQueryP2sh32(alternate).accepted, true);
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
  assert.deepEqual(fixtures.map(({ initialQueryIndex }) => initialQueryIndex), [3, 2, 1, 0]);
  assert.deepEqual(fixtures[3].selectedQueryTrace.candidates.map(({ duplicateOf }) => duplicateOf), [1, -1]);
  assert.throws(
    () => evaluateBchCircleFriQueryP2sh32(fixtures[1]),
    /single-input query fixture requires queryCount 1/,
  );
  const wires = encodeBchCircleFriMultiQueryTransactionFixture(fixtures);
  const evaluations = evaluateBchCircleFriMultiQueryTransactionFixture(wires);
  for (const result of evaluations) {
    assert.equal(result.accepted, true, result.error ?? `query input ${result.inputIndex} rejected`);
  }
  assert.equal(wires.materialized.length, 4);
  for (const materialized of wires.materialized.slice(1)) {
    assert.deepEqual(materialized.redeemBytecode, wires.materialized[0].redeemBytecode);
    assert.deepEqual(materialized.lockingBytecode, wires.materialized[0].lockingBytecode);
  }
  assert.ok(wires.transactionBytes < 100_000);
  assert.equal(wires.sourceOutputsBytes, 177);

  const swappedTransaction = structuredClone(wires.transaction);
  [swappedTransaction.inputs[0].unlockingBytecode, swappedTransaction.inputs[1].unlockingBytecode] = [
    swappedTransaction.inputs[1].unlockingBytecode,
    swappedTransaction.inputs[0].unlockingBytecode,
  ];
  const swapped = evaluateBchCircleFriMultiQueryTransactionFixture({
    ...wires,
    transaction: swappedTransaction,
  });
  assert.equal(swapped[0].accepted, false, 'query 1 witness accepted at active input 0');
  assert.equal(swapped[1].accepted, false, 'query 0 witness accepted at active input 1');

  const shortened = evaluateBchCircleFriMultiQueryTransactionFixture({
    materialized: wires.materialized.slice(0, 1),
    transaction: {
      ...structuredClone(wires.transaction),
      inputs: structuredClone(wires.transaction.inputs.slice(0, 1)),
      outputs: [{
        ...structuredClone(wires.transaction.outputs[0]),
        valueSatoshis: 1_000n,
      }],
    },
    sourceOutputs: structuredClone(wires.sourceOutputs.slice(0, 1)),
  });
  assert.equal(shortened[0].accepted, false, 'query 0 accepted without the remaining query inputs');

  const extended = evaluateBchCircleFriMultiQueryTransactionFixture({
    materialized: [...wires.materialized, wires.materialized[0]],
    transaction: {
      ...structuredClone(wires.transaction),
      inputs: [...structuredClone(wires.transaction.inputs), structuredClone(wires.transaction.inputs[0])],
      outputs: [{
        ...structuredClone(wires.transaction.outputs[0]),
        valueSatoshis: 5_000n,
      }],
    },
    sourceOutputs: [...structuredClone(wires.sourceOutputs), structuredClone(wires.sourceOutputs[0])],
  });
  assert.equal(extended.slice(0, 4).every(({ accepted }) => !accepted), true, 'query inputs accepted an extra transaction input');

  const wrongDuplicateDisposition = structuredClone(fixtures[3]);
  wrongDuplicateDisposition.transcriptTrace.queries[3].candidates[0].duplicateOf = -1;
  assert.deepEqual(
    buildBchCircleFriQueryRedeemBytecode(wrongDuplicateDisposition),
    buildBchCircleFriQueryRedeemBytecode(fixtures[3]),
  );
  const hostTraceMutation = [...fixtures];
  hostTraceMutation[3] = wrongDuplicateDisposition;
  const mutatedWires = encodeBchCircleFriMultiQueryTransactionFixture(hostTraceMutation);
  assert.equal(
    evaluateBchCircleFriMultiQueryTransactionFixture(mutatedWires).every(({ accepted }) => accepted),
    true,
  );
});
