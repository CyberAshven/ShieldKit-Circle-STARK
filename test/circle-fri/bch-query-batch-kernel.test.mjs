import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  utf8,
} from '../../src/circle-fri/bytes.mjs';

import {
  encodeCircleFriQueryProof,
  proveCircleFriQueries,
} from '../../src/circle-fri/query-proof.mjs';

import {
  createCircleFriQ2BatchWitness,
} from '../../src/circle-fri/query-batch-witness.mjs';

import {
  circleFriTopologyRecordBytes,
} from '../../src/circle-fri/topology-table.mjs';

import {
  buildBchCircleFriQ2BatchRedeemBytecode,
  createBchCircleFriQ2BatchFixture,
  encodeBchCircleFriQ2BatchTransactionFixture,
  evaluateBchCircleFriQ2BatchTransactionFixture,
  materializeBchCircleFriQ2BatchP2sh32,
} from '../../src/circle-fri/bch-query-batch-kernel.mjs';

const PARAMETERS = Object.freeze({ logDegreeBound: 6, logBlowup: 3, queryCount: 4 });
const CONTEXT = utf8('ShieldKit Circle-FRI executable query KAT v3');

const deterministicCoefficients = (seed = 0x465249n) => {
  let state = seed;
  return Array.from({ length: 1 << PARAMETERS.logDegreeBound }, () => {
    state = (state * 2_862_933_555_777_941_757n + 3_037_000_493n) & ((1n << 64n) - 1n);
    return (state >> 11n) % M31_MODULUS;
  });
};

const buildProof = (seed) => proveCircleFriQueries({
  coefficients: deterministicCoefficients(seed),
  logBlowup: PARAMETERS.logBlowup,
  queryCount: PARAMETERS.queryCount,
  protocolContext: CONTEXT,
});

const buildFixtures = (proof) => [[0, 1], [2, 3]].map((queryOrdinals) => (
  createBchCircleFriQ2BatchFixture({
    witness: createCircleFriQ2BatchWitness({
      proof,
      expected: PARAMETERS,
      protocolContext: CONTEXT,
      queryOrdinals,
    }),
    expected: PARAMETERS,
    protocolContext: CONTEXT,
  })
));

const proof = buildProof();
const honest = buildFixtures(proof);

const readU16 = (bytes, offset) => bytes[offset] + bytes[offset + 1] * 0x100;

const codecOffsets = (bytes) => {
  const roots = 22;
  const finalCodeword = roots + PARAMETERS.logDegreeBound * 32;
  const topologyRoot = finalCodeword + (2 ** PARAMETERS.logBlowup) * 4;
  const record0 = topologyRoot + 32;
  const recordBytes = circleFriTopologyRecordBytes(PARAMETERS);
  const record1 = record0 + recordBytes;
  const topologySiblingCount = record1 + recordBytes;
  let cursor = topologySiblingCount + 2 + readU16(bytes, topologySiblingCount) * 32;
  const layers = [];
  for (let round = 0; round < PARAMETERS.logDegreeBound; round += 1) {
    const siblingCount = readU16(bytes, cursor + 2);
    layers.push(Object.freeze({
      header: cursor,
      inverse0: cursor + 4,
      inverse1: cursor + 8,
      values: cursor + 12,
      siblings: cursor + 28,
      siblingCount,
    }));
    cursor += 28 + siblingCount * 32;
  }
  return Object.freeze({
    queryOrdinals: 10,
    queryIndices: 14,
    roots,
    finalCodeword,
    topologyRoot,
    record0,
    record1,
    recordBytes,
    topologySiblingCount,
    topologySiblings: topologySiblingCount + 2,
    layers,
    end: cursor,
  });
};

const mutateFixture = (fixture, mutation) => {
  const candidate = structuredClone(fixture);
  candidate.encodedWitness = candidate.encodedWitness.slice();
  mutation(candidate.encodedWitness, codecOffsets(candidate.encodedWitness));
  return candidate;
};

const evaluateInput0 = (wires) => evaluateBchCircleFriQ2BatchTransactionFixture({
  ...wires,
  materialized: wires.materialized.slice(0, 1),
})[0];

test('one fixed P2SH32 redeem accepts both canonical q2 witnesses in one standard transaction', () => {
  const proofBefore = encodeCircleFriQueryProof(proof);
  const wires = encodeBchCircleFriQ2BatchTransactionFixture(honest);
  const results = evaluateBchCircleFriQ2BatchTransactionFixture(wires);
  const proofAfter = encodeCircleFriQueryProof(proof);

  assert.deepEqual(proofAfter, proofBefore, 'BCH witness packaging changed the public proof bytes');
  assert.equal(results[0].accepted, true, results[0].error ?? 'batch 0 rejected');
  assert.equal(results[1].accepted, true, results[1].error ?? 'batch 1 rejected');
  assert.equal(results.every(({ standard }) => standard), true);
  assert.deepEqual(wires.materialized[0].redeemBytecode, wires.materialized[1].redeemBytecode);
  assert.deepEqual(wires.materialized[0].lockingBytecode, wires.materialized[1].lockingBytecode);
  assert.equal(wires.materialized[0].lockingBytecode.length, 35);
  assert.equal(wires.materialized[0].redeemBytecode.length, 4_536);
  assert.deepEqual(wires.materialized.map(({ operandUnlockingBytecode }) => operandUnlockingBytecode.length), [4_540, 4_604]);
  assert.deepEqual(wires.materialized.map(({ unlockingBytecode }) => unlockingBytecode.length), [9_079, 9_143]);
  assert.equal(wires.transactionBytes, 18_328);
  assert.equal(wires.sourceOutputsBytes, 89);
  assert.deepEqual(results.map(({ metrics }) => metrics.operationCost), [3_762_002, 3_796_759]);
  assert.deepEqual(results.map(({ metrics }) => metrics.hashDigestIterations), [608, 614]);
  assert.deepEqual(results.map(({ metrics }) => metrics.signatureCheckCount), [0, 0]);
  assert.ok(wires.transactionBytes <= 100_000);
  assert.ok(wires.materialized.every(({ redeemBytecode, unlockingBytecode }) => (
    redeemBytecode.length <= 5_200 && unlockingBytecode.length <= 10_000
  )));
});

test('each unlocking is exactly canonical PUSH32 digest, PUSHDATA2 witness, PUSHDATA2 redeem', () => {
  for (const fixture of honest) {
    const materialized = materializeBchCircleFriQ2BatchP2sh32(fixture);
    const bytes = materialized.unlockingBytecode;
    assert.equal(bytes[0], 0x20);
    assert.deepEqual(bytes.slice(1, 33), fixture.publicProofDigest);
    assert.equal(bytes[33], 0x4d);
    const witnessLength = bytes[34] + bytes[35] * 0x100;
    assert.equal(witnessLength, fixture.encodedWitness.length);
    const redeemPush = 36 + witnessLength;
    assert.equal(bytes[redeemPush], 0x4d);
    const redeemLength = bytes[redeemPush + 1] + bytes[redeemPush + 2] * 0x100;
    assert.equal(redeemLength, materialized.redeemBytecode.length);
    assert.equal(redeemPush + 3 + redeemLength, bytes.length);
  }
});

test('active input index selects the exact aligned batch and rejects swaps', () => {
  const wires = encodeBchCircleFriQ2BatchTransactionFixture(honest);
  const swapped = structuredClone(wires);
  [swapped.transaction.inputs[0].unlockingBytecode, swapped.transaction.inputs[1].unlockingBytecode] = [
    swapped.transaction.inputs[1].unlockingBytecode,
    swapped.transaction.inputs[0].unlockingBytecode,
  ];
  const results = evaluateBchCircleFriQ2BatchTransactionFixture(swapped);
  assert.equal(results.every(({ accepted }) => !accepted), true);

  const wrongOrdinals = mutateFixture(honest[0], (bytes, offsets) => {
    bytes[offsets.queryOrdinals] ^= 2;
  });
  assert.equal(evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([wrongOrdinals, honest[1]])).accepted, false);

  const wrongQueryIndex = mutateFixture(honest[0], (bytes, offsets) => {
    bytes[offsets.queryIndices] ^= 1;
  });
  assert.equal(evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([wrongQueryIndex, honest[1]])).accepted, false);
});

test('cross-input public transcript digest rejects altered prefixes and mixed public proofs', () => {
  const wires = encodeBchCircleFriQ2BatchTransactionFixture(honest);
  const wrongPrefix = structuredClone(wires);
  wrongPrefix.transaction.inputs[1].unlockingBytecode[1] ^= 1;
  const prefixResults = evaluateBchCircleFriQ2BatchTransactionFixture(wrongPrefix);
  assert.equal(prefixResults.every(({ accepted }) => !accepted), true);

  const nonPush32Prefix = structuredClone(wires);
  nonPush32Prefix.transaction.inputs[1].unlockingBytecode[0] = 0x4c;
  assert.equal(evaluateInput0(nonPush32Prefix).accepted, false);

  const alternate = buildFixtures(buildProof(0x46524bn));
  assert.notDeepEqual(alternate[0].publicProofDigest, honest[0].publicProofDigest);
  assert.deepEqual(
    buildBchCircleFriQ2BatchRedeemBytecode(alternate[0]),
    buildBchCircleFriQ2BatchRedeemBytecode(honest[0]),
  );
  const alternateResults = evaluateBchCircleFriQ2BatchTransactionFixture(
    encodeBchCircleFriQ2BatchTransactionFixture(alternate),
  );
  assert.equal(alternateResults.every(({ accepted }) => accepted), true);
  const mixed = structuredClone(wires);
  mixed.transaction.inputs[1].unlockingBytecode = materializeBchCircleFriQ2BatchP2sh32(alternate[1]).unlockingBytecode;
  const mixedResults = evaluateBchCircleFriQ2BatchTransactionFixture(mixed);
  assert.equal(mixedResults.every(({ accepted }) => !accepted), true);
});

test('runtime binds every root, topology record/frontier, M31 value/frontier, inverse, and final', () => {
  const mutations = [
    (bytes, offsets) => { bytes[offsets.roots] ^= 1; },
    (bytes, offsets) => { bytes[offsets.topologyRoot] ^= 1; },
    (bytes, offsets) => { bytes[offsets.record0 + 10] ^= 1; },
    (bytes, offsets) => { bytes[offsets.topologySiblings] ^= 1; },
    (bytes, offsets) => { bytes[offsets.layers[0].values] ^= 1; },
    (bytes, offsets) => { bytes[offsets.layers[2].siblings] ^= 1; },
    (bytes, offsets) => { bytes[offsets.layers[1].inverse0] ^= 1; },
    (bytes, offsets) => { bytes[offsets.finalCodeword] ^= 1; },
  ];
  for (const [ordinal, mutation] of mutations.entries()) {
    const candidate = mutateFixture(honest[0], mutation);
    const result = evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([candidate, honest[1]]));
    assert.equal(result.accepted, false, `runtime mutation ${ordinal} was accepted`);
  }
});

test('canonical codec parsing rejects swaps, truncated/extra bytes, and nonminimal frontier counts', () => {
  const recordSwap = mutateFixture(honest[0], (bytes, offsets) => {
    const first = bytes.slice(offsets.record0, offsets.record0 + offsets.recordBytes);
    const second = bytes.slice(offsets.record1, offsets.record1 + offsets.recordBytes);
    bytes.set(second, offsets.record0);
    bytes.set(first, offsets.record1);
  });
  assert.equal(evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([recordSwap, honest[1]])).accepted, false);

  const nonminimalTopology = mutateFixture(honest[0], (bytes, offsets) => {
    bytes[offsets.topologySiblingCount] += 1;
  });
  assert.equal(evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([nonminimalTopology, honest[1]])).accepted, false);

  const nonminimalLayer = mutateFixture(honest[0], (bytes, offsets) => {
    bytes[offsets.layers[0].header + 2] += 1;
  });
  assert.equal(evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([nonminimalLayer, honest[1]])).accepted, false);

  const truncated = structuredClone(honest[0]);
  truncated.encodedWitness = truncated.encodedWitness.slice(0, -1);
  assert.equal(evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([truncated, honest[1]])).accepted, false);

  const extra = structuredClone(honest[0]);
  extra.encodedWitness = new Uint8Array(honest[0].encodedWitness.length + 1);
  extra.encodedWitness.set(honest[0].encodedWitness);
  assert.equal(evaluateInput0(encodeBchCircleFriQ2BatchTransactionFixture([extra, honest[1]])).accepted, false);
});

test('exact transaction input roster rejects missing and extra inputs', () => {
  const wires = encodeBchCircleFriQ2BatchTransactionFixture(honest);
  const short = {
    ...structuredClone(wires),
    materialized: wires.materialized.slice(0, 1),
    transaction: {
      ...structuredClone(wires.transaction),
      inputs: structuredClone(wires.transaction.inputs.slice(0, 1)),
    },
    sourceOutputs: structuredClone(wires.sourceOutputs.slice(0, 1)),
  };
  assert.equal(evaluateBchCircleFriQ2BatchTransactionFixture(short)[0].accepted, false);

  const extra = {
    ...structuredClone(wires),
    transaction: {
      ...structuredClone(wires.transaction),
      inputs: [...structuredClone(wires.transaction.inputs), structuredClone(wires.transaction.inputs[0])],
    },
    sourceOutputs: [...structuredClone(wires.sourceOutputs), structuredClone(wires.sourceOutputs[0])],
  };
  assert.equal(evaluateBchCircleFriQ2BatchTransactionFixture(extra).every(({ accepted }) => !accepted), true);
});
