import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  utf8,
} from '../../src/circle-fri/bytes.mjs';

import {
  assertCircleFriParameters,
  buildCircleFriPublicTopologies,
  encodeCircleFriQueryProof,
  proveCircleFriQueries,
} from '../../src/circle-fri/query-proof.mjs';

import {
  decodeCircleFriQueryMultiproof,
  encodeCircleFriQueryMultiproof,
  proveCircleFriQueryMultiproof,
  verifyCircleFriQueryMultiproof,
} from '../../src/circle-fri/query-multiproof.mjs';

const deterministicCoefficients = (length, seed = 0x4d_554c_5449n) => {
  let state = seed;
  return Array.from({ length }, () => {
    state = (state * 2_862_933_555_777_941_757n + 3_037_000_493n) & ((1n << 64n) - 1n);
    return (state >> 11n) % M31_MODULUS;
  });
};

const PARAMETERS = Object.freeze({
  logDegreeBound: 6,
  logBlowup: 3,
  queryCount: 4,
  queryBatchSize: 2,
});
const CONTEXT = utf8('ShieldKit Circle-FRI canonical query multiproof KAT v2');

const buildProof = () => proveCircleFriQueryMultiproof({
  coefficients: deterministicCoefficients(1 << PARAMETERS.logDegreeBound),
  logBlowup: PARAMETERS.logBlowup,
  queryCount: PARAMETERS.queryCount,
  queryBatchSize: PARAMETERS.queryBatchSize,
  protocolContext: CONTEXT,
});

test('batched Circle-FRI multiproof verifies every query, layer, and fold', () => {
  const proof = buildProof();
  const verdict = verifyCircleFriQueryMultiproof({ proof, expected: PARAMETERS, protocolContext: CONTEXT });
  assert.equal(verdict.ok, true, verdict.reason);
  assert.equal(verdict.batchCount, 2);
  assert.equal(new Set(verdict.queryIndices).size, PARAMETERS.queryCount);
  const topology = buildCircleFriPublicTopologies(assertCircleFriParameters(PARAMETERS))[0];
  assert.equal(new Set(verdict.queryIndices.map((index) => topology.pairByLeaf[index])).size, PARAMETERS.queryCount);
  assert.equal(verdict.betas.length, PARAMETERS.logDegreeBound);
});

test('canonical multiproof codec round-trips and beats independent query paths', () => {
  const coefficients = deterministicCoefficients(1 << PARAMETERS.logDegreeBound);
  const proof = buildProof();
  const encoded = encodeCircleFriQueryMultiproof(proof);
  const independent = encodeCircleFriQueryProof(proveCircleFriQueries({
    coefficients,
    logBlowup: PARAMETERS.logBlowup,
    queryCount: PARAMETERS.queryCount,
    protocolContext: CONTEXT,
  }));
  assert.equal(encoded.length, 6_923);
  assert.equal(independent.length, 10_409);
  assert.ok(encoded.length < independent.length, `${encoded.length} !< ${independent.length}`);
  assert.equal(
    createHash('sha256').update(encoded).digest('hex'),
    '0f837823456c01a6c65ce8c4f998a584cc8ebaa2c31da120443e63160bd58765',
  );
  const decoded = decodeCircleFriQueryMultiproof(encoded);
  assert.deepEqual(encodeCircleFriQueryMultiproof(decoded), encoded);
  assert.equal(
    verifyCircleFriQueryMultiproof({ proof: decoded, expected: PARAMETERS, protocolContext: CONTEXT }).ok,
    true,
  );
});

test('multiproof rejects context, batch, value, frontier, and final-codeword tampering', () => {
  const proof = buildProof();
  assert.equal(verifyCircleFriQueryMultiproof({
    proof,
    expected: PARAMETERS,
    protocolContext: utf8('wrong context'),
  }).ok, false);
  assert.equal(verifyCircleFriQueryMultiproof({
    proof,
    expected: { ...PARAMETERS, queryBatchSize: 1 },
    protocolContext: CONTEXT,
  }).ok, false);
  assert.equal(verifyCircleFriQueryMultiproof({
    proof,
    expected: {
      logDegreeBound: PARAMETERS.logDegreeBound,
      logBlowup: PARAMETERS.logBlowup,
      queryCount: PARAMETERS.queryCount,
    },
    protocolContext: CONTEXT,
  }).ok, false);

  const valueTamper = structuredClone(proof);
  valueTamper.batches[0].layers[0].values[0] = (valueTamper.batches[0].layers[0].values[0] + 1n) % M31_MODULUS;
  assert.equal(verifyCircleFriQueryMultiproof({ proof: valueTamper, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);

  const frontierTamper = structuredClone(proof);
  frontierTamper.batches[1].layers[1].siblings[0][0] ^= 1;
  assert.equal(verifyCircleFriQueryMultiproof({ proof: frontierTamper, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);

  const swappedBatches = structuredClone(proof);
  [swappedBatches.batches[0], swappedBatches.batches[1]] = [swappedBatches.batches[1], swappedBatches.batches[0]];
  assert.equal(verifyCircleFriQueryMultiproof({ proof: swappedBatches, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);

  const finalTamper = structuredClone(proof);
  finalTamper.finalCodeword[0] = (finalTamper.finalCodeword[0] + 1n) % M31_MODULUS;
  assert.equal(verifyCircleFriQueryMultiproof({ proof: finalTamper, expected: PARAMETERS, protocolContext: CONTEXT }).ok, false);
});

test('multiproof decoder rejects malformed framing and noncanonical fields', () => {
  const encoded = encodeCircleFriQueryMultiproof(buildProof());
  assert.throws(() => decodeCircleFriQueryMultiproof(encoded.slice(0, -1)), /truncated/);
  const trailing = new Uint8Array(encoded.length + 1);
  trailing.set(encoded);
  assert.throws(() => decodeCircleFriQueryMultiproof(trailing), /trailing bytes/);
  const badMagic = encoded.slice();
  badMagic[0] ^= 1;
  assert.throws(() => decodeCircleFriQueryMultiproof(badMagic), /magic/);
  const oldVersion = encoded.slice();
  oldVersion[4] = 1;
  assert.throws(() => decodeCircleFriQueryMultiproof(oldVersion), /unsupported/);
  const noncanonical = encoded.slice();
  const finalOffset = 11 + PARAMETERS.logDegreeBound * 32;
  noncanonical.set(Uint8Array.of(0xff, 0xff, 0xff, 0x7f), finalOffset);
  assert.throws(() => decodeCircleFriQueryMultiproof(noncanonical), /not canonical/);
  const oversizedCount = encoded.slice();
  const firstValueCountOffset = finalOffset + (1 << PARAMETERS.logBlowup) * 4;
  oversizedCount.set(Uint8Array.of(0xff, 0xff, 0xff, 0xff), firstValueCountOffset);
  assert.throws(() => decodeCircleFriQueryMultiproof(oversizedCount), /value count is out of range/);
});

test('two-query batches expose the viable raw-byte frontier for the 128-bit rate term', () => {
  const parameters = Object.freeze({
    logDegreeBound: 6,
    logBlowup: 8,
    queryCount: 16,
    queryBatchSize: 2,
  });
  const proof = proveCircleFriQueryMultiproof({
    coefficients: deterministicCoefficients(1 << parameters.logDegreeBound, 0x128n),
    logBlowup: parameters.logBlowup,
    queryCount: parameters.queryCount,
    queryBatchSize: parameters.queryBatchSize,
    protocolContext: CONTEXT,
  });
  const encoded = encodeCircleFriQueryMultiproof(proof);
  assert.equal(verifyCircleFriQueryMultiproof({ proof, expected: parameters, protocolContext: CONTEXT }).ok, true);
  assert.equal(encoded.length, 58_507);
  assert.equal(
    createHash('sha256').update(encoded).digest('hex'),
    'c09394b751e2ff53804934583ab6bd1e1934085eda7de0b438b1cc105b710c2c',
  );
  const verdict = verifyCircleFriQueryMultiproof({ proof, expected: parameters, protocolContext: CONTEXT });
  const topology = buildCircleFriPublicTopologies(assertCircleFriParameters(parameters))[0];
  assert.equal(new Set(verdict.queryIndices.map((index) => topology.pairByLeaf[index])).size, parameters.queryCount);
});
