import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
  add,
  mul,
  neg,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  CIRCLE_GENERATOR,
  CIRCLE_IDENTITY,
  CIRCLE_ORDER,
  addCirclePoints,
  antipode,
  buildStandardCoset,
  doubleCirclePoint,
  isOnCircle,
  jPoint,
  jTwinIndex,
  piX,
  pointFromSlope,
  scalarMultiplyCircle,
  standardCosetParameters,
} from '../../src/circle-fri/circle.mjs';

import {
  foldCircleCodeword,
  foldJLayer,
  foldPiLayer,
} from '../../src/circle-fri/fold.mjs';

test('fixed generator spans the full 2^31 circle group', () => {
  assert.equal(CIRCLE_ORDER, 1n << 31n);
  assert.equal(isOnCircle(CIRCLE_GENERATOR), true);
  assert.deepEqual(scalarMultiplyCircle(CIRCLE_GENERATOR, CIRCLE_ORDER), CIRCLE_IDENTITY);
  assert.deepEqual(
    scalarMultiplyCircle(CIRCLE_GENERATOR, CIRCLE_ORDER / 2n),
    { x: M31_MODULUS - 1n, y: 0n },
  );
});

test('circle law, inverse, antipode, and rational parametrization agree', () => {
  for (const slope of [0n, 1n, 2n, 17n, M31_MODULUS - 1n]) {
    const p = pointFromSlope(slope);
    assert.equal(isOnCircle(p), true);
    assert.deepEqual(addCirclePoints(p, jPoint(p)), CIRCLE_IDENTITY);
    assert.deepEqual(doubleCirclePoint(antipode(p)), doubleCirclePoint(p));
  }
});

test('standard cosets are J-symmetric, unique, ordered, and avoid y=0', () => {
  for (const logSize of [1, 2, 3, 6, 10]) {
    const domain = buildStandardCoset(logSize);
    const parameters = standardCosetParameters(logSize);
    assert.equal(domain.length, 1 << logSize);
    assert.equal(parameters.size, BigInt(domain.length));
    assert.equal(new Set(domain.map(({ x, y }) => `${x}:${y}`)).size, domain.length);
    for (let index = 0; index < domain.length; index += 1) {
      const p = domain[index];
      const twin = domain[jTwinIndex(index, domain.length)];
      assert.equal(isOnCircle(p), true);
      assert.notEqual(p.y, 0n);
      assert.equal(twin.x, p.x);
      assert.equal(twin.y, neg(p.y));
      const next = domain[(index + 1) % domain.length];
      assert.deepEqual(addCirclePoints(p, parameters.step), next);
    }
  }
});

test('J fold exactly recovers a(x) + beta*b(x)', () => {
  const domain = buildStandardCoset(8);
  const beta = 987_654_321n;
  const a = (x) => add(7n, mul(13n, mul(x, x)));
  const b = (x) => add(19n, mul(23n, x));
  const codeword = domain.map(({ x, y }) => add(a(x), mul(y, b(x))));
  const folded = foldJLayer(domain, codeword, beta);
  assert.equal(folded.codeword.length, domain.length / 2);
  for (let index = 0; index < folded.codeword.length; index += 1) {
    const x = folded.domain[index];
    assert.equal(folded.codeword[index], add(a(x), mul(beta, b(x))));
  }
});

test('pi fold exactly recovers a(pi(x)) + beta*b(pi(x))', () => {
  const domain = buildStandardCoset(8);
  const jFolded = foldJLayer(domain, domain.map(({ x, y }) => add(x, y)), 5n);
  const beta = 123_456_789n;
  const a = (image) => add(29n, mul(31n, image));
  const b = (image) => add(37n, mul(41n, mul(image, image)));
  const codeword = jFolded.domain.map((x) => {
    const image = piX(x);
    return add(a(image), mul(x, b(image)));
  });
  const folded = foldPiLayer(jFolded.domain, codeword, beta);
  for (let index = 0; index < folded.codeword.length; index += 1) {
    const image = folded.domain[index];
    assert.equal(folded.codeword[index], add(a(image), mul(beta, b(image))));
  }
});

test('multi-layer fold halves one actual domain per challenge', () => {
  const domain = buildStandardCoset(10);
  const codeword = domain.map(({ x, y }) => add(mul(3n, x), mul(5n, y)));
  const result = foldCircleCodeword({
    domain,
    codeword,
    challenges: [11n, 13n, 17n, 19n, 23n],
  });
  assert.deepEqual(result.layers.map((layer) => layer.codeword.length), [512, 256, 128, 64, 32]);
  assert.equal(result.final.codeword.length, 32);
});

test('malformed domains and noncanonical values fail closed', () => {
  const domain = buildStandardCoset(3);
  assert.throws(() => foldJLayer(domain.slice(0, 7), new Array(7).fill(0n), 1n), /even number/);
  assert.throws(() => foldJLayer(domain, new Array(8).fill(M31_MODULUS), 1n), /canonical M31/);
  const malformed = domain.slice();
  malformed[7] = malformed[6];
  assert.throws(() => foldJLayer(malformed, new Array(8).fill(0n), 1n), /not J twins/);
  assert.throws(() => buildStandardCoset(21), /maximumPoints/);
});
