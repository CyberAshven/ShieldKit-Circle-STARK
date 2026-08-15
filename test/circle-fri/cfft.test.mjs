import test from 'node:test';
import assert from 'node:assert/strict';

import {
  M31_MODULUS,
  add,
  mul,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  buildStandardCoset,
  pointFromSlope,
} from '../../src/circle-fri/circle.mjs';

import {
  circleFFT,
  circleIFFT,
  evaluateCirclePolynomial,
  extendCircleEvaluations,
} from '../../src/circle-fri/cfft.mjs';

const deterministicElements = (length, seed = 0x726f6f74n) => {
  let state = seed;
  return Array.from({ length }, () => {
    state = (state * 6_364_136_223_846_793_005n + 1_442_695_040_888_963_407n) & ((1n << 64n) - 1n);
    return (state >> 17n) % M31_MODULUS;
  });
};

// Deliberately separate evaluator: this follows the basis definition directly
// and shares no planning/butterfly code with circleFFT.
const evaluateXNaive = (coefficients, x) => {
  if (coefficients.length === 1) return coefficients[0];
  const half = coefficients.length / 2;
  const image = add(mul(2n, mul(x, x)), M31_MODULUS - 1n);
  return add(
    evaluateXNaive(coefficients.slice(0, half), image),
    mul(x, evaluateXNaive(coefficients.slice(half), image)),
  );
};

const evaluateCircleNaive = (coefficients, { x, y }) => {
  if (coefficients.length === 1) return coefficients[0];
  const half = coefficients.length / 2;
  return add(
    evaluateXNaive(coefficients.slice(0, half), x),
    mul(y, evaluateXNaive(coefficients.slice(half), x)),
  );
};

test('Circle FFT and IFFT round-trip sizes 2 through 1024', () => {
  for (let logSize = 1; logSize <= 10; logSize += 1) {
    const domain = buildStandardCoset(logSize);
    const coefficients = deterministicElements(domain.length, BigInt(logSize));
    const evaluations = circleFFT(domain, coefficients);
    assert.deepEqual(circleIFFT(domain, evaluations), coefficients);
  }
});

test('forward butterflies agree with an independent basis evaluator', () => {
  for (let logSize = 1; logSize <= 7; logSize += 1) {
    const domain = buildStandardCoset(logSize);
    const coefficients = deterministicElements(domain.length, 100n + BigInt(logSize));
    assert.deepEqual(
      circleFFT(domain, coefficients),
      domain.map((p) => evaluateCircleNaive(coefficients, p)),
    );
  }
});

test('single-point evaluation agrees on-domain and off-domain', () => {
  const domain = buildStandardCoset(7);
  const coefficients = deterministicElements(domain.length, 0x63666674n);
  const evaluations = circleFFT(domain, coefficients);
  for (let index = 0; index < domain.length; index += 7) {
    assert.equal(evaluateCirclePolynomial(coefficients, domain[index]), evaluations[index]);
  }
  for (const slope of [0n, 1n, 7n, 123_456n, M31_MODULUS - 1n]) {
    const p = pointFromSlope(slope);
    assert.equal(
      evaluateCirclePolynomial(coefficients, p),
      evaluateCircleNaive(coefficients, p),
    );
  }
});

test('strided Circle LDE preserves the source polynomial on a larger coset', () => {
  const sourceDomain = buildStandardCoset(4);
  const targetDomain = buildStandardCoset(8);
  const sourceCoefficients = deterministicElements(sourceDomain.length, 0x6c6465n);
  const values = circleFFT(sourceDomain, sourceCoefficients);
  const result = extendCircleEvaluations({ sourceDomain, targetDomain, values });
  assert.equal(result.stride, 16);
  assert.deepEqual(result.coefficients, sourceCoefficients);
  assert.deepEqual(
    result.evaluations,
    targetDomain.map((p) => evaluateCircleNaive(sourceCoefficients, p)),
  );
});

test('CFFT rejects malformed lengths, values, and recursive fibers', () => {
  const domain = buildStandardCoset(3);
  assert.throws(() => circleIFFT(domain, [1n]), /exactly 8/);
  assert.throws(() => circleFFT(domain, new Array(8).fill(M31_MODULUS)), /canonical M31/);
  assert.throws(() => circleFFT(domain.slice(0, 6), new Array(6).fill(0n)), /power of two/);

  const brokenJ = domain.slice();
  brokenJ[7] = brokenJ[6];
  assert.throws(() => circleIFFT(brokenJ, new Array(8).fill(0n)), /exactly two J preimages|not J twins/);

  assert.throws(() => extendCircleEvaluations({
    sourceDomain: buildStandardCoset(4),
    targetDomain: buildStandardCoset(3),
    values: new Array(16).fill(0n),
  }), /multiple/);
});
