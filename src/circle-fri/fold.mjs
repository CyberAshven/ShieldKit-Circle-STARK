import {
  M31_MODULUS,
  add,
  inverse,
  mul,
  neg,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import {
  assertCirclePoint,
  jTwinIndex,
  piX,
} from './circle.mjs';

export const M31_HALF = (M31_MODULUS + 1n) / 2n;

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

const assertCodeword = (values, expectedLength) => {
  if (!Array.isArray(values) || values.length !== expectedLength) {
    fail(`codeword must contain exactly ${expectedLength} values`);
  }
  return values.map((value, index) => assertElement(value, `codeword[${index}]`));
};

/** Fold a pair f(+z), f(-z) into its even/odd decomposition at challenge beta. */
export const foldPair = ({ positive, negative, coordinate, beta }) => {
  const fPositive = assertElement(positive, 'positive');
  const fNegative = assertElement(negative, 'negative');
  const z = assertElement(coordinate, 'coordinate');
  const challenge = assertElement(beta, 'beta');
  if (z === 0n) fail('fold coordinate must be nonzero');
  const even = mul(add(fPositive, fNegative), M31_HALF);
  const odd = mul(sub(fPositive, fNegative), inverse(mul(2n, z)));
  return Object.freeze({
    even,
    odd,
    value: add(even, mul(challenge, odd)),
  });
};

/**
 * First Circle-FRI layer: fold J twins (x,+/-y) to the distinct x line.
 */
export const foldJLayer = (domain, codeword, beta) => {
  if (!Array.isArray(domain) || domain.length < 2 || (domain.length & 1) !== 0) {
    fail('J domain must contain an even number of points');
  }
  const values = assertCodeword(codeword, domain.length);
  const challenge = assertElement(beta, 'beta');
  const half = domain.length / 2;
  const xDomain = new Array(half);
  const folded = new Array(half);
  const pairs = new Array(half);

  for (let index = 0; index < half; index += 1) {
    const twin = jTwinIndex(index, domain.length);
    const positive = assertCirclePoint(domain[index], `domain[${index}]`);
    const negative = assertCirclePoint(domain[twin], `domain[${twin}]`);
    if (positive.x !== negative.x || positive.y !== neg(negative.y)) {
      fail(`domain points ${index} and ${twin} are not J twins`);
    }
    const result = foldPair({
      positive: values[index],
      negative: values[twin],
      coordinate: positive.y,
      beta: challenge,
    });
    xDomain[index] = positive.x;
    folded[index] = result.value;
    pairs[index] = Object.freeze({ index, twin, x: positive.x, y: positive.y, ...result });
  }
  return Object.freeze({ domain: xDomain, codeword: folded, pairs });
};

/**
 * Later Circle-FRI layers: fold x and -x to pi(x)=2*x^2-1.
 */
export const foldPiLayer = (xDomain, codeword, beta) => {
  if (!Array.isArray(xDomain) || xDomain.length < 2 || (xDomain.length & 1) !== 0) {
    fail('pi domain must contain an even number of x coordinates');
  }
  const xs = xDomain.map((x, index) => assertElement(x, `xDomain[${index}]`));
  const values = assertCodeword(codeword, xs.length);
  const challenge = assertElement(beta, 'beta');
  const byImage = new Map();
  for (let index = 0; index < xs.length; index += 1) {
    const image = piX(xs[index]);
    const key = image.toString();
    const entries = byImage.get(key) ?? [];
    entries.push(index);
    byImage.set(key, entries);
  }

  const nextDomain = [];
  const folded = [];
  const pairs = [];
  for (const [imageText, indices] of byImage) {
    if (indices.length !== 2) fail(`pi image ${imageText} does not have exactly two preimages`);
    const [leftIndex, rightIndex] = indices;
    const leftX = xs[leftIndex];
    const rightX = xs[rightIndex];
    if (rightX !== neg(leftX)) fail(`pi preimages ${leftIndex} and ${rightIndex} are not x/-x`);
    const result = foldPair({
      positive: values[leftIndex],
      negative: values[rightIndex],
      coordinate: leftX,
      beta: challenge,
    });
    const image = BigInt(imageText);
    nextDomain.push(image);
    folded.push(result.value);
    pairs.push(Object.freeze({
      leftIndex,
      rightIndex,
      x: leftX,
      image,
      ...result,
    }));
  }
  return Object.freeze({ domain: nextDomain, codeword: folded, pairs });
};

export const foldCircleCodeword = ({ domain, codeword, challenges }) => {
  if (!Array.isArray(challenges) || challenges.length < 1) fail('at least one challenge is required');
  const layers = [];
  const first = foldJLayer(domain, codeword, challenges[0]);
  layers.push(first);
  let current = first;
  for (let index = 1; index < challenges.length; index += 1) {
    if (current.codeword.length < 2) fail('too many fold challenges for codeword length');
    current = foldPiLayer(current.domain, current.codeword, challenges[index]);
    layers.push(current);
  }
  return Object.freeze({ layers, final: current });
};
