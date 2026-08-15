import {
  M31_MODULUS,
  add,
  inverse,
  mul,
  neg,
  sub,
} from '../../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

export const CIRCLE_ORDER = M31_MODULUS + 1n;
export const CIRCLE_IDENTITY = Object.freeze({ x: 1n, y: 0n });

// Full-order generator used by the independently implemented verifier.cash
// Circle-STARK prototype. Its order is checked below and in the test suite.
export const CIRCLE_GENERATOR = Object.freeze({ x: 2n, y: 1_268_011_823n });

const fail = (message) => {
  throw new TypeError(message);
};

const assertElement = (value, name) => {
  if (typeof value !== 'bigint' || value < 0n || value >= M31_MODULUS) {
    fail(`${name} must be a canonical M31 element`);
  }
  return value;
};

export const point = (x, y) => Object.freeze({
  x: assertElement(x, 'x'),
  y: assertElement(y, 'y'),
});

export const isOnCircle = ({ x, y }) => add(mul(x, x), mul(y, y)) === 1n;

export const assertCirclePoint = (value, name = 'point') => {
  if (value === null || typeof value !== 'object') fail(`${name} must be a circle point`);
  const canonical = point(value.x, value.y);
  if (!isOnCircle(canonical)) fail(`${name} does not satisfy x^2 + y^2 = 1`);
  return canonical;
};

/** Circle group multiplication, identifying (x, y) with x + i*y. */
export const addCirclePoints = (left, right) => {
  const a = assertCirclePoint(left, 'left');
  const b = assertCirclePoint(right, 'right');
  return point(
    sub(mul(a.x, b.x), mul(a.y, b.y)),
    add(mul(a.x, b.y), mul(a.y, b.x)),
  );
};

/** Group inverse and Circle-FRI J involution: (x, y) -> (x, -y). */
export const jPoint = (value) => {
  const p = assertCirclePoint(value);
  return point(p.x, neg(p.y));
};

/** Antipodal point: the second preimage of circle doubling. */
export const antipode = (value) => {
  const p = assertCirclePoint(value);
  return point(neg(p.x), neg(p.y));
};

export const scalarMultiplyCircle = (value, scalar) => {
  const p = assertCirclePoint(value);
  if (typeof scalar !== 'bigint' || scalar < 0n) fail('scalar must be a nonnegative BigInt');
  let result = CIRCLE_IDENTITY;
  let base = p;
  let remaining = scalar;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = addCirclePoints(result, base);
    base = addCirclePoints(base, base);
    remaining >>= 1n;
  }
  return result;
};

export const doubleCirclePoint = (value) => addCirclePoints(value, value);

/** x-coordinate of circle doubling, pi(x) = 2*x^2 - 1. */
export const piX = (x) => sub(mul(2n, mul(assertElement(x, 'x'), x)), 1n);

/** Rational parametrization of every point except (-1, 0). */
export const pointFromSlope = (slope) => {
  const t = assertElement(slope, 'slope');
  const tSquared = mul(t, t);
  const denominatorInverse = inverse(add(1n, tSquared));
  return point(
    mul(sub(1n, tSquared), denominatorInverse),
    mul(mul(2n, t), denominatorInverse),
  );
};

const assertLogSize = (logSize) => {
  if (!Number.isSafeInteger(logSize) || logSize < 1 || logSize > 30) {
    fail('logSize must be an integer in [1, 30]');
  }
  return logSize;
};

/**
 * Standard-position J-symmetric coset of 2^logSize points.
 *
 * The shift is one half-step relative to the subgroup generator. This avoids
 * y=0 and makes point i's J twin exactly point (N - 1 - i).
 */
export const standardCosetParameters = (logSize) => {
  const bits = assertLogSize(logSize);
  const size = 1n << BigInt(bits);
  const stepScalar = CIRCLE_ORDER / size;
  const shiftScalar = stepScalar / 2n;
  return Object.freeze({
    logSize: bits,
    size,
    step: scalarMultiplyCircle(CIRCLE_GENERATOR, stepScalar),
    shift: scalarMultiplyCircle(CIRCLE_GENERATOR, shiftScalar),
  });
};

export function* iterateStandardCoset(logSize) {
  const parameters = standardCosetParameters(logSize);
  let current = parameters.shift;
  for (let index = 0n; index < parameters.size; index += 1n) {
    yield current;
    current = addCirclePoints(current, parameters.step);
  }
}

export const buildStandardCoset = (logSize, { maximumPoints = 1 << 20 } = {}) => {
  const parameters = standardCosetParameters(logSize);
  if (!Number.isSafeInteger(maximumPoints) || maximumPoints < 1) fail('maximumPoints must be a positive safe integer');
  if (parameters.size > BigInt(maximumPoints)) {
    fail(`domain has ${parameters.size} points, exceeding maximumPoints=${maximumPoints}`);
  }
  return Array.from(iterateStandardCoset(logSize));
};

export const jTwinIndex = (index, size) => {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || size < 2 || index < 0 || index >= size) {
    fail('index and size must identify a point in a nontrivial domain');
  }
  return size - 1 - index;
};

// Fail immediately if the fixed generator or group-order assumption drifts.
assertCirclePoint(CIRCLE_GENERATOR, 'CIRCLE_GENERATOR');
const generatorHalfOrder = scalarMultiplyCircle(CIRCLE_GENERATOR, CIRCLE_ORDER / 2n);
if (generatorHalfOrder.x !== M31_MODULUS - 1n || generatorHalfOrder.y !== 0n) {
  throw new Error('CIRCLE_GENERATOR does not have order 2^31');
}
