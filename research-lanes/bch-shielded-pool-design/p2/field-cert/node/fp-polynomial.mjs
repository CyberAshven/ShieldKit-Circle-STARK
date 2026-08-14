const requireModulus = (modulus) => {
  if (typeof modulus !== 'bigint' || modulus <= 1n) {
    throw new RangeError('Fp modulus must be a bigint greater than one');
  }
};

const requireBigInt = (value, label) => {
  if (typeof value !== 'bigint') throw new TypeError(`${label} must be a bigint`);
  return value;
};

export const mod = (value, modulus) => {
  requireModulus(modulus);
  const reduced = requireBigInt(value, 'value') % modulus;
  return reduced < 0n ? reduced + modulus : reduced;
};

export const polyNormalize = (coefficients, modulus) => {
  requireModulus(modulus);
  if (!Array.isArray(coefficients) || coefficients.length === 0) {
    throw new TypeError('polynomial must be a nonempty coefficient array');
  }
  const normalized = coefficients.map((coefficient, index) => mod(requireBigInt(coefficient, `coefficient ${index}`), modulus));
  while (normalized.length > 1 && normalized.at(-1) === 0n) normalized.pop();
  return normalized;
};

export const polyZero = () => [0n];
export const polyOne = () => [1n];
export const polyX = () => [0n, 1n];

export const polyIsZero = (polynomial, modulus) => {
  const normalized = polyNormalize(polynomial, modulus);
  return normalized.length === 1 && normalized[0] === 0n;
};

export const polyEqual = (left, right, modulus) => {
  const normalizedLeft = polyNormalize(left, modulus);
  const normalizedRight = polyNormalize(right, modulus);
  return normalizedLeft.length === normalizedRight.length
    && normalizedLeft.every((coefficient, index) => coefficient === normalizedRight[index]);
};

export const polyAdd = (left, right, modulus) => {
  const a = polyNormalize(left, modulus);
  const b = polyNormalize(right, modulus);
  const length = Math.max(a.length, b.length);
  const result = Array.from({ length }, (_, index) => mod((a[index] ?? 0n) + (b[index] ?? 0n), modulus));
  return polyNormalize(result, modulus);
};

export const polyNeg = (polynomial, modulus) => {
  const normalized = polyNormalize(polynomial, modulus);
  return polyNormalize(normalized.map((coefficient) => mod(-coefficient, modulus)), modulus);
};

export const polySub = (left, right, modulus) => polyAdd(left, polyNeg(right, modulus), modulus);

export const polyScale = (polynomial, scalar, modulus) => {
  const normalized = polyNormalize(polynomial, modulus);
  const factor = mod(requireBigInt(scalar, 'scalar'), modulus);
  return polyNormalize(normalized.map((coefficient) => mod(coefficient * factor, modulus)), modulus);
};

export const polyMul = (left, right, modulus) => {
  const a = polyNormalize(left, modulus);
  const b = polyNormalize(right, modulus);
  const result = Array.from({ length: a.length + b.length - 1 }, () => 0n);
  for (let i = 0; i < a.length; i += 1) {
    for (let j = 0; j < b.length; j += 1) {
      result[i + j] = mod(result[i + j] + a[i] * b[j], modulus);
    }
  }
  return polyNormalize(result, modulus);
};

export const inverseMod = (value, modulus) => {
  requireModulus(modulus);
  let oldR = mod(requireBigInt(value, 'value'), modulus);
  let r = modulus;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1n) throw new RangeError('coefficient has no inverse modulo modulus');
  return mod(oldS, modulus);
};

export const polyDivMod = (dividend, divisor, modulus) => {
  const numerator = polyNormalize(dividend, modulus);
  const denominator = polyNormalize(divisor, modulus);
  if (polyIsZero(denominator, modulus)) throw new RangeError('division by zero polynomial');
  if (numerator.length < denominator.length) return [polyZero(), numerator];

  const quotient = Array.from({ length: numerator.length - denominator.length + 1 }, () => 0n);
  let remainder = [...numerator];
  const inverseLeading = inverseMod(denominator.at(-1), modulus);
  while (!polyIsZero(remainder, modulus) && remainder.length >= denominator.length) {
    const shift = remainder.length - denominator.length;
    const factor = mod(remainder.at(-1) * inverseLeading, modulus);
    quotient[shift] = mod(quotient[shift] + factor, modulus);
    for (let index = 0; index < denominator.length; index += 1) {
      remainder[index + shift] = mod(remainder[index + shift] - factor * denominator[index], modulus);
    }
    remainder = polyNormalize(remainder, modulus);
  }
  return [polyNormalize(quotient, modulus), remainder];
};

export const polyGcd = (left, right, modulus) => {
  let a = polyNormalize(left, modulus);
  let b = polyNormalize(right, modulus);
  while (!polyIsZero(b, modulus)) {
    const [, remainder] = polyDivMod(a, b, modulus);
    [a, b] = [b, remainder];
  }
  if (polyIsZero(a, modulus)) return polyZero();
  return polyScale(a, inverseMod(a.at(-1), modulus), modulus);
};

export const polyXgcd = (left, right, modulus) => {
  let oldR = polyNormalize(left, modulus);
  let r = polyNormalize(right, modulus);
  let oldS = polyOne();
  let s = polyZero();
  let oldT = polyZero();
  let t = polyOne();

  while (!polyIsZero(r, modulus)) {
    const [quotient, remainder] = polyDivMod(oldR, r, modulus);
    [oldR, r] = [r, remainder];
    [oldS, s] = [s, polySub(oldS, polyMul(quotient, s, modulus), modulus)];
    [oldT, t] = [t, polySub(oldT, polyMul(quotient, t, modulus), modulus)];
  }
  if (polyIsZero(oldR, modulus)) return { gcd: polyZero(), u: polyZero(), v: polyZero() };
  const scale = inverseMod(oldR.at(-1), modulus);
  return {
    gcd: polyScale(oldR, scale, modulus),
    u: polyScale(oldS, scale, modulus),
    v: polyScale(oldT, scale, modulus)
  };
};

export const polyPowMod = (base, exponent, modulusPolynomial, modulus) => {
  const power = requireBigInt(exponent, 'exponent');
  if (power < 0n) throw new RangeError('polynomial exponent must be nonnegative');
  const [, reducedBase] = polyDivMod(base, modulusPolynomial, modulus);
  let result = polyOne();
  let factor = reducedBase;
  let remaining = power;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = polyDivMod(polyMul(result, factor, modulus), modulusPolynomial, modulus)[1];
    remaining >>= 1n;
    if (remaining > 0n) factor = polyDivMod(polyMul(factor, factor, modulus), modulusPolynomial, modulus)[1];
  }
  return polyNormalize(result, modulus);
};

export const primeDivisors = (value) => {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError('degree must be a positive safe integer');
  const factors = [];
  let remaining = value;
  for (let divisor = 2; divisor * divisor <= remaining; divisor += divisor === 2 ? 1 : 2) {
    if (remaining % divisor === 0) {
      factors.push(divisor);
      while (remaining % divisor === 0) remaining /= divisor;
    }
  }
  if (remaining > 1) factors.push(remaining);
  return factors;
};
