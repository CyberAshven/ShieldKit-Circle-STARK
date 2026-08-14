const canonicalUnsignedDecimal = /^(0|[1-9][0-9]*)$/u;

export const requireExactKeys = (value, keys, label) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} has missing or unexpected keys`);
  }
};

export const parseCanonicalUnsignedDecimal = (value, label) => {
  if (typeof value !== 'string' || !canonicalUnsignedDecimal.test(value)) {
    throw new TypeError(`${label} must be canonical unsigned decimal`);
  }
  return BigInt(value);
};

export const encodeCanonicalUnsignedDecimal = (value, label) => {
  if (typeof value !== 'bigint' || value < 0n) {
    throw new TypeError(`${label} must be a nonnegative bigint`);
  }
  return value.toString(10);
};

export const parsePositiveSafeInteger = (value, label) => {
  const parsed = parseCanonicalUnsignedDecimal(value, label);
  if (parsed < 1n || parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return Number(parsed);
};

export const parseCanonicalModulus = (value, label = 'modulus') => {
  const modulus = parseCanonicalUnsignedDecimal(value, label);
  if (modulus <= 1n) throw new RangeError(`${label} must exceed one`);
  return modulus;
};

export const decodeCanonicalPolynomial = (coefficients, modulus, label) => {
  if (!Array.isArray(coefficients) || coefficients.length === 0) {
    throw new TypeError(`${label} must be a nonempty coefficient array`);
  }
  const decoded = coefficients.map((coefficient, index) => {
    const value = parseCanonicalUnsignedDecimal(coefficient, `${label}[${index}]`);
    if (value >= modulus) throw new RangeError(`${label}[${index}] is outside Fp`);
    return value;
  });
  if (decoded.length > 1 && decoded.at(-1) === 0n) {
    throw new TypeError(`${label} has a noncanonical trailing zero`);
  }
  return decoded;
};

export const encodeCanonicalPolynomial = (coefficients) => {
  if (!Array.isArray(coefficients) || coefficients.length === 0) {
    throw new TypeError('coefficients must be a nonempty normalized polynomial');
  }
  return coefficients.map((coefficient, index) => encodeCanonicalUnsignedDecimal(coefficient, `coefficient ${index}`));
};

export const sameJson = (left, right) => JSON.stringify(left) === JSON.stringify(right);
