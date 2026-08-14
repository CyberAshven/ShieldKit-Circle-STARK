import { encodeCanonicalUnsignedDecimal, parsePositiveSafeInteger } from './canonical.mjs';

export const isPrimeExponent = (exponent) => {
  if (!Number.isSafeInteger(exponent) || exponent < 2) return false;
  if (exponent === 2) return true;
  if (exponent % 2 === 0) return false;
  for (let divisor = 3; divisor * divisor <= exponent; divisor += 2) {
    if (exponent % divisor === 0) return false;
  }
  return true;
};

export const mersenneModulus = (exponent) => {
  if (!Number.isSafeInteger(exponent) || exponent < 2) throw new RangeError('Mersenne exponent must be at least two');
  return (1n << BigInt(exponent)) - 1n;
};

export const lucasLehmer = (exponent) => {
  if (!isPrimeExponent(exponent)) {
    throw new RangeError('Lucas-Lehmer requires a prime exponent');
  }
  const modulus = mersenneModulus(exponent);
  if (exponent === 2) return { iterations: 0, residue: 0n, passed: true };
  let state = 4n;
  for (let iteration = 0; iteration < exponent - 2; iteration += 1) {
    state = (state * state - 2n) % modulus;
    if (state < 0n) state += modulus;
  }
  return { iterations: exponent - 2, residue: state, passed: state === 0n };
};

export const generateMersennePrimeCheck = (exponentValue) => {
  const exponent = typeof exponentValue === 'number'
    ? exponentValue
    : parsePositiveSafeInteger(exponentValue, 'mersenneExponent');
  if (!isPrimeExponent(exponent)) throw new RangeError('fixture exponent is not prime');
  const modulus = mersenneModulus(exponent);
  const result = lucasLehmer(exponent);
  return {
    mersenneExponent: encodeCanonicalUnsignedDecimal(BigInt(exponent), 'mersenneExponent'),
    exponentPrime: true,
    exponentPrimalityMethod: 'deterministic-trial-division',
    modulus: encodeCanonicalUnsignedDecimal(modulus, 'modulus'),
    lucasLehmer: {
      iterations: encodeCanonicalUnsignedDecimal(BigInt(result.iterations), 'iterations'),
      residue: encodeCanonicalUnsignedDecimal(result.residue, 'residue'),
      passed: result.passed
    },
    classification: result.passed ? 'prime' : 'rejected-composite'
  };
};
