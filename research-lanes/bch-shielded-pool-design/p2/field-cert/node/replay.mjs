import {
  decodeCanonicalPolynomial,
  encodeCanonicalPolynomial,
  encodeCanonicalUnsignedDecimal,
  parseCanonicalModulus,
  parsePositiveSafeInteger,
  requireExactKeys,
  sameJson
} from './canonical.mjs';
import {
  polyAdd,
  polyEqual,
  polyGcd,
  polyMul,
  polyPowMod,
  polySub,
  polyX,
  polyXgcd,
  primeDivisors
} from './fp-polynomial.mjs';
import { isPrimeExponent, lucasLehmer, mersenneModulus } from './mersenne.mjs';

const primeCheckKeys = [
  'mersenneExponent',
  'exponentPrime',
  'exponentPrimalityMethod',
  'modulus',
  'lucasLehmer',
  'classification'
];

const certificateKeys = [
  'certificateId',
  'mersennePrimeCheck',
  'modulus',
  'coefficientEncoding',
  'polynomial',
  'degree',
  'hPowers',
  'primeDivisors',
  'witnesses',
  'finalResidue',
  'conclusion'
];

const frontierFixtureNotes = [
  'Deterministic generic-math fixture only; it is not a field, protocol, or proof-system selection.',
  'Lucas-Lehmer acceptance establishes the listed Mersenne modulus primality only and does not establish systemic soundness.'
];

const m89FixtureNotes = [
  'Analytical generic-math fixture only; it is not CAS-reviewed, implementation evidence, or a field-selection decision.',
  'The certificate records the exact Rabin residues, gcds, and Bezout witnesses for f = X^2 + 1 over M89.'
];

const recomputePrimeCheck = (stored) => {
  requireExactKeys(stored, primeCheckKeys, 'Mersenne prime check');
  requireExactKeys(stored.lucasLehmer, ['iterations', 'residue', 'passed'], 'Lucas-Lehmer result');
  const exponent = parsePositiveSafeInteger(stored.mersenneExponent, 'mersenneExponent');
  if (!isPrimeExponent(exponent)) throw new RangeError('stored exponent is not prime');
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

const parseHResidues = (storedH, polynomial, modulus, degree) => {
  if (!Array.isArray(storedH) || storedH.length !== degree + 1) {
    throw new RangeError('hPowers must retain exactly h_0 through h_d');
  }
  const parsed = [];
  let expected = polyPowMod(polyX(), 1n, polynomial, modulus);
  for (let index = 0; index <= degree; index += 1) {
    const entry = storedH[index];
    requireExactKeys(entry, ['index', 'coefficients'], `hPowers[${index}]`);
    if (entry.index !== encodeCanonicalUnsignedDecimal(BigInt(index), `hPowers[${index}].index`)) {
      throw new RangeError(`hPowers[${index}] index mismatch`);
    }
    const storedPolynomial = decodeCanonicalPolynomial(entry.coefficients, modulus, `hPowers[${index}].coefficients`);
    if (!polyEqual(storedPolynomial, expected, modulus)) throw new RangeError(`hPowers[${index}] residue mismatch`);
    parsed.push(storedPolynomial);
    expected = polyPowMod(expected, modulus, polynomial, modulus);
  }
  return parsed;
};

const replayWitnesses = (stored, polynomial, modulus, hPowers, degree) => {
  const expectedDivisors = primeDivisors(degree);
  if (!Array.isArray(stored.primeDivisors) || stored.primeDivisors.length !== expectedDivisors.length) {
    throw new RangeError('Rabin prime-divisor inventory mismatch');
  }
  if (!Array.isArray(stored.witnesses) || stored.witnesses.length !== expectedDivisors.length) {
    throw new RangeError('Rabin witness inventory mismatch');
  }
  const expectedPrimeDivisors = expectedDivisors.map((value) => encodeCanonicalUnsignedDecimal(BigInt(value), 'prime divisor'));
  if (!sameJson(stored.primeDivisors, expectedPrimeDivisors)) throw new RangeError('Rabin prime divisors mismatch');

  for (let index = 0; index < expectedDivisors.length; index += 1) {
    const primeDivisor = expectedDivisors[index];
    const hIndex = degree / primeDivisor;
    const witness = stored.witnesses[index];
    requireExactKeys(witness, ['primeDivisor', 'hIndex', 'g', 'gcd', 'bezoutU', 'bezoutV'], `witness ${index}`);
    if (witness.primeDivisor !== encodeCanonicalUnsignedDecimal(BigInt(primeDivisor), 'prime divisor')) {
      throw new RangeError(`witness ${index} prime divisor mismatch`);
    }
    if (witness.hIndex !== encodeCanonicalUnsignedDecimal(BigInt(hIndex), 'h index')) {
      throw new RangeError(`witness ${index} h index mismatch`);
    }
    const g = polySub(hPowers[hIndex], polyX(), modulus);
    const storedG = decodeCanonicalPolynomial(witness.g, modulus, `witness ${index}.g`);
    if (!polyEqual(storedG, g, modulus)) throw new RangeError(`witness ${index} g mismatch`);
    const gcd = polyGcd(polynomial, g, modulus);
    const storedGcd = decodeCanonicalPolynomial(witness.gcd, modulus, `witness ${index}.gcd`);
    if (!polyEqual(storedGcd, gcd, modulus) || !polyEqual(gcd, [1n], modulus)) {
      throw new RangeError(`witness ${index} gcd is not exactly one`);
    }
    const { gcd: bezoutGcd, u, v } = polyXgcd(polynomial, g, modulus);
    const storedU = decodeCanonicalPolynomial(witness.bezoutU, modulus, `witness ${index}.bezoutU`);
    const storedV = decodeCanonicalPolynomial(witness.bezoutV, modulus, `witness ${index}.bezoutV`);
    if (!polyEqual(bezoutGcd, [1n], modulus)
      || !polyEqual(storedU, u, modulus)
      || !polyEqual(storedV, v, modulus)) {
      throw new RangeError(`witness ${index} deterministic Bezout mismatch`);
    }
    const bezout = polyAdd(polyMul(storedU, polynomial, modulus), polyMul(storedV, g, modulus), modulus);
    if (!polyEqual(bezout, [1n], modulus)) throw new RangeError(`witness ${index} Bezout identity mismatch`);
  }
};

export const replayMersennePrimeCheck = (stored) => {
  try {
    return sameJson(stored, recomputePrimeCheck(stored));
  } catch {
    return false;
  }
};

export const replayRabinCertificate = (stored) => {
  try {
    requireExactKeys(stored, certificateKeys, 'Rabin certificate');
    if (!replayMersennePrimeCheck(stored.mersennePrimeCheck)) throw new RangeError('Mersenne prime check failed');
    if (stored.mersennePrimeCheck.lucasLehmer.passed !== true) throw new RangeError('Rabin certificate modulus is not prime');
    const modulus = parseCanonicalModulus(stored.modulus, 'certificate modulus');
    if (stored.modulus !== stored.mersennePrimeCheck.modulus) throw new RangeError('certificate modulus differs from prime check');
    if (stored.coefficientEncoding !== 'unsigned-decimal-c0-to-cd') throw new RangeError('coefficient encoding mismatch');
    const polynomial = decodeCanonicalPolynomial(stored.polynomial, modulus, 'polynomial');
    if (polynomial.length < 2 || polynomial.at(-1) !== 1n) throw new RangeError('polynomial must be monic and nonconstant');
    const degree = parsePositiveSafeInteger(stored.degree, 'degree');
    if (degree !== polynomial.length - 1) throw new RangeError('stored degree mismatch');
    const exponent = stored.mersennePrimeCheck.mersenneExponent;
    if (stored.certificateId !== `certificate:mersenne-q${exponent}-d${degree}-rabin`) {
      throw new RangeError('certificate identity mismatch');
    }
    const hPowers = parseHResidues(stored.hPowers, polynomial, modulus, degree);
    const finalResidue = decodeCanonicalPolynomial(stored.finalResidue, modulus, 'finalResidue');
    if (!polyEqual(finalResidue, polyPowMod(polyX(), 1n, polynomial, modulus), modulus)) {
      throw new RangeError('final residue must equal X mod f');
    }
    if (!polyEqual(hPowers.at(-1), finalResidue, modulus)) throw new RangeError('h_d does not equal X mod f');
    replayWitnesses(stored, polynomial, modulus, hPowers, degree);
    if (stored.conclusion !== 'irreducible') throw new RangeError('Rabin conclusion mismatch');
    return true;
  } catch {
    return false;
  }
};

const fixtureEnvelope = (stored, kind, fixtureId, expectedNotes) => {
  requireExactKeys(stored, [
    'schema',
    'fixtureId',
    'kind',
    'status',
    'casReview',
    'evidenceClassification',
    'selection',
    'notes',
    kind === 'mersenne-prime-check-fixture' ? 'checks' : 'certificate'
  ], 'fixture envelope');
  if (stored.schema !== 'shieldkit-labs/field-cert/v1'
    || stored.fixtureId !== fixtureId
    || stored.kind !== kind
    || stored.status !== 'generic-math-unqualified'
    || stored.casReview !== 'not-cas-reviewed'
    || stored.evidenceClassification !== 'not-evidence'
    || stored.selection !== 'none'
    || !sameJson(stored.notes, expectedNotes)) {
    throw new RangeError('fixture envelope mismatch');
  }
};

export const replayFrontierPrimeChecksFixture = (stored) => {
  try {
    fixtureEnvelope(stored, 'mersenne-prime-check-fixture', 'fixture:frontier-mersenne-prime-checks-v1', frontierFixtureNotes);
    const expectedExponents = ['13', '17', '19', '29', '31', '61', '89', '107', '127'];
    if (!Array.isArray(stored.checks) || stored.checks.length !== expectedExponents.length) return false;
    return stored.checks.every((check, index) => check.mersenneExponent === expectedExponents[index] && replayMersennePrimeCheck(check));
  } catch {
    return false;
  }
};

export const replayM89X2PlusOneFixture = (stored) => {
  try {
    fixtureEnvelope(stored, 'rabin-irreducibility-fixture', 'fixture:m89-x2-plus-1-rabin-v1', m89FixtureNotes);
    return replayRabinCertificate(stored.certificate);
  } catch {
    return false;
  }
};
