import {
  decodeCanonicalPolynomial,
  encodeCanonicalPolynomial,
  encodeCanonicalUnsignedDecimal
} from './canonical.mjs';
import {
  polyAdd,
  polyEqual,
  polyGcd,
  polyPowMod,
  polySub,
  polyX,
  polyXgcd,
  primeDivisors
} from './fp-polynomial.mjs';
import { generateMersennePrimeCheck, mersenneModulus } from './mersenne.mjs';

const requireMonicNonconstant = (polynomial, modulus) => {
  if (polynomial.length < 2) throw new RangeError('Rabin polynomial must have positive degree');
  if (polynomial.at(-1) !== 1n) throw new RangeError('Rabin polynomial must be monic');
  if (polynomial.some((coefficient) => coefficient < 0n || coefficient >= modulus)) {
    throw new RangeError('Rabin polynomial coefficient is outside Fp');
  }
};

const generateRabinWitnesses = (polynomial, modulus, hPowers) => {
  const degree = polynomial.length - 1;
  return primeDivisors(degree).map((primeDivisor) => {
    const hIndex = degree / primeDivisor;
    const g = polySub(hPowers[hIndex], polyX(), modulus);
    const gcd = polyGcd(polynomial, g, modulus);
    const { gcd: bezoutGcd, u, v } = polyXgcd(polynomial, g, modulus);
    if (!polyEqual(gcd, bezoutGcd, modulus)) throw new Error('internal gcd/xgcd disagreement');
    return {
      primeDivisor: encodeCanonicalUnsignedDecimal(BigInt(primeDivisor), 'primeDivisor'),
      hIndex: encodeCanonicalUnsignedDecimal(BigInt(hIndex), 'hIndex'),
      g: encodeCanonicalPolynomial(g),
      gcd: encodeCanonicalPolynomial(gcd),
      bezoutU: encodeCanonicalPolynomial(u),
      bezoutV: encodeCanonicalPolynomial(v)
    };
  });
};

export const generateRabinCertificate = ({ mersenneExponent, polynomialCoefficients }) => {
  const primeCheck = generateMersennePrimeCheck(mersenneExponent);
  if (!primeCheck.lucasLehmer.passed) throw new RangeError('Rabin certificate requires a prime modulus');
  const exponent = Number(BigInt(primeCheck.mersenneExponent));
  const modulus = mersenneModulus(exponent);
  const polynomial = decodeCanonicalPolynomial(polynomialCoefficients, modulus, 'polynomial');
  requireMonicNonconstant(polynomial, modulus);
  const degree = polynomial.length - 1;
  const hPowers = [polyPowMod(polyX(), 1n, polynomial, modulus)];
  for (let index = 1; index <= degree; index += 1) {
    hPowers.push(polyPowMod(hPowers[index - 1], modulus, polynomial, modulus));
  }
  const xResidue = polyPowMod(polyX(), 1n, polynomial, modulus);
  const witnesses = generateRabinWitnesses(polynomial, modulus, hPowers);
  return {
    certificateId: `certificate:mersenne-q${primeCheck.mersenneExponent}-d${degree}-rabin`,
    mersennePrimeCheck: primeCheck,
    modulus: primeCheck.modulus,
    coefficientEncoding: 'unsigned-decimal-c0-to-cd',
    polynomial: encodeCanonicalPolynomial(polynomial),
    degree: encodeCanonicalUnsignedDecimal(BigInt(degree), 'degree'),
    hPowers: hPowers.map((residue, index) => ({
      index: encodeCanonicalUnsignedDecimal(BigInt(index), 'h index'),
      coefficients: encodeCanonicalPolynomial(residue)
    })),
    primeDivisors: primeDivisors(degree).map((primeDivisor) => encodeCanonicalUnsignedDecimal(BigInt(primeDivisor), 'prime divisor')),
    witnesses,
    finalResidue: encodeCanonicalPolynomial(xResidue),
    conclusion: 'irreducible'
  };
};

export const generateFrontierPrimeChecksFixture = () => ({
  schema: 'shieldkit-labs/field-cert/v1',
  fixtureId: 'fixture:frontier-mersenne-prime-checks-v1',
  kind: 'mersenne-prime-check-fixture',
  status: 'generic-math-unqualified',
  casReview: 'not-cas-reviewed',
  evidenceClassification: 'not-evidence',
  selection: 'none',
  notes: [
    'Deterministic generic-math fixture only; it is not a field, protocol, or proof-system selection.',
    'Lucas-Lehmer acceptance establishes the listed Mersenne modulus primality only and does not establish systemic soundness.'
  ],
  checks: [13, 17, 19, 29, 31, 61, 89, 107, 127].map((exponent) => generateMersennePrimeCheck(exponent))
});

export const generateM89X2PlusOneFixture = () => ({
  schema: 'shieldkit-labs/field-cert/v1',
  fixtureId: 'fixture:m89-x2-plus-1-rabin-v1',
  kind: 'rabin-irreducibility-fixture',
  status: 'generic-math-unqualified',
  casReview: 'not-cas-reviewed',
  evidenceClassification: 'not-evidence',
  selection: 'none',
  notes: [
    'Analytical generic-math fixture only; it is not CAS-reviewed, implementation evidence, or a field-selection decision.',
    'The certificate records the exact Rabin residues, gcds, and Bezout witnesses for f = X^2 + 1 over M89.'
  ],
  certificate: generateRabinCertificate({
    mersenneExponent: '89',
    polynomialCoefficients: ['1', '0', '1']
  })
});
