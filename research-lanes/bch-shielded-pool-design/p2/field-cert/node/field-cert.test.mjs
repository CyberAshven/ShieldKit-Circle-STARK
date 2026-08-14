import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

import {
  generateFrontierPrimeChecksFixture,
  generateM89X2PlusOneFixture,
  polyAdd,
  polyDivMod,
  polyEqual,
  polyGcd,
  polyMul,
  polyPowMod,
  polySub,
  polyXgcd,
  replayFrontierPrimeChecksFixture,
  replayM89X2PlusOneFixture,
  replayMersennePrimeCheck,
  replayRabinCertificate
} from './index.mjs';

const fixture = (name) => JSON.parse(readFileSync(new URL(`../fixtures/${name}`, import.meta.url), 'utf8'));
const copy = (value) => structuredClone(value);

const frontier = fixture('frontier-prime-checks.v1.json');
const m89 = fixture('m89-x2-plus-1-rabin.v1.json');
const schema = JSON.parse(readFileSync(new URL('../certificate.schema.json', import.meta.url), 'utf8'));
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

test('generator output is deterministic and matches the stored generic fixtures', () => {
  assert.deepEqual(generateFrontierPrimeChecksFixture(), frontier);
  assert.deepEqual(generateM89X2PlusOneFixture(), m89);
});

test('frontier Mersenne checks and the M89 Rabin certificate replay', () => {
  assert.equal(replayFrontierPrimeChecksFixture(frontier), true);
  assert.equal(replayM89X2PlusOneFixture(m89), true);
  assert.equal(replayMersennePrimeCheck(frontier.checks.find((check) => check.mersenneExponent === '29')), true);
  assert.equal(frontier.checks.find((check) => check.mersenneExponent === '29').lucasLehmer.passed, false);
  assert.equal(replayRabinCertificate(m89.certificate), true);
});

test('fixture checker emits one canonical PASS line after strict schema validation and replay', () => {
  const checkerPath = fileURLToPath(new URL('./check-fixture.mjs', import.meta.url));
  for (const [name, expected] of [
    ['frontier-prime-checks.v1.json', 'PASS fixture:frontier-mersenne-prime-checks-v1 mersenne-prime-check-fixture\n'],
    ['m89-x2-plus-1-rabin.v1.json', 'PASS fixture:m89-x2-plus-1-rabin-v1 rabin-irreducibility-fixture\n']
  ]) {
    const result = spawnSync(process.execPath, [checkerPath, fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url))], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, expected);
    assert.equal(result.stderr, '');
  }
});

test('generic Fp polynomial operations retain exact division, gcd, Bezout, and residues', () => {
  const p = 7n;
  const a = [1n, 2n, 3n];
  const b = [4n, 5n];
  const product = polyMul(a, b, p);
  const [quotient, remainder] = polyDivMod(product, a, p);
  assert.equal(polyEqual(quotient, b, p), true);
  assert.equal(polyEqual(remainder, [0n], p), true);
  assert.equal(polyEqual(polyAdd(a, polySub(b, b, p), p), a, p), true);
  const gcd = polyGcd([1n, 0n, 1n], [1n, 1n], p);
  assert.equal(polyEqual(gcd, [1n], p), true);
  const { gcd: bezoutGcd, u, v } = polyXgcd([1n, 0n, 1n], [1n, 1n], p);
  assert.equal(polyEqual(bezoutGcd, [1n], p), true);
  assert.equal(polyEqual(polyAdd(polyMul(u, [1n, 0n, 1n], p), polyMul(v, [1n, 1n], p), p), [1n], p), true);
  assert.equal(polyEqual(polyPowMod([0n, 1n], 6n, [1n, 0n, 1n], p), [6n], p), true);
});

test('replay fails closed on coefficient, residue, gcd, Bezout, modulus, and Lucas-Lehmer mutations', () => {
  const coefficient = copy(m89);
  coefficient.certificate.polynomial[0] = '2';
  assert.equal(replayM89X2PlusOneFixture(coefficient), false);

  const residue = copy(m89);
  residue.certificate.hPowers[1].coefficients[1] = '1';
  assert.equal(replayM89X2PlusOneFixture(residue), false);

  const gcd = copy(m89);
  gcd.certificate.witnesses[0].gcd[0] = '2';
  assert.equal(replayM89X2PlusOneFixture(gcd), false);

  const bezout = copy(m89);
  bezout.certificate.witnesses[0].bezoutV[1] = '1';
  assert.equal(replayM89X2PlusOneFixture(bezout), false);

  const modulus = copy(m89);
  modulus.certificate.modulus = '618970019642690137449562110';
  assert.equal(replayM89X2PlusOneFixture(modulus), false);

  const ll = copy(frontier);
  ll.checks.find((check) => check.mersenneExponent === '31').lucasLehmer.residue = '1';
  assert.equal(replayFrontierPrimeChecksFixture(ll), false);

  const encoding = copy(m89);
  encoding.certificate.coefficientEncoding = 'descending-cd-to-c0';
  assert.equal(replayM89X2PlusOneFixture(encoding), false);
});

test('canonical decimal and trailing-coefficient aliases fail closed', () => {
  const leadingZero = copy(m89);
  leadingZero.certificate.polynomial[0] = '01';
  assert.equal(replayM89X2PlusOneFixture(leadingZero), false);

  const trailingZero = copy(m89);
  trailingZero.certificate.hPowers[0].coefficients.push('0');
  assert.equal(replayM89X2PlusOneFixture(trailingZero), false);
});

test('fixture envelope and strict schema reject mutation', () => {
  assert.equal(validateSchema(frontier), true, JSON.stringify(validateSchema.errors));
  assert.equal(validateSchema(m89), true, JSON.stringify(validateSchema.errors));

  const envelopeMutation = copy(frontier);
  envelopeMutation.status = 'qualified';
  assert.equal(validateSchema(envelopeMutation), false);
  assert.equal(replayFrontierPrimeChecksFixture(envelopeMutation), false);

  const schemaMutation = copy(m89);
  schemaMutation.unexpected = 'field-selection';
  assert.equal(validateSchema(schemaMutation), false);
  assert.equal(replayM89X2PlusOneFixture(schemaMutation), false);
});
