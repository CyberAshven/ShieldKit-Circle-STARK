import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  DirectExtensionError,
  createDirectExtension,
} from './direct-extension.mjs';
import {
  M89_LIMB_BYTES,
  M89_MODULUS,
  add as m89Add,
  decodeM89Hex,
  encodeM89Hex,
  inverse as m89Inverse,
  mul as m89Mul,
  neg as m89Neg,
  square as m89Square,
  sub as m89Sub,
} from './m89.mjs';

const kat = JSON.parse(readFileSync(new URL('./m89-kat.json', import.meta.url), 'utf8'));
const tuple = (values) => values.map((value) => BigInt(value));
const expectThrow = (fn, pattern) => assert.throws(fn, (error) => error instanceof DirectExtensionError && pattern.test(error.message));

const m89 = createDirectExtension({
  modulus: M89_MODULUS,
  degree: 2,
  limbBytes: M89_LIMB_BYTES,
  definingPolynomial: [1n, 0n, 1n],
});

test('generic direct polynomial context is config-bound and exactly reproduces frozen M89 KATs', () => {
  assert.equal(m89.elementBytes, 24);
  assert.equal(m89.config.unusedHighBits, 7);
  assert.equal(m89.config.unusedHighBitMask, 0xfe);
  for (const item of kat.elements) {
    const value = tuple(item.value);
    assert.equal(m89.encodeHex(value), item.wireHex, item.id);
    assert.deepEqual(m89.decodeHex(item.wireHex), value, item.id);
  }
  for (const item of kat.operations) {
    const left = tuple(item.left);
    const expected = tuple(item.expected);
    const actual = item.op === 'add' ? m89.add(left, tuple(item.right))
      : item.op === 'sub' ? m89.sub(left, tuple(item.right))
        : item.op === 'neg' ? m89.neg(left)
            : item.op === 'mul' ? m89.mul(left, tuple(item.right))
            : item.op === 'square' ? m89.square(left)
              : m89.inverseForCertifiedField(left);
    assert.deepEqual(actual, expected, item.id);
  }
  assert.deepEqual(m89.add([M89_MODULUS - 1n, 0n], [1n, 0n]), m89Add([M89_MODULUS - 1n, 0n], [1n, 0n]));
  assert.deepEqual(m89.sub([0n, 0n], [1n, 0n]), m89Sub([0n, 0n], [1n, 0n]));
  assert.deepEqual(m89.neg([0n, 1n]), m89Neg([0n, 1n]));
  assert.deepEqual(m89.mul([1n, 1n], [0n, 1n]), m89Mul([1n, 1n], [0n, 1n]));
  assert.deepEqual(m89.square([1n, 1n]), m89Square([1n, 1n]));
  assert.deepEqual(m89.inverseWithHint([1n, 1n], tuple(kat.elements.find((item) => item.id === 'inverse-one-plus-u').value)), m89Inverse([1n, 1n]));
  assert.deepEqual(m89.inverseForCertifiedField([1n, 1n]), m89Inverse([1n, 1n]));
  assert.equal(m89.encodeHex(m89.decodeHex(encodeM89Hex([1n, 0n]))), encodeM89Hex([1n, 0n]));
  assert.deepEqual(m89.decodeHex(encodeM89Hex([0n, 1n])), decodeM89Hex(encodeM89Hex([0n, 1n])));
});

test('codec is fixed-width LE, exact-degree, full-consumption, high-bit, and range strict', () => {
  const wire = m89.encode([1n, 0n]);
  assert.deepEqual(m89.read(wire, 0), { value: [1n, 0n], nextOffset: 24 });
  assert.deepEqual(m89.decodeSequence(wire), [[1n, 0n]]);
  assert.deepEqual(m89.decodeSequence(new Uint8Array([...wire, ...wire])), [[1n, 0n], [1n, 0n]]);
  expectThrow(() => m89.decode(new Uint8Array(23)), /exactly 24/);
  expectThrow(() => m89.decode(new Uint8Array(25)), /exactly 24/);
  expectThrow(() => m89.decode(new Uint8Array([...wire, 0])), /exactly 24/);
  expectThrow(() => m89.decodeHex('000000000000000000000080' + '00'.repeat(12)), /unused high bit/);
  expectThrow(() => m89.decodeHex('ffffffffffffffffffffff01' + '00'.repeat(12)), />= p/);
  expectThrow(() => m89.decodeSequence(new Uint8Array([...wire, 0])), /ends before/);
  expectThrow(() => m89.read(wire, 1), /ends before/);
  expectThrow(() => m89.encode([1n]), /exactly 2 coefficients/);
  expectThrow(() => m89.encode([1, 0n]), /BigInt/);
  expectThrow(() => m89.encode([M89_MODULUS, 0n]), /must be in/);
  expectThrow(() => m89.decodeCoefficient(new Uint8Array(11)), /exactly 12/);
});

test('arbitrary monic direct polynomial uses deterministic naive reduction', () => {
  const cubic = createDirectExtension({ modulus: 17n, degree: 3, limbBytes: 1, definingPolynomial: [2n, 3n, 4n, 1n] });
  // x^3 = -(2 + 3x + 4x^2), and x^4 is reduced descending from x^3*x.
  assert.deepEqual(cubic.mul([0n, 1n, 0n], [0n, 0n, 1n]), [15n, 14n, 13n]);
  assert.deepEqual(cubic.square([0n, 0n, 1n]), [8n, 10n, 13n]);
  assert.deepEqual(cubic.add([16n, 0n, 0n], [1n, 0n, 0n]), [0n, 0n, 0n]);
  assert.deepEqual(cubic.sub([0n, 0n, 0n], [1n, 0n, 0n]), [16n, 0n, 0n]);
  assert.deepEqual(cubic.neg([0n, 1n, 0n]), [0n, 16n, 0n]);
  assert.equal(cubic.equal([1n, 2n, 3n], [1n, 2n, 3n]), true);
  assert.equal(cubic.equal([1n, 2n, 3n], [1n, 2n, 4n]), false);
});

test('inverse hints verify through generic multiplication and preserve type boundaries', () => {
  const value = [123456789n, 987654321n];
  const hint = m89Inverse(value);
  assert.equal(m89.verifyInverseHint(value, hint), true);
  assert.deepEqual(m89.inverseWithHint(value, hint), hint);
  assert.equal(m89.verifyInverseHint(value, [hint[0], (hint[1] + 1n) % M89_MODULUS]), false);
  expectThrow(() => m89.verifyInverseHint([0n, 0n], [1n, 0n]), /zero/);
  expectThrow(() => m89.add([1n, 0n], 1n), /exactly 2 coefficients/);
  expectThrow(() => m89.add([1n, 0n], [1n]), /exactly 2 coefficients/);
  expectThrow(() => m89.add([1n, 0n], [1, 0n]), /BigInt/);
});

test('nonnegative BigInt exponentiation and certified-field inverse are strict', () => {
  assert.deepEqual(m89.pow([1n, 1n], 0n), [1n, 0n]);
  assert.deepEqual(m89.pow([0n, 1n], 2n), [M89_MODULUS - 1n, 0n]);
  assert.deepEqual(m89.pow([1n, 1n], 2n), [0n, 2n]);
  assert.deepEqual(m89.pow([1n, 1n], 3n), m89.mul([0n, 2n], [1n, 1n]));
  assert.deepEqual(m89.inverseForCertifiedField([1n, 1n]), m89Inverse([1n, 1n]));
  expectThrow(() => m89.pow([1n, 0n], 1), /exponent.*BigInt/);
  expectThrow(() => m89.pow([1n, 0n], -1n), /nonnegative BigInt/);
  expectThrow(() => m89.inverseForCertifiedField([0n, 0n]), /zero/);
  expectThrow(() => m89.inverseForCertifiedField([1n, 0n, 0n]), /exactly 2 coefficients/);

  const reducible = createDirectExtension({
    modulus: 17n,
    degree: 2,
    limbBytes: 1,
    definingPolynomial: [16n, 0n, 1n], // x^2 - 1
  });
  expectThrow(
    () => reducible.inverseForCertifiedField([16n, 1n]), // x - 1 is a nonzero zero divisor
    /does not verify/,
  );
});

test('configuration rejects noncanonical host values and non-monic/incomplete polynomials', () => {
  expectThrow(() => createDirectExtension({ modulus: 17, degree: 2, limbBytes: 1, definingPolynomial: [1n, 0n, 1n] }), /modulus.*BigInt/);
  expectThrow(() => createDirectExtension({ modulus: 17n, degree: 2, limbBytes: 1, definingPolynomial: [1n, 0, 1n] }), /definingPolynomial\[1\].*BigInt/);
  expectThrow(() => createDirectExtension({ modulus: 17n, degree: 2, limbBytes: 1, definingPolynomial: [1n, 0n] }), /exactly degree\+1/);
  expectThrow(() => createDirectExtension({ modulus: 17n, degree: 2, limbBytes: 1, definingPolynomial: [1n, 0n, 2n] }), /monic/);
  expectThrow(() => createDirectExtension({ modulus: 17n, degree: 2, limbBytes: 1, definingPolynomial: [1n, 0n, 17n] }), /must be in/);
  expectThrow(() => createDirectExtension({ modulus: 17n, degree: 2, limbBytes: 0, definingPolynomial: [1n, 0n, 1n] }), /positive safe integer/);
  expectThrow(() => createDirectExtension({ modulus: 257n, degree: 2, limbBytes: 1, definingPolynomial: [1n, 0n, 1n] }), /fixed width/);
  expectThrow(() => createDirectExtension({ modulus: 17n, degree: 2, limbBytes: 2, definingPolynomial: [1n, 0n, 1n] }), /fixed width/);
  expectThrow(() => createDirectExtension({ modulus: 17n, degree: 2, limbBytes: 1, p: 19n, definingPolynomial: [1n, 0n, 1n] }), /disagree/);
});
