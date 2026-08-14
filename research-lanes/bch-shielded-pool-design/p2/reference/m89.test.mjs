import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  M89_ELEMENT_BYTES,
  M89_MODULUS,
  M89Error,
  add,
  assertFullConsumption,
  bytesToHex,
  decodeFpHex,
  decodeM89,
  decodeM89Hex,
  decodeM89Sequence,
  encodeM89,
  encodeM89Hex,
  fpAdd,
  fpMul,
  fpNeg,
  fpSub,
  hexToBytesStrict,
  inverse,
  inverseWithHint,
  mul,
  neg,
  readM89,
  square,
  sub,
  verifyInverseHint,
} from './m89.mjs';

const katPath = new URL('./m89-kat.json', import.meta.url);
const kat = JSON.parse(readFileSync(katPath, 'utf8'));
const tuple = (values) => values.map((value) => BigInt(value));
const throws = (fn, pattern) => assert.throws(fn, (error) => error instanceof M89Error && pattern.test(error.message));

test('M89 KAT elements, exact codec, and independently recorded relations agree', () => {
  assert.equal(kat.modulus, M89_MODULUS.toString());
  assert.equal(kat.elementBytes, M89_ELEMENT_BYTES);
  for (const item of kat.elements) {
    assert.equal(encodeM89Hex(tuple(item.value)), item.wireHex, item.id);
    assert.deepEqual(decodeM89Hex(item.wireHex), tuple(item.value), item.id);
  }
  for (const item of kat.operations) {
    const left = tuple(item.left);
    const expected = tuple(item.expected);
    const actual = item.op === 'add' ? add(left, tuple(item.right))
      : item.op === 'sub' ? sub(left, tuple(item.right))
        : item.op === 'neg' ? neg(left)
          : item.op === 'mul' ? mul(left, tuple(item.right))
            : item.op === 'square' ? square(left) : inverse(left);
    assert.deepEqual(actual, expected, item.id);
  }
  assert.equal(mul([0n, 1n], [0n, 1n])[0], M89_MODULUS - 1n);
  assert.deepEqual(square([1n, 1n]), [0n, 2n]);
  assert.deepEqual(mul([1n, 1n], inverse([1n, 1n])), [1n, 0n]);
  assert.match(createHash('sha256').update(readFileSync(katPath)).digest('hex'), /^[0-9a-f]{64}$/u);
});

test('strict codec rejects high bits, range aliases, wrong lengths, and unconsumed bytes', () => {
  for (const item of kat.rejections) throws(() => decodeM89Hex(item.wireHex), /high bit|>= p|exactly 48/);
  throws(() => decodeFpHex('000000000000000000000080'), /high bit/);
  throws(() => decodeM89(new Uint8Array(23)), /exactly 24/);
  throws(() => decodeM89(new Uint8Array(25)), /exactly 24/);
  throws(() => decodeM89Hex('01'.repeat(25)), /exactly 48/);
  throws(() => decodeM89Hex(`AA${'00'.repeat(23)}`), /lowercase/);
  const wire = encodeM89([1n, 0n]);
  assert.deepEqual(readM89(wire, 0), { value: [1n, 0n], nextOffset: 24 });
  assert.deepEqual(decodeM89Sequence(wire), [[1n, 0n]]);
  assertFullConsumption(24, 24, 'fixture');
  throws(() => assertFullConsumption(23, 24, 'fixture'), /trailing/);
  throws(() => decodeM89Sequence(new Uint8Array([...wire, 0])), /ends before/);
  assert.equal(bytesToHex(encodeM89([0n, 0n])), '00'.repeat(24));
  assert.deepEqual(hexToBytesStrict('0100'), new Uint8Array([1, 0]));
});

test('Fp and Fp2 arithmetic, inverse hints, and type boundaries are strict', () => {
  assert.equal(fpAdd(M89_MODULUS - 1n, 1n), 0n);
  assert.equal(fpSub(0n, 1n), M89_MODULUS - 1n);
  assert.equal(fpNeg(0n), 0n);
  assert.equal(fpMul(M89_MODULUS - 1n, M89_MODULUS - 1n), 1n);
  const a = [123456789n, 987654321n];
  const h = inverse(a);
  assert.equal(verifyInverseHint(a, h), true);
  assert.deepEqual(inverseWithHint(a, h), h);
  assert.equal(verifyInverseHint(a, [h[0], (h[1] + 1n) % M89_MODULUS]), false);
  throws(() => verifyInverseHint([0n, 0n], [1n, 0n]), /zero/);
  throws(() => add([M89_MODULUS, 0n], [0n, 0n]), /must be in/);
  throws(() => mul([1, 0n], [0n, 1n]), /BigInt/);
  throws(() => encodeM89([0n]), /two-coefficient/);
});
