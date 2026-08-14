import assert from 'node:assert/strict';
import test from 'node:test';

import {
  M31_KERNEL_CASES,
  M31_PRIME,
  buildM31MulLockingBytecode,
  decodeM31,
  encodeM31,
  evaluateM31Mul,
  materializeM31Case,
} from './m31-kernel.mjs';

test('M31 fixed-4-byte native codec has one unsigned LE representation below p', () => {
  for (const value of [0n, 1n, 255n, 65_536n, M31_PRIME - 1n]) {
    assert.equal(decodeM31(encodeM31(value)), value);
  }
  assert.throws(() => decodeM31(Uint8Array.of(0x01, 0x00, 0x00)), /exactly four/);
  assert.throws(() => decodeM31(Uint8Array.of(0x01, 0x00, 0x00, 0x00, 0x00)), /exactly four/);
  assert.throws(() => decodeM31(Uint8Array.of(0xff, 0xff, 0xff, 0x7f)), /out of range/);
  assert.throws(() => decodeM31(Uint8Array.of(0x00, 0x00, 0x00, 0x80)), /out of range/);
  assert.throws(() => decodeM31(Uint8Array.of(0x01, 0x00, 0x00, 0x80)), /out of range/);
  assert.throws(() => decodeM31(Uint8Array.of(0xff, 0xff, 0xff, 0xff)), /out of range/);
  assert.throws(() => encodeM31(M31_PRIME), /0 <= x < p/);
  for (const [value, wire] of [
    [0x7fn, '7f000000'], [0x80n, '80000000'], [0xffn, 'ff000000'],
    [0x100n, '00010000'], [0x7fffn, 'ff7f0000'], [0x8000n, '00800000'],
    [0x7f_ffffn, 'ffff7f00'], [0x80_0000n, '00008000'],
    [0xff_ffffn, 'ffffff00'], [0x100_0000n, '00000001'],
    [1n << 30n, '00000040'], [M31_PRIME - 2n, 'fdffff7f'],
    [M31_PRIME - 1n, 'feffff7f'],
  ]) {
    assert.equal(Buffer.from(encodeM31(value)).toString('hex'), wire);
  }
});

test('real Libauth BCH-2026 VM accepts only the M31 multiplication relation', () => {
  const locking = buildM31MulLockingBytecode();
  assert.equal(locking.length, 78);
  for (const entry of M31_KERNEL_CASES) {
    const fixture = materializeM31Case(entry);
    const result = evaluateM31Mul(fixture);
    assert.equal(result.accepted, entry.accepted, `${entry.id}: ${result.error}`);
    assert.equal(result.standard, true, entry.id);
    assert.equal(result.lockingHex.length / 2, 78);
    assert.equal(result.unlockingHex.length / 2, fixture.unlockingBytecode.length);
    for (const key of [
      'evaluatedInstructionCount', 'signatureCheckCount', 'hashDigestIterations',
      'arithmeticCost', 'stackPushedBytes', 'operationCost',
    ]) assert.equal(typeof result.metrics[key], 'number', `${entry.id}:${key}`);
    for (const value of Object.values(result.metrics.stackMaximums)) assert.equal(typeof value, 'number', entry.id);
    for (const value of Object.values(result.metrics.limits)) assert.equal(typeof value, 'number', entry.id);
  }
});

test('full M31 product boundary is evaluated natively before modular reduction', () => {
  const a = M31_PRIME - 1n;
  const fullProduct = a * a;
  assert.ok(fullProduct > (1n << 61n));
  assert.ok(fullProduct < (1n << 63n));
  const boundary = materializeM31Case(M31_KERNEL_CASES.find(({ id }) => id === 'm31-product-boundary'));
  const result = evaluateM31Mul(boundary);
  assert.equal(result.accepted, true, result.error);
  assert.equal(result.metrics.arithmeticCost, 57);
  assert.deepEqual(result.metrics.stackMaximums, {
    primaryItems: 6,
    alternateItems: 1,
    definedFunctions: 0,
    controlDepth: 0,
    functionCallDepth: 0,
    cumulativeMemoryItems: 6,
    elementBytes: 8,
  });
  assert.equal(result.metrics.limits.maximumOperationCost, 44_800);
  assert.equal(result.metrics.limits.operationCostHeadroom, 38_129);
  assert.equal(result.metrics.limits.maximumHashDigestIterations, 28);
});

test('mutating the synthesized unsigned sign byte cannot preserve acceptance', () => {
  const entry = M31_KERNEL_CASES.find(({ id }) => id === 'm31-small-product');
  const fixture = materializeM31Case(entry);
  const mutated = fixture.lockingBytecode.slice();
  const pattern = [0x76, 0x00, 0x51, 0x80, 0x7e];
  const offset = mutated.findIndex((_, index) => pattern.every((byte, inner) => mutated[index + inner] === byte));
  assert.notEqual(offset, -1);
  mutated[offset + 1] = 0x51; // OP_0 -> OP_1: raw || 01, no longer the unsigned-u32 decoder.
  const result = evaluateM31Mul({ lockingBytecode: mutated, unlockingBytecode: fixture.unlockingBytecode });
  assert.equal(result.accepted, false);
});
