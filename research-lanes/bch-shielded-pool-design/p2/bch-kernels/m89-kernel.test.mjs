import assert from 'node:assert/strict';
import test from 'node:test';

import {
  M89_PRIME,
  buildM89EMacLockingBytecode,
  buildM89EMacUnlockingBytecode,
  buildM89ESquareMacLockingBytecode,
  buildM89ESquareMacUnlockingBytecode,
  buildM89EInverseCheckLockingBytecode,
  buildM89EInverseCheckUnlockingBytecode,
  decodeM89,
  decodeM89Element,
  encodeM89,
  encodeM89Element,
  evaluateM89ScriptFixture,
} from './m89-kernel.mjs';

const mod = (value) => ((value % M89_PRIME) + M89_PRIME) % M89_PRIME;
const mul = (left, right) => ({
  c0: mod(left.c0 * right.c0 - left.c1 * right.c1),
  c1: mod(left.c0 * right.c1 + left.c1 * right.c0),
});
const add = (left, right) => ({ c0: mod(left.c0 + right.c0), c1: mod(left.c1 + right.c1) });

const A = Object.freeze({ c0: 3n, c1: 5n });
const B = Object.freeze({ c0: 7n, c1: 11n });
const C = Object.freeze({ c0: 13n, c1: 17n });
const D = add(mul(A, B), C);
const S = add(mul(A, A), C);

const metricsShape = (result) => {
  for (const key of [
    'evaluatedInstructionCount', 'signatureCheckCount', 'hashDigestIterations',
    'arithmeticCost', 'stackPushedBytes', 'operationCost',
  ]) assert.equal(typeof result.metrics[key], 'number', key);
  for (const value of Object.values(result.metrics.stackMaximums)) assert.equal(typeof value, 'number');
  for (const value of Object.values(result.metrics.limits)) assert.equal(typeof value, 'number');
};

test('M89 fixed-12-byte unsigned LE codec and exact 24-byte element codec', () => {
  for (const value of [0n, 1n, 0x7fn, 0x80n, (1n << 88n) - 1n, M89_PRIME - 1n]) {
    assert.equal(decodeM89(encodeM89(value)), value);
  }
  assert.equal(decodeM89Element(encodeM89Element({ c0: M89_PRIME - 1n, c1: 0n })).c0, M89_PRIME - 1n);
  assert.throws(() => decodeM89(Uint8Array.of(1, 2, 3)), /exactly 12 bytes/);
  assert.throws(() => decodeM89(Uint8Array.from([...new Array(11).fill(0), 0x02])), /unused high bits/);
  assert.throws(() => decodeM89(Uint8Array.from([...new Array(11).fill(0xff), 0x01])), /out of range/);
  assert.throws(() => decodeM89Element(new Uint8Array(23)), /exactly 24 bytes/);
  assert.throws(() => encodeM89(M89_PRIME), /0 <= x < p/);
});

test('standard VM accepts canonical E-MAC, E-SQUARE-MAC, and inverse check', () => {
  const cases = [
    {
      name: 'mac',
      lockingBytecode: buildM89EMacLockingBytecode(),
      unlockingBytecode: buildM89EMacUnlockingBytecode({ first: A, second: B, addend: C, result: D }),
      length: 568,
      pushes: 4,
      lockingDigestSha256: '93be03468372ca3d75d1bc929944d2990f85ab07867b7d88d785f381f9a10dc9',
      unlockingDigestSha256: '3c6847c84bec1c50567fd6c34e2bb843e16623e92c1a79876d4d6f2f340f0183',
      metrics: [356, 0, 0, 425, 1187, 37212],
    },
    {
      name: 'square',
      lockingBytecode: buildM89ESquareMacLockingBytecode(),
      unlockingBytecode: buildM89ESquareMacUnlockingBytecode({ first: A, addend: C, result: S }),
      length: 419,
      pushes: 3,
      lockingDigestSha256: '0d8dce97461894c113fc80a8a1477a82a00542c4e281185721cba848a7ba5e8b',
      unlockingDigestSha256: '4af703876378a4189eb6ab6163de178645834a6168ea15a9d430da93de0deb97',
      metrics: [269, 0, 0, 242, 899, 28041],
    },
    {
      name: 'inverse',
      lockingBytecode: buildM89EInverseCheckLockingBytecode(),
      unlockingBytecode: buildM89EInverseCheckUnlockingBytecode({
        value: { c0: 1n, c1: 0n }, inverseHint: { c0: 1n, c1: 0n },
      }),
      length: 338,
      pushes: 2,
      lockingDigestSha256: 'b2781f4c5e2091ad6797ef85cce530bc320695bcb11fc6d83c9f9234b3c3aada',
      unlockingDigestSha256: 'dd59b6665b601d92869fa83152805a9336bf816c7e52df18360354c5d7619111',
      metrics: [202, 0, 0, 174, 578, 20952],
    },
  ];
  for (const entry of cases) {
    const result = evaluateM89ScriptFixture(entry);
    assert.equal(result.accepted, true, `${entry.name}: ${result.error}`);
    assert.equal(result.standard, true);
    assert.equal(result.lockingHex.length / 2, entry.length);
    assert.equal(result.unlockingHex.length / 2, entry.pushes * 25);
    assert.equal(result.lockingDigestSha256, entry.lockingDigestSha256);
    assert.equal(result.unlockingDigestSha256, entry.unlockingDigestSha256);
    assert.deepEqual([
      result.metrics.evaluatedInstructionCount, result.metrics.signatureCheckCount,
      result.metrics.hashDigestIterations, result.metrics.arithmeticCost,
      result.metrics.stackPushedBytes, result.metrics.operationCost,
    ], entry.metrics);
    metricsShape(result);
    // Every operand is one exact 24-byte direct push; no limb is pushed separately.
    assert.match(result.unlockingHex, /^(18[0-9a-f]{48})+$/);
  }
});

test('full-width p-1 boundary runs through native schoolbook arithmetic', () => {
  const q = { c0: M89_PRIME - 1n, c1: M89_PRIME - 1n };
  const mac = evaluateM89ScriptFixture({
    lockingBytecode: buildM89EMacLockingBytecode(),
    unlockingBytecode: buildM89EMacUnlockingBytecode({ first: q, second: q, addend: q, result: add(mul(q, q), q) }),
  });
  assert.equal(mac.accepted, true, mac.error);
  const square = evaluateM89ScriptFixture({
    lockingBytecode: buildM89ESquareMacLockingBytecode(),
    unlockingBytecode: buildM89ESquareMacUnlockingBytecode({ first: q, addend: q, result: add(mul(q, q), q) }),
  });
  assert.equal(square.accepted, true, square.error);

  // Explicitly exercise a0*b0 < a1*b1: raw SUB is below zero before
  // per-product reduction and the second p-normalization.
  const negativeLeft = { c0: 0n, c1: M89_PRIME - 1n };
  const imaginaryUnit = { c0: 0n, c1: 1n };
  const negativeDiffMac = evaluateM89ScriptFixture({
    lockingBytecode: buildM89EMacLockingBytecode(),
    unlockingBytecode: buildM89EMacUnlockingBytecode({
      first: negativeLeft, second: imaginaryUnit, addend: { c0: 0n, c1: 0n },
      result: { c0: 1n, c1: 0n },
    }),
  });
  assert.equal(negativeDiffMac.accepted, true, negativeDiffMac.error);
  const negativeDiffSquare = evaluateM89ScriptFixture({
    lockingBytecode: buildM89ESquareMacLockingBytecode(),
    unlockingBytecode: buildM89ESquareMacUnlockingBytecode({
      first: negativeLeft, addend: { c0: 0n, c1: 0n },
      result: { c0: M89_PRIME - 1n, c1: 0n },
    }),
  });
  assert.equal(negativeDiffSquare.accepted, true, negativeDiffSquare.error);
});

test('single-invariant raw failures are rejected by the Script parser', () => {
  const validMac = () => ({
    lockingBytecode: buildM89EMacLockingBytecode(),
    unlockingBytecode: buildM89EMacUnlockingBytecode({ first: A, second: B, addend: C, result: D }),
  });
  const high = encodeM89Element(A);
  high[11] |= 0x02;
  const highResult = evaluateM89ScriptFixture({
    lockingBytecode: buildM89EMacLockingBytecode(),
    unlockingBytecode: buildM89EMacUnlockingBytecode({ rawFirst: high, second: B, addend: C, result: D }),
  });
  assert.equal(highResult.accepted, false);

  const atP = Uint8Array.from([...new Array(11).fill(0xff), 0x01, ...encodeM89(0n)]);
  const rangeResult = evaluateM89ScriptFixture({
    lockingBytecode: buildM89EMacLockingBytecode(),
    unlockingBytecode: buildM89EMacUnlockingBytecode({ rawFirst: atP, second: B, addend: C, result: D }),
  });
  assert.equal(rangeResult.accepted, false);

  for (const length of [0, 12, 23, 25]) {
    const malformed = evaluateM89ScriptFixture({
      lockingBytecode: buildM89EMacLockingBytecode(),
      unlockingBytecode: buildM89EMacUnlockingBytecode({
        rawFirst: new Uint8Array(length), second: B, addend: C, result: D,
      }),
    });
    assert.equal(malformed.accepted, false, `raw length ${length}`);
  }

  const wrongResult = validMac();
  const resultRaw = encodeM89Element(D);
  resultRaw[0] ^= 1;
  wrongResult.unlockingBytecode = buildM89EMacUnlockingBytecode({
    first: A, second: B, addend: C, rawResult: resultRaw,
  });
  assert.equal(evaluateM89ScriptFixture(wrongResult).accepted, false);
});

test('inverse check rejects zero value and an incorrect hint', () => {
  const lockingBytecode = buildM89EInverseCheckLockingBytecode();
  const zero = evaluateM89ScriptFixture({
    lockingBytecode,
    unlockingBytecode: buildM89EInverseCheckUnlockingBytecode({
      value: { c0: 0n, c1: 0n }, inverseHint: { c0: 0n, c1: 0n },
    }),
  });
  assert.equal(zero.accepted, false);
  const badHint = evaluateM89ScriptFixture({
    lockingBytecode,
    unlockingBytecode: buildM89EInverseCheckUnlockingBytecode({
      value: { c0: 1n, c1: 0n }, inverseHint: { c0: 2n, c1: 0n },
    }),
  });
  assert.equal(badHint.accepted, false);
  const iInverse = evaluateM89ScriptFixture({
    lockingBytecode,
    unlockingBytecode: buildM89EInverseCheckUnlockingBytecode({
      value: { c0: 0n, c1: 1n }, inverseHint: { c0: 0n, c1: M89_PRIME - 1n },
    }),
  });
  assert.equal(iInverse.accepted, true, iInverse.error);
});
