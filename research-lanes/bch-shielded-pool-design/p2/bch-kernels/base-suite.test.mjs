import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeM31Hex } from '../reference/m31.mjs';
import {
  M31_FULL_BASE_CASES,
  M31_FULL_BASE_CORPUS_SHA256,
  encodeFullBaseTransactionFixture,
  evaluateFullBaseCase,
  rawInputHexForFullBaseCase,
} from './base-suite.mjs';

const EXPECTED_COUNTS = Object.freeze({
  add: 1_144,
  inverseHint: 108,
  mul: 1_175,
  neg: 76,
  square: 76,
  sub: 1_145,
});

test('generated neutral-M31 suite has a stable, complete inventory', () => {
  assert.equal(M31_FULL_BASE_CORPUS_SHA256, 'fa76c62cfd3fb2ea4898b0b42fda5f21edcd41cb023c84925237eb903fe0dcd9');
  assert.equal(M31_FULL_BASE_CASES.length, 3_724);
  assert.equal(new Set(M31_FULL_BASE_CASES.map(({ id }) => id)).size, M31_FULL_BASE_CASES.length);
  assert.equal(M31_FULL_BASE_CASES.filter(({ accepted }) => !accepted).length, 106);
  const actual = {};
  for (const entry of M31_FULL_BASE_CASES) actual[entry.operation] = (actual[entry.operation] ?? 0) + 1;
  assert.deepEqual(actual, EXPECTED_COUNTS);
  for (const requiredPrefix of ['corpus-kat-', 'random-', 'low-', 'boundary-', 'malformed-', 'decoder-sign-byte-mutation-']) {
    assert.ok(M31_FULL_BASE_CASES.some(({ id }) => id.startsWith(requiredPrefix)), requiredPrefix);
  }
});

test('every accepted suite wire differentially decodes in the native reference', () => {
  for (const entry of M31_FULL_BASE_CASES.filter(({ accepted }) => accepted)) {
    for (const [name, wire] of Object.entries(rawInputHexForFullBaseCase(entry))) {
      assert.doesNotThrow(() => decodeM31Hex(wire), `${entry.id}:${name}:${wire}`);
    }
  }
});

test('all 3724 relations execute with their expected standard Libauth verdict', () => {
  for (const entry of M31_FULL_BASE_CASES) {
    const result = evaluateFullBaseCase(entry);
    assert.equal(result.standard, true, entry.id);
    assert.equal(result.accepted, entry.accepted, `${entry.id}: ${result.error}`);
    assert.equal(result.metrics.limits.operationCostHeadroom >= 0, true, entry.id);
    assert.equal(result.metrics.limits.stackItemsHeadroom >= 0, true, entry.id);
    assert.equal(result.metrics.limits.elementBytesHeadroom >= 0, true, entry.id);
  }
});

test('full-suite transaction fixtures preserve malformed raw operand bytes', () => {
  for (const entry of M31_FULL_BASE_CASES.filter(({ id }) => id.startsWith('malformed-'))) {
    const wires = encodeFullBaseTransactionFixture(entry);
    for (const wire of Object.values(rawInputHexForFullBaseCase(entry))) {
      assert.ok(wires.transactionHex.includes(wire), `${entry.id}:${wire}`);
    }
  }
});
