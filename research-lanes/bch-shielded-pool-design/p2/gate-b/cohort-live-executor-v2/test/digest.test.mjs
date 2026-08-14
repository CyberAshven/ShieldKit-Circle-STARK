import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { canonicalJson, utf8Encode } from '../src/canonical.mjs';
import { sha256Hex } from '../src/sha256.mjs';
import { authorityDagDigest, modelRootDigest, stateDigest, transitionGrammarDigest } from '../src/model.mjs';
import { rawFileDigest } from '../validate-static.mjs';

const kat = JSON.parse(await readFile(new URL('./digest.kat.json', import.meta.url), 'utf8'));

test('local SHA-256 passes standard, Unicode, and LF vectors', () => {
  for (const vector of kat.sha256) assert.equal(sha256Hex(utf8Encode(vector.input)), vector.value);
});

test('framed digest includes one final LF and matches independent node crypto', () => {
  for (const vector of kat.framed) {
    const frame = `${vector.domain}\u0000${canonicalJson(vector.value)}\n`;
    const independent = createHash('sha256').update(frame, 'utf8').digest('hex');
    assert.equal(sha256Hex(utf8Encode(frame)), vector.valueDigest);
    assert.equal(independent, vector.valueDigest);
    assert.equal(stateDigest(vector.value), vector.valueDigest);
  }
});

test('manifest file digests bind raw bytes without canonical metadata or appended LF', () => {
  const domain = 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/file';
  for (const vector of kat.rawFile) {
    const bytes = Buffer.from(vector.bytes);
    const frame = Buffer.concat([Buffer.from(`${domain}\u0000`, 'utf8'), bytes]);
    const independent = createHash('sha256').update(frame).digest('hex');
    assert.equal(sha256Hex(frame), vector.value);
    assert.equal(independent, vector.value);
    assert.equal(rawFileDigest(bytes), vector.value);
    assert.notEqual(sha256Hex(utf8Encode(`${domain}\u0000${String.fromCharCode(...vector.bytes)}\n`)), vector.value);
  }
});

test('canonical JSON sorts keys while preserving array order', () => {
  assert.equal(canonicalJson({ z: [2, 1], a: { d: true, c: null } }), '{"a":{"c":null,"d":true},"z":[2,1]}');
  assert.equal(canonicalJson({ a: 'A\nB', euro: '€' }), '{"a":"A\\nB","euro":"€"}');
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
});

test('digest domains separate equal semantic payloads', () => {
  const state = { schema: 'shieldkit-labs/p2/gate-b/cohort-live-executor/v2/state/v2', identifier: 'cohort-live-executor-v2', variant: 'initial', facts: ['Q'], phase: 'open' };
  const payload = canonicalJson({ same: true });
  assert.match(authorityDagDigest(), /^[0-9a-f]{64}$/);
  assert.match(transitionGrammarDigest(), /^[0-9a-f]{64}$/);
  assert.match(modelRootDigest(), /^[0-9a-f]{64}$/);
  assert.match(stateDigest(state), /^[0-9a-f]{64}$/);
  assert.notEqual(sha256Hex(utf8Encode(`shieldkit-labs/p2/gate-b/cohort-live-executor/v2/state\u0000${payload}\n`)), sha256Hex(utf8Encode(`shieldkit-labs/p2/gate-b/cohort-live-executor/v2/root\u0000${payload}\n`)));
  assert.notEqual(authorityDagDigest(), transitionGrammarDigest());
});

test('canonical input rejects ambiguous or unsupported values', () => {
  assert.throws(() => canonicalJson({ value: undefined }), /unsupported undefined/);
  assert.throws(() => canonicalJson({ value: 1n }), /unsupported bigint/);
  assert.throws(() => canonicalJson({ value: NaN }), /non-canonical number/);
  assert.throws(() => canonicalJson({ value: -0 }), /non-canonical number/);
  assert.throws(() => canonicalJson(['a', , 'b']), /sparse/);
  assert.throws(() => canonicalJson({ value: '\ud800' }), /lone high surrogate/);
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), /cyclic/);
});
