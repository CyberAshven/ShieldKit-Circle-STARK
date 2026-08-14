import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { canonicalJson, utf8Encode } from '../src/canonical.mjs';
import { sha256Hex } from '../src/sha256.mjs';
import * as model from '../src/model.mjs';
import { rawFileDigest } from '../validate-static.mjs';

const PREFIX = 'shieldkit-labs/p2/gate-b/cohort-authority-binding-model/v1/';
const KAT = JSON.parse(readFileSync(new URL('./digest.kat.json', import.meta.url)));

function native(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function patternedBytes(length) {
  return Uint8Array.from({ length }, (_, index) => (index * 73 + 19) & 0xff);
}

function framed(suffix, value) {
  return utf8Encode(`${PREFIX}${suffix}\u0000${canonicalJson(value)}\n`);
}

test('SHA-256 standard vectors match Node crypto', () => {
  assert.equal(sha256Hex(new Uint8Array()), KAT.standard.empty);
  assert.equal(sha256Hex(utf8Encode('abc')), KAT.standard.abc);
  assert.equal(sha256Hex(new Uint8Array()), native(Buffer.alloc(0)));
  assert.equal(sha256Hex(utf8Encode('abc')), native(Buffer.from('abc')));
});

test('SHA-256 boundary-length vectors match checked-in and Node crypto KATs', () => {
  for (const vector of KAT.boundaryVectors) {
    const bytes = patternedBytes(vector.length);
    assert.equal(sha256Hex(bytes), vector.sha256, `checked-in length ${vector.length}`);
    assert.equal(sha256Hex(bytes), native(bytes), `Node crypto length ${vector.length}`);
  }
});

test('canonical JSON sorts keys and preserves array order', () => {
  assert.equal(canonicalJson({ z: [2, 1], a: { y: true, x: null } }), '{"a":{"x":null,"y":true},"z":[2,1]}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
});

test('Unicode and final-LF framing are byte-exact', () => {
  const value = { text: 'A€𝄞' };
  assert.equal(Buffer.from(utf8Encode(canonicalJson(value))).toString('utf8'), canonicalJson(value));
  const bytes = framed('fact-catalog', value);
  assert.equal(Buffer.from(bytes).toString('utf8'), `${PREFIX}fact-catalog\u0000${canonicalJson(value)}\n`);
  assert.equal(sha256Hex(bytes), native(bytes));
});

test('canonical JSON rejects noncanonical inputs', () => {
  for (const value of [undefined, NaN, Infinity, -0, 1n, '\ud800', [, 1]]) {
    assert.throws(() => canonicalJson(value));
  }
  const withSymbol = { a: 1 };
  withSymbol[Symbol('hidden')] = 1;
  assert.throws(() => canonicalJson(withSymbol));
  const withAccessor = {};
  Object.defineProperty(withAccessor, 'a', { enumerable: true, get() { return 1; } });
  assert.throws(() => canonicalJson(withAccessor));
});

test('semantic domain frames are independently reproducible', () => {
  const root = JSON.parse(readFileSync(new URL('../authority-binding-root.v1.json', import.meta.url)));
  const payload = { ...root };
  delete payload.contentDigest;
  const vectors = [
    ['authority-requirement-dag', model.AUTHORITY_DAG, model.authorityDagDigest()],
    ['dependency-catalog', model.DEPENDENCY_CATALOG, model.dependencyCatalogDigest()],
    ['external-origin-catalog', model.EXTERNAL_ORIGINS, model.externalOriginsDigest()],
    ['fact-catalog', model.FACT_CATALOG, model.factCatalogDigest()],
    ['state-grammar', model.STATE_GRAMMAR, model.stateGrammarDigest()],
    ['root', payload, model.modelRootDigest()],
  ];
  for (const [suffix, value, digest] of vectors) assert.equal(digest, native(framed(suffix, value)), suffix);
});

test('semantic domains are separated', () => {
  const value = { a: 1 };
  assert.notEqual(sha256Hex(framed('fact-catalog', value)), sha256Hex(framed('state-grammar', value)));
});

test('actual validator raw-file helper matches independent empty and non-UTF8 KATs', () => {
  const prefix = Buffer.from(`${PREFIX}file\u0000`, 'utf8');
  const vectors = [
    [Buffer.alloc(0), KAT.rawFileDigest.empty],
    [Buffer.from([0xff, 0x00, 0x80]), KAT.rawFileDigest.ff0080],
  ];
  for (const [bytes, expected] of vectors) {
    const independent = createHash('sha256').update(prefix).update(bytes).digest('hex');
    assert.equal(rawFileDigest(bytes), expected);
    assert.equal(rawFileDigest(bytes), independent);
  }
});
