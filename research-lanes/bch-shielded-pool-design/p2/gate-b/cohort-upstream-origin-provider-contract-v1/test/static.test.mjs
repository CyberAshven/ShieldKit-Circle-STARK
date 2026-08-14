import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { canonicalJson, rawFileDigest, semanticDigest, validateStatic } from '../validate-static.mjs';

const KAT = JSON.parse(readFileSync(new URL('./digest.kat.json', import.meta.url), 'utf8'));

test('sealed catalog validates with no evaluation of dependencies', () => {
  assert.deepEqual(validateStatic(), { identifier: 'cohort-upstream-origin-provider-contract-v1', rootDigest: 'e76b1c35b47fac325b0e2750495ce4fabc8f1d9145974cdbbae95b63f2699020', sealed: true, files: 21 });
});

test('canonical JSON and SHA-256 boundary vectors agree with node crypto', () => {
  assert.equal(canonicalJson(KAT.canonical.input), KAT.canonical.json);
  for (const vector of KAT.sha256) {
    const bytes = Object.hasOwn(vector, 'bytesHex') ? Buffer.from(vector.bytesHex, 'hex') : Buffer.alloc(vector.length, vector.byte);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), vector.digest);
  }
});

test('semantic and raw-file frames are independently recomputed', () => {
  const expectedSemantic = createHash('sha256').update(Buffer.from(KAT.semantic.domain + '\u0000' + canonicalJson(KAT.semantic.value) + '\n', 'utf8')).digest('hex');
  assert.equal(semanticDigest(KAT.semantic.domain, KAT.semantic.value), expectedSemantic);
  assert.equal(KAT.semantic.sha256, expectedSemantic);
  for (const vector of KAT.rawFile) {
    const bytes = Buffer.from(vector.bytesHex, 'hex');
    const expected = createHash('sha256').update(Buffer.concat([Buffer.from('shieldkit-labs/p2/gate-b/cohort-upstream-origin-provider-contract/v1/file\u0000'), bytes])).digest('hex');
    assert.equal(rawFileDigest(bytes), expected);
    assert.equal(vector.digest, expected);
  }
});
