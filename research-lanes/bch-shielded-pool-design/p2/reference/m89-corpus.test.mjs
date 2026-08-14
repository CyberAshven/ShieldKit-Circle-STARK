import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { artifactBytes, artifactSha256, buildArtifact, evaluateCase, generateCases, sampleFp } from './m89-corpus.mjs';

const corpusPath = new URL('./m89-corpus.json', import.meta.url);
const descriptorPath = new URL('../algebra-component/descriptors/m89-d2-x2-plus-1.v1.json', import.meta.url);
const campaignPath = new URL('../gate-b/equal-relation-arithmetic-campaign.v1.json', import.meta.url);
const corpusBytes = readFileSync(corpusPath);
const corpus = JSON.parse(corpusBytes);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const expectedArtifactSha256 = '175f7fe9e7812030f87c7259d99e0ae808ed441d23986d6a1d0ea356e29da4f0';

test('M89 corpus artifact is byte-stable, content-pinned, and exactly 266 ordered cases', () => {
  const regenerated = buildArtifact();
  assert.deepEqual(Buffer.from(artifactBytes(regenerated)), corpusBytes);
  assert.equal(artifactSha256(regenerated), expectedArtifactSha256);
  assert.equal(sha256(corpusBytes), expectedArtifactSha256);
  assert.equal(corpus.schema, 'shieldkit-labs/m89-gate-b0-shakedown-corpus/v2');
  assert.equal(corpus.selection, 'none');
  assert.equal(corpus.tupleRef, null);
  assert.equal(corpus.counts.total, 266);
  assert.deepEqual(corpus.counts.byRelation, {
    'relation:e-mac': 88,
    'relation:e-square-mac': 88,
    'relation:e-inverse-check': 90,
  });
  assert.equal(corpus.counts.accepted + corpus.counts.rejected, 266);
  assert.equal(corpus.descriptor.contentDigest, JSON.parse(readFileSync(descriptorPath, 'utf8')).contentDigest.value);
  assert.equal(corpus.campaign.contentDigest, JSON.parse(readFileSync(campaignPath, 'utf8')).contentDigest.value);
  assert.equal(corpus.campaign.fileDigest, sha256(readFileSync(campaignPath)));
});

test('all raw operands replay through native strict parser and exact relation evaluator', () => {
  assert.deepEqual(generateCases(), corpus.cases);
  for (const candidate of corpus.cases) {
    for (const raw of Object.values(candidate.raw)) assert.equal(typeof raw, 'string');
    assert.deepEqual(evaluateCase(candidate), candidate.expected, `${candidate.relationId}/${candidate.categoryId}/${candidate.caseIndex}`);
  }
});

test('corrected mutation plans have exact lengths, order, postconditions, and failure stages', () => {
  const expectedMacFamilies = ['wrong-length', 'truncation', 'trailing-bytes', 'out-of-range', 'sign-alias', 'swapped-limb', 'wrong-relation-output'];
  const expectedInverseFamilies = [...expectedMacFamilies, 'zero-inverse-hint'];
  for (const [relationId, families] of [
    ['relation:e-mac', expectedMacFamilies],
    ['relation:e-square-mac', expectedMacFamilies],
    ['relation:e-inverse-check', expectedInverseFamilies],
  ]) {
    const malformed = corpus.cases.filter((item) => item.relationId === relationId && item.categoryId === 'category:malformed');
    assert.deepEqual(malformed.map((item) => item.mutation), families.flatMap((family) => [family, family]));
    assert.ok(malformed.every((item) => item.expected.verdict === 'reject'));
    for (const item of malformed) {
      const length = item.raw.A.length / 2;
      if (item.mutation === 'wrong-length') {
        assert.equal(length, item.limbIndex * 12);
        assert.equal(item.expected.stage, 'exact-extension-element-length-check-before-limb-decode');
      } else if (item.mutation === 'truncation') {
        assert.equal(length, 23);
        assert.equal(item.expected.stage, 'exact-extension-element-length-check-before-limb-decode');
      } else if (item.mutation === 'trailing-bytes') {
        assert.equal(length, 25);
        assert.equal(item.expected.stage, 'exact-extension-element-length-check-before-limb-decode');
      } else if (item.mutation === 'out-of-range') {
        assert.equal(item.expected.stage, 'coefficient-range-check-before-arithmetic');
      } else if (item.mutation === 'sign-alias') {
        assert.equal(item.expected.stage, 'unused-high-bit-check-before-numeric-decode');
      } else if (relationId === 'relation:e-inverse-check') {
        assert.equal(item.expected.stage, 'inverse-relation-check');
      } else {
        assert.equal(item.expected.stage, 'relation-check');
      }
    }
  }
});

test('v2 counter sampler pins frame, little-endian interpretation, vectorAttempt, and sampleRetry', () => {
  const sample = sampleFp({ relationIndex: 0, categoryIndex: 2, operandIndex: 0, limbIndex: 0, caseIndex: 0, vectorAttempt: 0, sampleRetry: 0 });
  assert.equal(sample.value, 546043869015866768489400785n);
  assert.equal(sample.sampleRetry, 0);
  assert.equal(sample.frameHex, '736869656c646b69742d676174652d622d636f727075732d7632000123456789abcdef0002000000000000000000000000000000');
});
