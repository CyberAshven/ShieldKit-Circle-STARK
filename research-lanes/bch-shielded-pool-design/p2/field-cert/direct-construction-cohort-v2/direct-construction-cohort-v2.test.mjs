import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import { contentDigestFor, currentEnvironmentMismatches, generateCertificateSet, rawReplayReportFor, verifyCertificateSet } from './direct-construction-cohort-v2.mjs';

const loadJson = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const artifact = loadJson('./direct-construction-cohort-v2.v2.json');
const schema = loadJson('./direct-construction-cohort-v2.v2.schema.json');
const manifest = loadJson('./MANIFEST.json');
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const copy = (value) => structuredClone(value);
const bytesOf = (name) => readFileSync(new URL(name, import.meta.url));
const generated = generateCertificateSet();

test('certificate set is strict-schema valid, deterministic, content-bound, and replay-valid', () => {
  assert.equal(validate(artifact), true, JSON.stringify(validate.errors));
  assert.equal(artifact.contentDigest, contentDigestFor(artifact));
  assert.deepEqual(generated.artifact, artifact);
  assert.equal(artifact.certificates.length, 4);
  assert.equal(artifact.certificates.every((entry) => entry.replayPassed === true), true);
  assert.equal(verifyCertificateSet(artifact), true);
  const report = readFileSync(new URL('./repository-replay-report.v2.txt', import.meta.url), 'utf8');
  assert.equal(report, rawReplayReportFor(artifact));
  assert.equal(artifact.replayReportBinding.byteCount, Buffer.byteLength(report));
  assert.equal(artifact.replayReportBinding.sha256, createHash('sha256').update(report).digest('hex'));
  const environmentMismatch = currentEnvironmentMismatches();
  if (environmentMismatch.length > 0) process.stderr.write(`NOTE repository environment mismatch: ${environmentMismatch.join('; ')}\n`);
  assert.equal(Array.isArray(environmentMismatch), true);
});

test('exact schedule order, polynomial bindings, and individual entry identities are pinned', () => {
  assert.deepEqual(artifact.scheduleOrder.map(({ constructionId, certificateEntryId, fieldSpecRef, q, degree, polynomialCanonical }) => ({ constructionId, certificateEntryId, fieldSpecRef, q, degree, polynomialCanonical })), [
    { constructionId: 'algebra-construction:m89-d2-x2-plus-1-v1', certificateEntryId: 'certificate-entry:m89-d2-x2-plus-1-v1', fieldSpecRef: 'field-spec:m89-d2', q: 89, degree: 2, polynomialCanonical: ['1', '0', '1'] },
    { constructionId: 'algebra-construction:m61-d3-x3-minus-5-v1', certificateEntryId: 'certificate-entry:m61-d3-x3-minus-5-v1', fieldSpecRef: 'field-spec:m61-d3', q: 61, degree: 3, polynomialCanonical: ['2305843009213693946', '0', '0', '1'] },
    { constructionId: 'algebra-construction:m31-d5-x5-plus-2x-minus-1-v1', certificateEntryId: 'certificate-entry:m31-d5-x5-plus-2x-minus-1-v1', fieldSpecRef: 'field-spec:m31-d5', q: 31, degree: 5, polynomialCanonical: ['2147483646', '2', '0', '0', '0', '1'] },
    { constructionId: 'algebra-construction:m31-d6-x6-minus-5-v1', certificateEntryId: 'certificate-entry:m31-d6-x6-minus-5-v1', fieldSpecRef: 'field-spec:m31-d6', q: 31, degree: 6, polynomialCanonical: ['2147483642', '0', '0', '0', '0', '0', '1'] }
  ]);
  for (const [index, entry] of artifact.certificates.entries()) {
    assert.equal(entry.certificateEntryId, artifact.scheduleOrder[index].certificateEntryId);
    assert.equal(entry.constructionId, artifact.scheduleOrder[index].constructionId);
    assert.deepEqual(entry.polynomialCanonical, artifact.scheduleOrder[index].polynomialCanonical);
    assert.equal(entry.p, entry.certificate.modulus);
    assert.equal(typeof entry.p, 'string');
    assert.equal(entry.certificate.mersennePrimeCheck.lucasLehmer.passed, true);
    assert.equal(entry.certificate.finalResidue.length > 0, true);
  }
});

test('repository replay command emits the bound raw report', () => {
  const result = spawnSync(process.execPath, ['repository-replay.mjs', 'direct-construction-cohort-v2.v2.json'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout, readFileSync(new URL('./repository-replay-report.v2.txt', import.meta.url), 'utf8'));
});

test('manifest and SHA256SUMS bind every generated/support file', () => {
  assert.equal(manifest.schema, 'shieldkit-labs/p2/direct-construction-cohort-v2/manifest/v1');
  for (const file of manifest.files) {
    const bytes = bytesOf(`./${file.path}`);
    assert.equal(bytes.length, file.byteCount, `${file.path} byte count`);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), file.sha256, `${file.path} digest`);
  }
  const sums = readFileSync(new URL('./SHA256SUMS', import.meta.url), 'utf8');
  const expectedSums = [...manifest.files.map(({ path }) => path), 'MANIFEST.json'].map((path) => `${createHash('sha256').update(bytesOf(`./${path}`)).digest('hex')}  ${path}`).join('\n') + '\n';
  assert.equal(sums, expectedSums);
});

test('adversarial certificate, binding, boundary, and unknown-field mutations fail closed', () => {
  const mutations = [
    (value) => { value.certificates[0].certificate.polynomial[0] = '2'; },
    (value) => { value.certificates[1].certificate.hPowers[1].coefficients[0] = '2'; },
    (value) => { value.certificates[2].certificate.witnesses[0].gcd = ['2']; },
    (value) => { value.certificates[2].certificate.witnesses[0].bezoutU[0] = '2'; },
    (value) => { value.certificates[3].certificate.finalResidue[0] = '2'; },
    (value) => { value.certificates[0].constructionId = 'algebra-construction:wrong'; },
    (value) => { value.inputBindings[0].fileSha256 = '0'.repeat(64); },
    (value) => { value.inputBindings[0].schemaPath = 'research-lanes/wrong-schema.json'; },
    (value) => { value.inputBindings[0].schemaSha256 = '0'.repeat(64); },
    (value) => { value.importedSourceBindings[0].sha256 = '0'.repeat(64); },
    (value) => { value.repositoryEnvironment.policy = 'changed'; },
    (value) => { value.toolBinding.generatorCommand = 'node altered.mjs'; },
    (value) => { value.replayReportBinding.sha256 = '0'.repeat(64); },
    (value) => { value.boundary.permittedConclusion = 'protocol-selected'; },
    (value) => { value.certificates[0].certificateId = 'certificate:wrong'; },
    (value) => { value.certificates[0].establishes = 'field-family-selected'; },
    (value) => { value.status = 'selected'; },
    (value) => { value.protocolBoundary = 'protocol-selected'; },
    (value) => { value.unexpected = true; }
  ];
  for (const mutate of mutations) {
    const candidate = copy(artifact);
    mutate(candidate);
    candidate.contentDigest = contentDigestFor(candidate);
    assert.throws(() => verifyCertificateSet(candidate));
  }
  for (const mutate of [
    (value) => { value.status = 'selected'; },
    (value) => { value.protocolBoundary = 'protocol-selected'; },
    (value) => { value.unexpected = true; }
  ]) {
    const candidate = copy(artifact);
    mutate(candidate);
    assert.equal(validate(candidate), false);
  }
  const swapped = copy(artifact);
  [swapped.certificates[0].certificate, swapped.certificates[1].certificate] = [swapped.certificates[1].certificate, swapped.certificates[0].certificate];
  assert.throws(() => verifyCertificateSet(swapped));
  const swappedEntryIds = copy(artifact);
  [swappedEntryIds.certificates[0].certificateEntryId, swappedEntryIds.certificates[1].certificateEntryId] = [swappedEntryIds.certificates[1].certificateEntryId, swappedEntryIds.certificates[0].certificateEntryId];
  assert.throws(() => verifyCertificateSet(swappedEntryIds));

  const stale = copy(artifact);
  stale.status = 'selected';
  assert.throws(() => verifyCertificateSet(stale));

  const failedReplay = copy(artifact);
  failedReplay.certificates[0].certificate.polynomial[0] = '2';
  failedReplay.contentDigest = contentDigestFor(failedReplay);
  const failedReport = rawReplayReportFor(failedReplay);
  assert.match(failedReport, /status=repository-replay-failed\n/u);
  assert.doesNotMatch(failedReport, /status=all-repository-replays-passed\n/u);
  const temporaryPath = new URL('./.failed-replay-test.json', import.meta.url);
  writeFileSync(temporaryPath, JSON.stringify(failedReplay));
  try {
    const result = spawnSync(process.execPath, ['repository-replay.mjs', temporaryPath.pathname], { encoding: 'utf8' });
    assert.notEqual(result.status, 0);
  } finally {
    unlinkSync(temporaryPath);
  }
});
