import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import { contentDigestFor, generateConstructionFreezeBundle, validateConstructionFreezeSemantics } from './construction-freeze.mjs';

const loadJson = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const summary = loadJson('./construction-freeze.v1.json');
const transcript = loadJson('./construction-freeze.normalized-transcript.v1.json');
const summarySchema = loadJson('./construction-freeze.v1.schema.json');
const transcriptSchema = loadJson('./construction-freeze-normalized-transcript.v1.schema.json');
const validateSummary = new Ajv2020({ allErrors: true, strict: true }).compile(summarySchema);
const validateTranscript = new Ajv2020({ allErrors: true, strict: true }).compile(transcriptSchema);
const copy = (value) => structuredClone(value);
const summaryBytes = readFileSync(new URL('./construction-freeze.v1.json', import.meta.url));
const transcriptBytes = readFileSync(new URL('./construction-freeze.normalized-transcript.v1.json', import.meta.url));
const generated = generateConstructionFreezeBundle();

test('summary and normalized transcript regenerate once, validate strictly, and bind content/file digests', () => {
  assert.equal(validateSummary(summary), true, JSON.stringify(validateSummary.errors));
  assert.equal(validateTranscript(transcript), true, JSON.stringify(validateTranscript.errors));
  assert.deepEqual(generated.summary, summary);
  assert.deepEqual(generated.transcript, transcript);
  assert.equal(summary.contentDigest, contentDigestFor(summary));
  assert.equal(transcript.contentDigest, contentDigestFor(transcript));
  assert.equal(transcriptBytes.includes(0x0d), false);
  assert.equal(transcriptBytes.toString('utf8'), `${JSON.stringify(transcript)}\n`);
  assert.equal(transcriptBytes.toString('utf8').endsWith('\n\n'), false);
  assert.deepEqual(Object.keys(transcript), ['schema', 'transcriptId', 'rows', 'rowCount', 'contentDigest']);
  assert.deepEqual(Object.keys(transcript.rows[0]), ['targetOrderIndex', 'candidateIndex', 'globalOrderIndex', 'support', 'secondaryIndex', 'q', 'degree', 'p', 'tCentered', 'tCanonical', 'polynomialCanonical', 'irreducible', 'reductionExponents', 'reductionRows', 'score']);
  assert.deepEqual(Object.keys(transcript.rows[0].score), ['nonZeroNonSignedUnitEntryCount', 'nonZeroEntryCount', 'bitLengthSum', 'peakBitLength', 'peakRowFanIn', 'polynomialMaxAbsCoefficient', 'polynomialSupport', 'polynomialL1', 'signedLexRanks', 'lexicographicTuple']);
  assert.equal(summary.transcriptBinding.byteCount, transcriptBytes.length);
  assert.equal(summary.transcriptBinding.sha256, createHash('sha256').update(transcriptBytes).digest('hex'));
  assert.equal(summary.transcriptBinding.contentDigest, transcript.contentDigest);
  const sums = readFileSync(new URL('./SHA256SUMS', import.meta.url), 'utf8');
  const summarySha = createHash('sha256').update(summaryBytes).digest('hex');
  const transcriptSha = createHash('sha256').update(transcriptBytes).digest('hex');
  assert.equal(sums, `${summarySha}  construction-freeze.v1.json\n${transcriptSha}  construction-freeze.normalized-transcript.v1.json\n`);
});

test('candidate domain, order, counts, winners, scores, and reductions are exact', () => {
  assert.deepEqual(summary.targets.map(({ q, degree, testedCount, irreducibleCount }) => ({ q, degree, testedCount, irreducibleCount })), [
    { q: 31, degree: 5, testedCount: 4128, irreducibleCount: 752 },
    { q: 31, degree: 6, testedCount: 5152, irreducibleCount: 831 },
    { q: 61, degree: 3, testedCount: 2080, irreducibleCount: 650 }
  ]);
  assert.deepEqual(summary.targets.map(({ winner }) => winner.tCentered), [[-1, 2, 0, 0, 0], [-5, 0, 0, 0, 0, 0], [-5, 0, 0]]);
  assert.deepEqual(summary.targets.map(({ winner }) => winner.score.lexicographicTuple), [
    [4, 8, 12, 2, 2, 2, 3, 4, 1, 4, 0, 0, 0],
    [5, 5, 15, 3, 1, 5, 2, 6, 9, 0, 0, 0, 0, 0],
    [2, 2, 6, 3, 1, 5, 2, 6, 9, 0, 0]
  ]);
  const targetStarts = [0, 4128, 9280];
  const targetWidths = [4128, 5152, 2080];
  for (let index = 0; index < transcript.rows.length; index += 1) {
    const row = transcript.rows[index];
    const targetIndex = index < targetStarts[1] ? 0 : index < targetStarts[2] ? 1 : 2;
    assert.equal(row.globalOrderIndex, index);
    assert.equal(row.targetOrderIndex, targetIndex);
    assert.equal(row.candidateIndex, index - targetStarts[targetIndex]);
    assert.equal(row.q, summary.targets[targetIndex].q);
    assert.equal(row.degree, summary.targets[targetIndex].degree);
    assert.equal(row.p, summary.targets[targetIndex].p);
    assert.equal(row.tCentered.length, row.degree);
    assert.equal(row.tCanonical.length, row.degree);
    assert.equal(row.polynomialCanonical.length, row.degree + 1);
    assert.equal(row.polynomialCanonical.at(-1), '1');
    assert.equal(row.reductionExponents.length, row.degree - 1);
    assert.equal(row.reductionRows.length, row.degree - 1);
    assert.equal(row.support, row.tCentered.filter((value) => value !== 0).length);
    assert.ok(row.support === 1 || row.support === 2);
    assert.notEqual(row.tCentered[0], 0);
    if (row.support === 1) assert.equal(row.secondaryIndex, null);
    if (row.support === 2) assert.ok(Number.isInteger(row.secondaryIndex) && row.secondaryIndex >= 1 && row.tCentered[row.secondaryIndex] !== 0);
  }
  assert.deepEqual(targetWidths, summary.targets.map(({ testedCount }) => testedCount));
  for (const target of summary.targets) {
    const row = transcript.rows[target.winnerCandidateIndex + targetStarts[summary.targets.indexOf(target)]];
    assert.equal(row.irreducible, true);
    assert.deepEqual(target.winner, Object.fromEntries(Object.keys(target.winner).map((key) => [key, row[key]])));
  }
});

test('semantic validation rejects score, recurrence, order, winner, exact-bound, and transcript drift', () => {
  const mutations = [
    (s, t) => { s.targets[0].winner.score.lexicographicTuple[0] += 1; },
    (s, t) => { t.rows[35].reductionRows[0][0] = '2'; },
    (s, t) => { [t.rows[0], t.rows[1]] = [t.rows[1], t.rows[0]]; },
    (s, t) => { s.targets[0].winnerCandidateIndex += 1; },
    (s, t) => { s.searchContract.K = 15; },
    (s, t) => { t.rows[0].irreducible = !t.rows[0].irreducible; }
  ];
  for (const mutate of mutations) {
    const candidateSummary = copy(summary);
    const candidateTranscript = copy(transcript);
    mutate(candidateSummary, candidateTranscript);
    assert.equal(validateConstructionFreezeSemantics(candidateSummary, candidateTranscript, generated), false);
  }
});

test('strict schemas reject boundary, family-elimination, and unknown-field drift', () => {
  for (const mutate of [
    (value) => { value.status = 'evidence'; },
    (value) => { value.selection = 'selected'; },
    (value) => { value.protocolBoundary = 'protocol-selected'; },
    (value) => { value.failClosedPolicy.familyPolicy = 'eliminate-the-entire-(p,d)-family'; },
    (value) => { value.unexpected = 'drift'; }
  ]) {
    const candidate = copy(summary);
    mutate(candidate);
    assert.equal(validateSummary(candidate), false);
  }
  const unknownRow = copy(transcript);
  unknownRow.rows[0].checkerCertificateDigest = '0'.repeat(64);
  assert.equal(validateTranscript(unknownRow), false);
});
